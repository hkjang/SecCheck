package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hkjang/SecCheck/internal/auth"
	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/vault"
)

type Options struct {
	Store                    *store.Store
	Auth                     *auth.Service
	Box                      *cryptox.Box
	Version, WebDir, DataDir string
}

// APIRoute is one registered endpoint. The OpenAPI document is generated from
// these, so a route cannot exist without being described: the specification
// used to be a hand-written subset covering a third of the surface, which is
// worse than no specification for an integrator who trusts it.
type APIRoute struct {
	Method, Path, Tag, Summary string
	Roles                      []string
	Public                     bool
}

type Server struct {
	Options
	blobs        *vault.Vault
	api          []APIRoute
	mux          *http.ServeMux
	limiter      *rateLimiter
	loginLimiter *rateLimiter
	securityMu   sync.Mutex
	securityAt   time.Time
	securityConf runtimeSecurity
	// A full chain verification re-hashes every event ever written and holds a
	// connection while it does. Several at once is a way to take the service
	// down from a button anybody with the audit role can press twice.
	verifying atomic.Bool
}

type runtimeSecurity struct {
	CORSOrigins        []string `json:"cors_origins"`
	RateLimitPerMinute int      `json:"rate_limit_per_minute"`
	TrustedProxies     []string `json:"trusted_proxies"`
	// MetricsPublic keeps /metrics reachable without credentials, which is
	// what a Prometheus scrape usually expects and what every installation
	// has had so far. It is exposed as a setting because the numbers are not
	// nothing: user and review counts, failed sign-ins in the last day,
	// locked accounts. Turning it off leaves the endpoint available to a
	// read-scoped API key.
	MetricsPublic *bool `json:"metrics_public"`

	trusted []netip.Prefix
}

// metricsPublic defaults to true so that upgrading does not silently break a
// scrape that has been running for months.
func (c runtimeSecurity) metricsPublic() bool { return c.MetricsPublic == nil || *c.MetricsPublic }

type ctxKey string

const sessionKey ctxKey = "session"
const clientIPKey ctxKey = "client_ip"

func NewServer(o Options) http.Handler {
	s := &Server{Options: o, blobs: vault.New(o.DataDir, o.Box, o.Store), mux: http.NewServeMux(), limiter: newRateLimiter(), loginLimiter: newRateLimiter()}
	s.routes()
	return s.middleware(s.mux)
}

func (s *Server) routes() {
	// Public operational and authentication endpoints.
	s.handle("GET", "/health", "운영", "프로세스 생존 확인", nil, true, s.health)
	s.handle("GET", "/ready", "운영", "데이터베이스 포함 준비 상태 확인", nil, true, s.ready)
	s.handle("GET", "/metrics", "운영", "Prometheus 지표", nil, true, s.metrics)
	s.handle("GET", "/api/v1/public/config", "인증", "로그인 전 공개 설정 (서비스명, 버전, SSO 사용 여부, 표시 시간대)", nil, true, s.publicConfig)
	s.handle("POST", "/api/v1/auth/login", "인증", "비밀번호 로그인. 일회용 코드가 설정된 계정은 totp_code 필요", nil, true, s.login)
	s.handle("GET", "/api/v1/auth/oidc/start", "인증", "OIDC 인증 시작 (Authorization Code + PKCE)", nil, true, s.oidcStart)
	s.handle("GET", "/api/v1/auth/oidc/callback", "인증", "OIDC Callback 처리", nil, true, s.oidcCallback)

	// Authenticated user, dashboard, review lifecycle, evidence, exports and search.
	s.handle("POST", "/api/v1/auth/logout", "인증", "로그아웃 및 세션 삭제", nil, false, s.logout)
	s.handle("GET", "/api/v1/me", "프로필", "로그인 사용자 정보와 CSRF 토큰", nil, false, s.me)
	s.handle("PATCH", "/api/v1/me", "프로필", "표시 이름, 이메일, 부서 수정", nil, false, s.updateMe)
	s.handle("PUT", "/api/v1/me/password", "프로필", "본인 비밀번호 변경. 다른 세션은 모두 종료", nil, false, s.changePassword)
	s.handle("GET", "/api/v1/me/security", "프로필", "일회용 코드 사용 여부와 활성 세션 수", nil, false, s.accountSecurity)
	s.handle("GET", "/api/v1/me/sessions", "프로필", "본인 로그인 세션 목록", nil, false, s.listSessions)
	s.handle("DELETE", "/api/v1/me/sessions/{id}", "프로필", "특정 세션 종료", nil, false, s.revokeSession)
	s.handle("POST", "/api/v1/me/sessions/revoke-others", "프로필", "현재 세션을 제외한 모든 세션 종료", nil, false, s.revokeOtherSessions)
	s.handle("POST", "/api/v1/me/totp/setup", "프로필", "일회용 코드 등록 시작 (비밀키와 otpauth URI 반환)", nil, false, s.startTOTPEnrollment)
	s.handle("POST", "/api/v1/me/totp/enable", "프로필", "일회용 코드 활성화", nil, false, s.enableTOTP)
	s.handle("POST", "/api/v1/me/totp/disable", "프로필", "일회용 코드 해제. 현재 비밀번호 필요", nil, false, s.disableTOTP)
	s.handle("GET", "/api/v1/dashboard", "대시보드", "상태별 건수, 내 차례 목록, 기한 임박 보완 요청", nil, false, s.dashboard)
	s.handle("GET", "/api/v1/search", "검색", "심의, 체크리스트 항목, 증적 통합 검색", nil, false, s.search)
	s.handle("GET", "/api/v1/reports/reviews", "리포트", "기간별 심의 통계. format=xlsx로 Excel 리포트", []string{"SYSTEM_ADMIN", "SECURITY_REVIEWER", "AUDITOR", "APPROVER"}, false, s.reviewReport)
	s.handle("GET", "/api/v1/notifications", "알림", "인앱 알림 목록 (unread, event 필터와 페이지네이션)", nil, false, s.notifications)
	s.handle("GET", "/api/v1/notifications/unread-count", "알림", "읽지 않은 알림 수", nil, false, s.unreadNotifications)
	s.handle("POST", "/api/v1/notifications/read-all", "알림", "모든 알림 읽음 처리", nil, false, s.readAllNotifications)
	s.handle("GET", "/api/v1/me/notification-preferences", "알림", "알림 수신 설정과 이벤트 카탈로그 조회", nil, false, s.getNotificationPreferences)
	s.handle("PUT", "/api/v1/me/notification-preferences", "알림", "알림 수신 설정 저장", nil, false, s.updateNotificationPreferences)
	s.handle("GET", "/api/v1/users/directory", "사용자", "활성 사용자 이름 목록 (담당자 선택용)", nil, false, s.userDirectory)
	s.handle("POST", "/api/v1/notifications/{id}/read", "알림", "알림 하나 읽음 처리", nil, false, s.readNotification)
	s.handle("GET", "/api/v1/review-requests", "심의", "권한 범위의 심의 목록. 정렬, 필터, 페이지네이션, format=csv 지원", nil, false, s.listReviewRequests)
	s.handle("POST", "/api/v1/review-requests", "심의", "심의 생성 및 Rule Engine 기반 체크리스트 스냅샷 배정", []string{"REQUESTER"}, false, s.createReviewRequest)
	s.handle("GET", "/api/v1/review-requests/{id}", "심의", "심의 상세와 진행률", nil, false, s.getReviewRequest)
	s.handle("PATCH", "/api/v1/review-requests/{id}", "심의", "심의 기본정보, 담당자, 오픈 예정일 수정", nil, false, s.updateReviewRequest)
	s.handle("GET", "/api/v1/review-requests/{id}/items", "심의", "응답, 검토결과, 증적, 보완요청, 코멘트를 포함한 스냅샷 항목", nil, false, s.listSubmissionItems)
	s.handle("GET", "/api/v1/review-requests/{id}/completion-check", "심의", "검토 완료를 막는 항목 목록. 검토 완료 전에 미리 확인", nil, false, s.completionCheck)
	s.handle("GET", "/api/v1/review-requests/{id}/submission-check", "심의", "제출을 막는 미완료 항목 목록. 제출 전에 미리 확인", nil, false, s.submissionCheck)
	s.handle("GET", "/api/v1/review-requests/{id}/items/{itemID}/verdict-history", "심의", "같은 서비스의 이전 심의에서 이 항목이 어떻게 판정되었는지", nil, false, s.itemVerdictHistory)
	s.handle("GET", "/api/v1/review-requests/{id}/items/{itemID}/why", "심의", "이 항목이 이 심의에 배정된 이유. 적용 규칙의 조건별 판정 또는 수동 포함 사유", nil, false, s.itemAssignmentReason)
	s.handle("GET", "/api/v1/review-requests/{id}/history", "심의", "이 심의에서 일어난 일의 이력. 감사로그에서 해당 심의 범위만 추출", nil, false, s.reviewHistory)
	s.handle("PUT", "/api/v1/review-requests/{id}/responses/{itemID}", "심의", "체크리스트 항목 작성. expected_updated_at으로 동시 편집 충돌 감지", nil, false, s.saveResponse)
	s.handle("POST", "/api/v1/review-requests/{id}/responses/bulk", "심의", "체크리스트 항목 일괄 작성 또는 담당자 일괄 배정", nil, false, s.bulkSaveResponses)
	s.handle("POST", "/api/v1/review-requests/{id}/submit", "워크플로", "서버 검증 후 제출 또는 재제출", nil, false, s.submitReview)
	s.handle("POST", "/api/v1/review-requests/{id}/begin-review", "워크플로", "보안 담당자 검토 시작", []string{"SECURITY_REVIEWER"}, false, s.beginReview)
	s.handle("POST", "/api/v1/review-results/{id}/follow-up", "워크플로", "후속조치 보고(report), 이행 확인(confirm), 해제(reopen)", nil, false, s.markFollowUp)
	s.handle("POST", "/api/v1/review-requests/{id}/review-results/bulk", "워크플로", "선택한 항목 일괄 판정", []string{"SECURITY_REVIEWER"}, false, s.bulkSaveReviewResults)
	s.handle("PUT", "/api/v1/review-requests/{id}/review-results/{itemID}", "워크플로", "항목별 검토 결과 저장", []string{"SECURITY_REVIEWER"}, false, s.saveReviewResult)
	s.handle("POST", "/api/v1/review-requests/{id}/change-requests", "워크플로", "항목 보완 요청 등록", []string{"SECURITY_REVIEWER"}, false, s.createChangeRequest)
	s.handle("POST", "/api/v1/review-requests/{id}/change-requests/bulk", "워크플로", "선택한 항목에 같은 보완 요청 일괄 등록. 이미 처리 중인 항목은 건너뜁니다", []string{"SECURITY_REVIEWER"}, false, s.bulkChangeRequests)
	s.handle("PATCH", "/api/v1/change-requests/{id}", "워크플로", "보완 조치 답변 또는 조치 검증", nil, false, s.updateChangeRequest)
	s.handle("POST", "/api/v1/review-requests/{id}/complete-review", "워크플로", "검토 완료. 승인 절차 설정에 따라 승인 대기 또는 완료", []string{"SECURITY_REVIEWER"}, false, s.completeReview)
	s.handle("POST", "/api/v1/review-requests/{id}/approve", "워크플로", "최종 승인", []string{"APPROVER"}, false, s.approveReview)
	s.handle("POST", "/api/v1/review-requests/{id}/reject", "워크플로", "반려", []string{"APPROVER"}, false, s.rejectReview)
	s.handle("POST", "/api/v1/review-requests/{id}/reopen", "워크플로", "반려된 심의를 보완할 수 있도록 다시 엶(보완 필요 상태로)", []string{"SECURITY_REVIEWER"}, false, s.reopenRejectedReview)
	s.handle("POST", "/api/v1/review-requests/{id}/withdraw-approval", "워크플로", "승인 대기 중인 심의의 결재 요청 회수(검토 중으로 되돌림)", []string{"SECURITY_REVIEWER"}, false, s.withdrawApproval)
	s.handle("POST", "/api/v1/review-requests/{id}/cancel", "워크플로", "요청자 본인의 심의 취소", []string{"REQUESTER"}, false, s.cancelReview)
	s.handle("POST", "/api/v1/review-requests/{id}/close", "워크플로", "승인 또는 반려된 심의 종료", []string{"SECURITY_REVIEWER"}, false, s.closeReview)
	s.handle("GET", "/api/v1/review-requests/{id}/assignees", "심의", "항목 담당자로 지정할 수 있는 사용자 목록", nil, false, s.listAssignees)
	s.handle("POST", "/api/v1/review-requests/{id}/transfer-requester", "심의", "심의 요청자를 다른 사람에게 인계. 요청자 본인 또는 시스템 관리자", nil, false, s.transferRequester)
	s.handle("GET", "/api/v1/review-requests/{id}/participants", "심의", "참여자 목록", nil, false, s.listParticipants)
	s.handle("POST", "/api/v1/review-requests/{id}/participants", "심의", "참여자 추가. role은 CONTRIBUTOR 또는 VIEWER", nil, false, s.addParticipant)
	s.handle("DELETE", "/api/v1/review-requests/{id}/participants/{userID}", "심의", "참여자 해제", nil, false, s.removeParticipant)
	s.handle("POST", "/api/v1/review-requests/{id}/copy", "심의", "이전 답변을 복사한 재심의 생성", []string{"REQUESTER"}, false, s.copyReview)
	s.handle("GET", "/api/v1/review-requests/{id}/rule-candidates", "심의", "자동 배정 결과와 미배정 후보 항목", []string{"TEMPLATE_ADMIN"}, false, s.listRuleCandidates)
	s.handle("POST", "/api/v1/review-requests/{id}/rule-overrides", "심의", "자동 배정 결과 수동 조정. 사유가 감사로그에 기록됨", []string{"TEMPLATE_ADMIN"}, false, s.overrideRuleResult)
	s.handle("POST", "/api/v1/review-requests/{id}/items/{itemID}/evidences", "증적", "증적 업로드. 확장자와 Magic/MIME 검증 후 암호화 저장", nil, false, s.uploadEvidence)
	s.handle("GET", "/api/v1/review-requests/{id}/items/{itemID}/evidences/carry-over", "증적", "같은 서비스의 이전 심의에 이 항목으로 첨부돼 있던 증적 목록", nil, false, s.listCarryOverEvidence)
	s.handle("POST", "/api/v1/review-requests/{id}/items/{itemID}/evidences/carry-over", "증적", "같은 서비스의 이전 심의에 첨부된 증적을 이 항목으로 가져오기", nil, false, s.carryOverEvidence)
	s.handle("POST", "/api/v1/review-requests/{id}/items/{itemID}/comments", "심의", "항목 코멘트 작성", nil, false, s.addComment)
	s.handle("GET", "/api/v1/evidences/{id}/download", "증적", "증적 복호화 다운로드. version=N으로 이전 버전 지정. 검사 미완료 파일은 거부", nil, false, s.downloadEvidence)
	s.handle("GET", "/api/v1/evidences/{id}/versions", "증적", "증적 버전 이력. 교체 시각·업로더·해시", nil, false, s.listEvidenceVersions)
	s.handle("POST", "/api/v1/evidences/{id}/versions", "증적", "증적 새 버전 업로드", nil, false, s.newEvidenceVersion)
	s.handle("DELETE", "/api/v1/evidences/{id}", "증적", "증적 논리 삭제", nil, false, s.deleteEvidence)
	s.handle("GET", "/api/v1/review-requests/{id}/export/{format}", "내보내기", "xlsx, pdf, json, zip 결과 내보내기", nil, false, s.exportReview)

	// Personal key management is deliberately separate from administrative configuration.
	s.handle("GET", "/api/v1/me/api-keys", "API 키", "본인 API 키 목록", nil, false, s.listAPIKeys)
	s.handle("POST", "/api/v1/me/api-keys", "API 키", "API 키 발급. 토큰은 이때만 표시됨", nil, false, s.createAPIKey)
	s.handle("POST", "/api/v1/me/api-keys/{id}/rotate", "API 키", "기존 키를 폐기하고 새 키 발급", nil, false, s.rotateAPIKey)
	s.handle("DELETE", "/api/v1/me/api-keys/{id}", "API 키", "API 키 폐기", nil, false, s.revokeAPIKey)
	s.handle("POST", "/api/v1/me/encryption-key/rotate", "API 키", "개인 증적 암호화 키 회전", nil, false, s.rotateDataKey)

	// Template administration and workbook migration.
	s.handle("GET", "/api/v1/templates", "템플릿", "템플릿 목록. 검색, 분류 필터, 페이지네이션", nil, false, s.listTemplates)
	s.handle("POST", "/api/v1/templates", "템플릿", "템플릿 생성", []string{"TEMPLATE_ADMIN"}, false, s.createTemplate)
	s.handle("GET", "/api/v1/templates/{id}", "템플릿", "템플릿 상세와 버전별 항목", nil, false, s.getTemplate)
	s.handle("PATCH", "/api/v1/templates/{id}", "템플릿", "템플릿 이름, 설명, 사용 여부 수정", []string{"TEMPLATE_ADMIN"}, false, s.updateTemplate)
	s.handle("DELETE", "/api/v1/templates/{id}", "템플릿", "미게시·미사용 템플릿 삭제", []string{"TEMPLATE_ADMIN"}, false, s.deleteTemplate)
	s.handle("POST", "/api/v1/templates/{id}/copy", "템플릿", "템플릿 복제", []string{"TEMPLATE_ADMIN"}, false, s.copyTemplate)
	s.handle("POST", "/api/v1/templates/{id}/versions", "템플릿", "새 버전 생성", []string{"TEMPLATE_ADMIN"}, false, s.createTemplateVersion)
	s.handle("POST", "/api/v1/templates/{id}/versions/{versionID}/items", "템플릿", "초안 버전에 체크리스트 항목 추가", []string{"TEMPLATE_ADMIN"}, false, s.createTemplateItem)
	s.handle("PATCH", "/api/v1/templates/{id}/versions/{versionID}/items/{itemID}", "템플릿", "초안 항목 수정", []string{"TEMPLATE_ADMIN"}, false, s.updateTemplateItem)
	s.handle("DELETE", "/api/v1/templates/{id}/versions/{versionID}/items/{itemID}", "템플릿", "초안 항목 삭제", []string{"TEMPLATE_ADMIN"}, false, s.deleteTemplateItem)
	s.handle("POST", "/api/v1/templates/{id}/versions/{versionID}/publish", "템플릿", "버전 게시. 게시 후에는 수정 불가", []string{"TEMPLATE_ADMIN"}, false, s.publishVersion)
	s.handle("POST", "/api/v1/templates/{id}/versions/{versionID}/retire", "템플릿", "버전 사용 중지", []string{"TEMPLATE_ADMIN"}, false, s.retireVersion)
	s.handle("GET", "/api/v1/templates/{id}/rule-check", "템플릿", "게시된 체크리스트에서 규칙 오류로 배정되지 않는 항목", []string{"TEMPLATE_ADMIN", "SECURITY_REVIEWER"}, false, s.ruleCheck)
	s.handle("GET", "/api/v1/templates/{id}/versions/{versionID}/diff", "템플릿", "이전 버전과의 항목 차이", nil, false, s.versionDiff)
	s.handle("GET", "/api/v1/templates/{id}/versions/{versionID}/changes", "템플릿", "버전 변경 이력", nil, false, s.versionChanges)
	s.handle("POST", "/api/v1/templates/rule-simulation", "템플릿", "서비스 특성별 자동 배정 시뮬레이션. 심의를 만들지 않음", []string{"TEMPLATE_ADMIN", "SECURITY_REVIEWER", "REQUESTER"}, false, s.simulateRules)
	s.handle("POST", "/api/v1/templates/import/preview", "템플릿", "Excel 가져오기 드라이런. 생성될 항목과 경고 반환", []string{"TEMPLATE_ADMIN"}, false, s.previewImport)
	s.handle("POST", "/api/v1/templates/import", "템플릿", "Excel 워크북을 템플릿으로 가져오기", []string{"TEMPLATE_ADMIN"}, false, s.importTemplate)
	s.handle("GET", "/api/v1/templates/{id}/export", "템플릿", "템플릿을 Excel로 내보내기", []string{"TEMPLATE_ADMIN"}, false, s.exportTemplate)

	// Unified Security Controls and impact tracking across checklist versions.
	s.handle("GET", "/api/v1/security-controls", "Security Control", "통합 Control 목록과 영향 건수", nil, false, s.listControls)
	s.handle("POST", "/api/v1/security-controls", "Security Control", "Control 생성", []string{"TEMPLATE_ADMIN"}, false, s.createControl)
	s.handle("PATCH", "/api/v1/security-controls/{id}", "Security Control", "Control 수정", []string{"TEMPLATE_ADMIN"}, false, s.updateControl)
	s.handle("DELETE", "/api/v1/security-controls/{id}", "Security Control", "Control 삭제", []string{"TEMPLATE_ADMIN"}, false, s.deleteControl)
	s.handle("GET", "/api/v1/security-controls/{id}/impact", "Security Control", "연결된 체크리스트와 영향 심의 범위", nil, false, s.controlImpact)

	// Administrative plane.
	s.handle("GET", "/api/v1/admin/users", "관리", "사용자 목록과 역할, 잠금 상태", []string{"SYSTEM_ADMIN"}, false, s.listUsers)
	s.handle("POST", "/api/v1/admin/users", "관리", "로컬 사용자 생성", []string{"SYSTEM_ADMIN"}, false, s.createUser)
	s.handle("PUT", "/api/v1/admin/users/{id}/roles", "관리", "사용자 역할 변경", []string{"SYSTEM_ADMIN"}, false, s.updateUserRoles)
	s.handle("GET", "/api/v1/admin/users/{id}/open-work", "관리", "이 계정이 아직 맡고 있는 심의와 후속조치 수. 비활성화 전 인계 확인용", []string{"SYSTEM_ADMIN"}, false, s.userOpenWork)
	s.handle("POST", "/api/v1/admin/users/{id}/handover", "관리", "이 계정이 맡고 있는 심의·항목·보완 요청을 다른 사람에게 일괄 인계", []string{"SYSTEM_ADMIN"}, false, s.handoverUserWork)
	s.handle("POST", "/api/v1/admin/users/{id}/active", "관리", "계정 활성화 또는 비활성화", []string{"SYSTEM_ADMIN"}, false, s.setUserActive)
	s.handle("POST", "/api/v1/admin/users/{id}/unlock", "관리", "로그인 실패로 잠긴 계정 해제", []string{"SYSTEM_ADMIN"}, false, s.unlockUser)
	s.handle("POST", "/api/v1/admin/users/{id}/password", "관리", "로컬 계정 임시 비밀번호 재설정", []string{"SYSTEM_ADMIN"}, false, s.resetUserPassword)
	s.handle("POST", "/api/v1/admin/users/{id}/totp/reset", "관리", "일회용 코드 초기화", []string{"SYSTEM_ADMIN"}, false, s.resetUserTOTP)
	s.handle("GET", "/api/v1/admin/settings", "관리", "관리 설정 목록", []string{"SYSTEM_ADMIN"}, false, s.listSettings)
	s.handle("PUT", "/api/v1/admin/settings/{key}", "관리", "관리 설정 저장. 비밀값은 Master Key로 암호화", []string{"SYSTEM_ADMIN"}, false, s.updateSetting)
	s.handle("POST", "/api/v1/admin/settings/oidc/test", "관리", "OIDC Discovery 연결 테스트", []string{"SYSTEM_ADMIN"}, false, s.testOIDC)
	s.handle("POST", "/api/v1/admin/settings/notification/test", "관리", "SMTP 설정 테스트 메일 발송", []string{"SYSTEM_ADMIN"}, false, s.testSMTP)
	s.handle("POST", "/api/v1/admin/settings/upload/test", "관리", "ClamAV 연결 테스트(clamd PING)", []string{"SYSTEM_ADMIN"}, false, s.testClamAV)
	s.handle("GET", "/api/v1/admin/audit", "관리", "해시 체인 감사로그. 이벤트, 사용자, 기간 필터와 format=csv", []string{"SYSTEM_ADMIN", "AUDITOR"}, false, s.listAudit)
	s.handle("GET", "/api/v1/admin/audit/verify", "관리", "해시 체인 검증. full=1이면 전체 재검증", []string{"SYSTEM_ADMIN", "AUDITOR"}, false, s.verifyAudit)
	s.handle("GET", "/api/v1/admin/api-keys", "관리", "설치 전체의 API 키 목록과 소유자, 마지막 사용 시각", []string{"SYSTEM_ADMIN"}, false, s.listAllAPIKeys)
	s.handle("POST", "/api/v1/admin/api-keys/{id}/revoke", "관리", "다른 사용자의 API 키 폐기", []string{"SYSTEM_ADMIN"}, false, s.revokeAnyAPIKey)
	s.handle("GET", "/api/v1/admin/logs", "관리", "구조화 서버 로그. 메시지, 요청 ID, 필드 통합 검색", []string{"SYSTEM_ADMIN"}, false, s.listLogs)
	s.handle("GET", "/api/v1/admin/jobs", "관리", "백그라운드 작업 큐 상태", []string{"SYSTEM_ADMIN"}, false, s.listJobs)
	s.handle("POST", "/api/v1/admin/jobs/{id}/retry", "관리", "실패한 작업 재시도", []string{"SYSTEM_ADMIN"}, false, s.retryJob)
	s.handle("POST", "/api/v1/admin/jobs/retry-failed", "관리", "실패한 작업 일괄 재시도", []string{"SYSTEM_ADMIN"}, false, s.retryFailedJobs)
	s.handle("GET", "/api/v1/admin/system", "관리", "버전, 스키마 버전, 데이터 규모", []string{"SYSTEM_ADMIN"}, false, s.systemInfo)

	// Machine interfaces.
	s.handle("GET", "/api/v1/integrations", "machine", "연계 인터페이스 정보와 제공 중인 MCP 도구 목록", nil, false, s.integrationInfo)
	s.handle("GET", "/api/openapi.json", "machine", "OpenAPI 3.1 명세", nil, false, s.openAPI)
	s.handle("POST", "/mcp", "machine", "MCP 2026-07-28 Streamable HTTP endpoint", nil, false, s.mcp)
	s.mux.Handle("/", SPA{Dir: s.WebDir})
}

// handle registers an endpoint and records it for the specification in one
// step, so the two cannot drift apart.
func (s *Server) handle(method, path, tag, summary string, roles []string, public bool, h http.HandlerFunc) {
	s.api = append(s.api, APIRoute{Method: method, Path: path, Tag: tag, Summary: summary, Roles: roles, Public: public})
	if public {
		s.mux.HandleFunc(method+" "+path, h)
		return
	}
	s.mux.Handle(method+" "+path, s.require(roles, h))
}

func (s *Server) require(roles []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.Auth.Authenticate(r)
		if err != nil {
			problem(w, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", err.Error(), nil)
			return
		}
		if len(roles) > 0 && !auth.HasRole(sess, roles...) {
			s.recordDenial(r, sess, "role", roles)
			problem(w, http.StatusForbidden, "FORBIDDEN", "이 작업을 수행할 권한이 없습니다.", nil)
			return
		}
		// A password somebody else chose is a shared secret. Until the owner
		// replaces it the account can reach only the screens that let them do
		// that -- the same shape as the one-time-code gate below.
		if sess.User.MustChangePassword && !sess.APIKey && !passwordChangePath(r.URL.Path) {
			problem(w, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "관리자가 발급한 임시 비밀번호입니다. 먼저 비밀번호를 변경하세요.", nil)
			return
		}
		// A privileged account that policy requires to hold a one-time code can
		// reach only the enrolment endpoints until it has one.
		if sess.EnrollTOTP && !totpEnrollmentPath(r.URL.Path) {
			problem(w, http.StatusForbidden, "TOTP_ENROLLMENT_REQUIRED", "보안 정책에 따라 일회용 코드를 먼저 등록해야 합니다.", nil)
			return
		}
		// /mcp is exempt because JSON-RPC reads travel by POST; the write
		// scope is enforced against the named tool in callMCPTool instead.
		if sess.APIKey && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && r.URL.Path != "/mcp" && !contains(sess.Scopes, "read:write") {
			s.recordDenial(r, sess, "api_scope", nil)
			problem(w, http.StatusForbidden, "API_SCOPE_FORBIDDEN", "이 API 키에는 쓰기 범위가 없습니다.", nil)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" && !sess.APIKey {
			if subtleValue(r.Header.Get("X-CSRF-Token"), sess.CSRF) == false {
				problem(w, http.StatusForbidden, "CSRF_INVALID", "요청 검증 토큰이 올바르지 않습니다.", nil)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	})
}

func session(r *http.Request) auth.Session { return r.Context().Value(sessionKey).(auth.Session) }

// totpEnrollmentPath lists what a half-enrolled account may still call: read
// its own profile, complete enrolment, and sign out.
// passwordChangePath is what an account holding a temporary password may
// still reach: its own profile, the change itself, and the way out.
func passwordChangePath(path string) bool {
	switch path {
	case "/api/v1/me", "/api/v1/me/security", "/api/v1/me/password", "/api/v1/auth/logout":
		return true
	}
	return false
}

func totpEnrollmentPath(path string) bool {
	switch path {
	case "/api/v1/me", "/api/v1/me/security", "/api/v1/auth/logout",
		"/api/v1/me/totp/setup", "/api/v1/me/totp/enable":
		return true
	}
	return false
}

func (s *Server) vault() *vault.Vault { return s.blobs }

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = store.NewID()
		}
		r.Header.Set("X-Request-ID", requestID)
		w.Header().Set("X-Request-ID", requestID)
		setSecurityHeaders(w.Header())
		security := s.runtimeSecurity(r.Context())
		r = r.WithContext(context.WithValue(r.Context(), clientIPKey, resolveClientIP(r, security.trusted)))
		if origin := r.Header.Get("Origin"); origin != "" && contains(security.CORSOrigins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token, MCP-Protocol-Version, MCP-Session-Id")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		if !s.limiter.allow(clientIP(r), security.RateLimitPerMinute) {
			problem(w, http.StatusTooManyRequests, "RATE_LIMITED", "요청이 너무 많습니다. 잠시 후 다시 시도하세요.", nil)
			return
		}
		rw := &statusWriter{ResponseWriter: w, status: 200}
		defer func() {
			if v := recover(); v != nil {
				slog.Error("panic", "request_id", requestID, "error", v, "stack", string(debug.Stack()))
				s.Store.Log(context.Background(), "ERROR", requestID, "api", "internal panic", map[string]any{"path": r.URL.Path})
				if !rw.wrote {
					problem(rw, http.StatusInternalServerError, "INTERNAL_ERROR", "요청 처리 중 오류가 발생했습니다.", nil)
				}
			}
			slog.Info("request", "method", r.Method, "path", r.URL.Path, "status", rw.status, "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
			if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/mcp" {
				level := "INFO"
				if rw.status >= 500 {
					level = "ERROR"
				} else if rw.status >= 400 {
					level = "WARN"
				}
				s.Store.Log(context.Background(), level, requestID, "http", "HTTP request", map[string]any{"method": r.Method, "path": r.URL.Path, "status": rw.status, "duration_ms": time.Since(start).Milliseconds()})
			}
		}()
		next.ServeHTTP(rw, r)
	})
}

func setSecurityHeaders(header http.Header) {
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "same-origin")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	header.Set("Cross-Origin-Embedder-Policy", "require-corp")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests")
}

// invalidateSettingCaches is called after a setting is saved so the change is
// live on the next request rather than after the cache window.
func (s *Server) invalidateSettingCaches(key string) {
	switch key {
	case "security":
		s.securityMu.Lock()
		s.securityAt = time.Time{}
		s.securityConf = runtimeSecurity{}
		s.securityMu.Unlock()
		s.Auth.InvalidatePolicy()
	case "general":
		s.Store.InvalidateLocation()
	}
}

func (s *Server) runtimeSecurity(ctx context.Context) runtimeSecurity {
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	if time.Since(s.securityAt) < 15*time.Second && s.securityConf.RateLimitPerMinute > 0 {
		return s.securityConf
	}
	var cfg runtimeSecurity
	_, _ = s.Store.Setting(ctx, "security", &cfg)
	if cfg.RateLimitPerMinute < 30 || cfg.RateLimitPerMinute > 10000 {
		cfg.RateLimitPerMinute = 120
	}
	for _, raw := range cfg.TrustedProxies {
		if prefix, err := parseProxyPrefix(raw); err == nil {
			cfg.trusted = append(cfg.trusted, prefix)
		}
	}
	s.securityConf = cfg
	s.securityAt = time.Now()
	return cfg
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fault answers with a 500 and records why. The message a reader sees cannot
// carry the cause -- it would leak the shape of the database -- and until this
// existed the cause was not written down anywhere at all: the access log noted
// that a request had failed and stopped there. An installation with no
// internet access has nothing else to go on.
func (s *Server) fault(w http.ResponseWriter, r *http.Request, code, message string, cause error) {
	detail := "no rows affected"
	if cause != nil {
		detail = cause.Error()
	}
	s.Store.Log(r.Context(), "ERROR", requestID(r), "api", message, map[string]any{"code": code, "path": r.URL.Path, "error": detail})
	problem(w, http.StatusInternalServerError, code, message, nil)
}

func problem(w http.ResponseWriter, status int, code, message string, details any) {
	jsonResponse(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "details": details}})
}

// A request body is capped at a couple of megabytes, so a single answer could
// carry that much text in one field. Nothing rejected it: it went into the
// database, into every export -- where a spreadsheet cell holds 32,767
// characters and no more -- and into a textarea nobody could scroll. The
// fields that take a paragraph are bounded like the ones that already were.
const (
	longTextLimit  = 4000
	shortTextLimit = 2000
)

// tooLong reports the first field that exceeds its limit, so the message can
// name it rather than saying something was wrong.
func tooLong(fields map[string]string, limit int) string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if len([]rune(fields[name])) > limit {
			return name
		}
	}
	return ""
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		problem(w, 400, "INVALID_JSON", "입력 형식이 올바르지 않습니다.", err.Error())
		return false
	}
	return true
}

// decodeOptionalJSON accepts an absent body, for endpoints whose fields are
// all optional. decodeJSON would reject the empty request an API client
// reasonably sends.
func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return true
		}
		problem(w, 400, "INVALID_JSON", "입력 형식이 올바르지 않습니다.", err.Error())
		return false
	}
	return true
}

// clientIP returns the address the request is attributed to for rate limiting
// and audit logging. The middleware resolves it once per request; the direct
// peer address is the fallback for handlers reached outside that path.
func clientIP(r *http.Request) string {
	if value, ok := r.Context().Value(clientIPKey).(string); ok && value != "" {
		return value
	}
	return remoteIP(r)
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return h
	}
	return r.RemoteAddr
}

// parseProxyPrefix accepts either a CIDR block or a single address so that the
// common "one reverse proxy" deployment does not have to write /32.
func parseProxyPrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// resolveClientIP walks X-Forwarded-For from right to left while the addresses
// belong to configured reverse proxies, and returns the first address that
// does not. Without configured proxies the header is ignored entirely, so a
// client cannot spoof its own rate-limit bucket or audit trail.
func resolveClientIP(r *http.Request, trusted []netip.Prefix) string {
	remote := remoteIP(r)
	if len(trusted) == 0 || !trustedAddr(remote, trusted) {
		return remote
	}
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(forwarded) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(forwarded[i]))
		if err != nil {
			break
		}
		if candidate := addr.Unmap().String(); !trustedAddr(candidate, trusted) {
			return candidate
		}
	}
	return remote
}

func trustedAddr(value string, trusted []netip.Prefix) bool {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
func requestID(r *http.Request) string { return r.Header.Get("X-Request-ID") }

// recordDenial writes down an attempt the service refused on permission. Every
// other refusal that matters -- a failed login, a download of somebody else's
// evidence -- is in the chain; this one, "somebody asked for an endpoint their
// role does not allow", was refused and forgotten, so an account probing what
// it can reach left no trace at all.
func (s *Server) recordDenial(r *http.Request, sess auth.Session, reason string, required []string) {
	after := map[string]any{"reason": reason, "method": r.Method}
	if len(required) > 0 {
		after["required_roles"] = required
	}
	if sess.APIKey {
		after["api_key"] = true
	}
	_ = s.Store.Audit(r.Context(), store.AuditEvent{
		UserID: sess.User.ID, UserName: sess.User.DisplayName, SourceIP: clientIP(r), SessionID: sess.ID,
		EventType: "ACCESS_DENIED", TargetType: "ENDPOINT", TargetID: r.URL.Path,
		RequestID: requestID(r), Result: "FAILURE", After: after,
	})
}

func auditFrom(r *http.Request, event, targetType, targetID string, before, after any) store.AuditEvent {
	sess := session(r)
	return store.AuditEvent{UserID: sess.User.ID, UserName: sess.User.DisplayName, SourceIP: clientIP(r), SessionID: sess.ID, EventType: event, TargetType: targetType, TargetID: targetID, RequestID: requestID(r), Before: before, After: after}
}
func subtleValue(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
func containsRole(u store.User, role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}
func hasAnyRole(u store.User, roles ...string) bool {
	for _, role := range roles {
		if containsRole(u, role) {
			return true
		}
	}
	return false
}

// parsePage reads limit/offset for the paginated list endpoints. Lists used to
// return a hard-coded first 200 rows with no total, so older records simply
// disappeared from the UI.
func parsePage(r *http.Request) (int, int) {
	limit, offset := 50, 0
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = min(v, 200)
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v > 0 {
		offset = min(v, 1_000_000)
	}
	return limit, offset
}

func parseLimit(r *http.Request) int {
	var n int
	if _, err := fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &n); err != nil || n < 1 {
		return 50
	}
	if n > 200 {
		return 200
	}
	return n
}

// maxRateLimiterEntries bounds the counter table so that traffic from a large
// number of distinct source addresses cannot grow the process memory without
// limit. The table is swept every minute; the cap is only a backstop.
const maxRateLimiterEntries = 50000

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateEntry
	sweptAt time.Time
}
type rateEntry struct {
	window time.Time
	count  int
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{entries: map[string]*rateEntry{}, sweptAt: time.Now()}
}
func (l *rateLimiter) allow(key string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweep(now)
	e := l.entries[key]
	if e == nil || now.Sub(e.window) >= time.Minute {
		l.entries[key] = &rateEntry{window: now, count: 1}
		return true
	}
	e.count++
	return e.count <= limit
}

// blocked reports whether the key has already spent its budget for the current
// window without consuming from it, so a caller can count only the events it
// actually wants to throttle.
func (l *rateLimiter) blocked(key string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweep(now)
	e := l.entries[key]
	return e != nil && now.Sub(e.window) < time.Minute && e.count >= limit
}

func (l *rateLimiter) record(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweep(now)
	if e := l.entries[key]; e != nil && now.Sub(e.window) < time.Minute {
		e.count++
		return
	}
	l.entries[key] = &rateEntry{window: now, count: 1}
}

func (l *rateLimiter) sweep(now time.Time) {
	if now.Sub(l.sweptAt) < time.Minute && len(l.entries) < maxRateLimiterEntries {
		return
	}
	for key, e := range l.entries {
		if now.Sub(e.window) >= time.Minute {
			delete(l.entries, key)
		}
	}
	if len(l.entries) >= maxRateLimiterEntries {
		l.entries = map[string]*rateEntry{}
	}
	l.sweptAt = now
}

var errForbidden = errors.New("forbidden")
