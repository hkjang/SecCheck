package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/auth"
)

// listSessions lets people see where their account is signed in. The rows
// already existed; nothing surfaced them.
func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,source_ip,user_agent,created_at,last_seen_at,expires_at,(id=$2) AS current FROM sessions WHERE user_id=$1 AND expires_at>now() ORDER BY last_seen_at DESC`, sess.User.ID, sess.ID)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "세션을 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"id", "source_ip", "user_agent", "created_at", "last_seen_at", "expires_at", "current"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "목록을 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, items)
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	id := r.PathValue("id")
	if id == sess.ID {
		problem(w, 422, "CURRENT_SESSION", "현재 사용 중인 세션은 로그아웃으로 종료하세요.", nil)
		return
	}
	// A session identifier means nothing once the row is deleted, so the
	// device and address it belonged to are captured while they still exist.
	var agent, ip string
	var seen *time.Time
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT user_agent,source_ip,last_seen_at FROM sessions WHERE id=$1 AND user_id=$2`, id, sess.User.ID).Scan(&agent, &ip, &seen)
	tag, err := s.Store.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE id=$1 AND user_id=$2`, id, sess.User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 404, "NOT_FOUND", "세션을 찾을 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "REVOKE_SESSION", "SESSION", id, map[string]any{"user_agent": agent, "source_ip": ip, "last_seen_at": seen}, nil))
	w.WriteHeader(204)
}

func (s *Server) revokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	tag, err := s.Store.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`, sess.User.ID, sess.ID)
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "세션을 종료하지 못했습니다.", err)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "REVOKE_SESSION", "SESSION", "others", nil, map[string]any{"revoked": tag.RowsAffected()}))
	jsonResponse(w, 200, map[string]any{"revoked": tag.RowsAffected()})
}

// startTOTPEnrollment issues a fresh secret. It is stored but left disabled
// until the user proves they can generate a code from it.
func (s *Server) startTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	if sess.User.AuthSource != "local" {
		problem(w, 422, "EXTERNAL_ACCOUNT", "SSO 계정의 다중 인증은 사내 인증 서버에서 관리합니다.", nil)
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		s.fault(w, r, "TOTP_FAILED", "일회용 코드 설정을 시작하지 못했습니다.", err)
		return
	}
	if err = s.Auth.StoreTOTPSecret(r.Context(), sess.User.ID, secret); err != nil {
		s.fault(w, r, "TOTP_FAILED", "일회용 코드 설정을 저장하지 못했습니다.", err)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "TOTP_ENROLLMENT_STARTED", "USER", sess.User.ID, nil, nil))
	jsonResponse(w, 200, map[string]any{
		"secret":       auth.FormatTOTPSecret(secret),
		"raw_secret":   secret,
		"uri":          auth.TOTPURI("SecCheck", sess.User.Username, secret),
		"algorithm":    "SHA1",
		"digits":       6,
		"period":       30,
		"instructions": "인증 앱에서 계정을 수동으로 추가하고 위 비밀키를 입력한 뒤, 표시되는 6자리 코드로 활성화하세요.",
	})
}

func (s *Server) enableTOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	sess := session(r)
	if err := s.Auth.EnableTOTP(r.Context(), sess.User.ID, in.Code); err != nil {
		problem(w, 422, "TOTP_INVALID", "코드가 올바르지 않습니다. 기기 시간이 정확한지 확인하세요.", nil)
		return
	}
	// Other sessions were opened with one factor only.
	_, _ = s.Store.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`, sess.User.ID, sess.ID)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "TOTP_ENABLED", "USER", sess.User.ID, nil, nil))
	w.WriteHeader(204)
}

// disableTOTP requires the current password so a borrowed session cannot strip
// the second factor off an account.
func (s *Server) disableTOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CurrentPassword string `json:"current_password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	sess := session(r)
	if !verifyPassword(sess.User.PasswordHash, in.CurrentPassword) {
		problem(w, 403, "INVALID_CREDENTIALS", "현재 비밀번호가 올바르지 않습니다.", nil)
		return
	}
	if err := s.Auth.DisableTOTP(r.Context(), sess.User.ID); err != nil {
		s.fault(w, r, "UPDATE_FAILED", "일회용 코드를 해제하지 못했습니다.", err)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "TOTP_DISABLED", "USER", sess.User.ID, nil, nil))
	w.WriteHeader(204)
}

// resetUserTOTP is the recovery path for a lost authenticator device.
func (s *Server) resetUserTOTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Auth.DisableTOTP(r.Context(), id); err != nil {
		problem(w, 404, "NOT_FOUND", "사용자를 찾을 수 없습니다.", nil)
		return
	}
	_, _ = s.Store.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1`, id)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "TOTP_RESET", "USER", id, nil, nil))
	w.WriteHeader(204)
}

func (s *Server) accountSecurity(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	var enabled bool
	var enrolledAt *time.Time
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT totp_enabled,totp_enrolled_at FROM users WHERE id=$1`, sess.User.ID).Scan(&enabled, &enrolledAt)
	var sessions int
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM sessions WHERE user_id=$1 AND expires_at>now()`, sess.User.ID).Scan(&sessions)
	jsonResponse(w, 200, map[string]any{
		"totp_enabled":     enabled,
		"totp_enrolled_at": enrolledAt,
		"totp_required":    sess.EnrollTOTP,
		"active_sessions":  sessions,
		"auth_source":      sess.User.AuthSource,
	})
}

// bulkSaveResponses applies one answer to many checklist items. Marking two
// hundred entries N/A one at a time was the single most repetitive part of
// filling in a checklist.
func (s *Server) bulkSaveResponses(w http.ResponseWriter, r *http.Request) {
	reviewID := r.PathValue("id")
	if !s.canEditReview(r.Context(), session(r), reviewID) {
		problem(w, 403, "FORBIDDEN", "이 심의를 작성할 수 없습니다.", nil)
		return
	}
	var in struct {
		ItemIDs        []string `json:"item_ids"`
		Applicability  string   `json:"applicability"`
		SelfAssessment string   `json:"self_assessment"`
		NAReason       string   `json:"na_reason"`
		CurrentState   string   `json:"current_state"`
		ActionPlan     string   `json:"action_plan"`
		AssignedTo     string   `json:"assigned_to"`
		Overwrite      bool     `json:"overwrite"`
		// AssignOnly splits a long checklist across a team without touching
		// anybody's answers.
		AssignOnly bool `json:"assign_only"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.ItemIDs) == 0 {
		problem(w, 422, "VALIDATION_FAILED", "적용할 항목을 선택하세요.", nil)
		return
	}
	if len(in.ItemIDs) > 1000 {
		problem(w, 422, "VALIDATION_FAILED", "한 번에 1000개까지 적용할 수 있습니다.", nil)
		return
	}
	if in.AssignOnly {
		s.bulkAssign(w, r, reviewID, in.ItemIDs, in.AssignedTo)
		return
	}
	if !contains([]string{"Y", "N", "N/A"}, in.Applicability) {
		problem(w, 422, "VALIDATION_FAILED", "적용 여부는 Y, N 또는 N/A여야 합니다.", nil)
		return
	}
	if in.SelfAssessment != "" && !contains([]string{"COMPLIANT", "INSUFFICIENT", "N/A"}, in.SelfAssessment) {
		problem(w, 422, "VALIDATION_FAILED", "자체 판단 값을 확인하세요.", nil)
		return
	}
	if in.Applicability == "N/A" && strings.TrimSpace(in.NAReason) == "" {
		problem(w, 422, "NA_REASON_REQUIRED", "N/A 일괄 적용에는 공통 사유가 필요합니다.", map[string]string{"na_reason": "필수 입력 항목입니다."})
		return
	}
	if field := tooLong(map[string]string{"current_state": in.CurrentState, "action_plan": in.ActionPlan, "na_reason": in.NAReason}, longTextLimit); field != "" {
		problem(w, 422, "VALIDATION_FAILED", fmt.Sprintf("입력이 너무 깁니다. %d자 이내로 작성하세요.", longTextLimit), map[string]string{field: fmt.Sprintf("%d자를 넘습니다.", longTextLimit)})
		return
	}
	// Without overwrite, entries that already carry an answer are left alone so
	// a bulk action cannot silently discard someone's work.
	conflict := `ON CONFLICT(submission_item_id) DO NOTHING`
	if in.Overwrite {
		conflict = `ON CONFLICT(submission_item_id) DO UPDATE SET applicability=EXCLUDED.applicability,self_assessment=EXCLUDED.self_assessment,na_reason=EXCLUDED.na_reason,current_state=EXCLUDED.current_state,action_plan=EXCLUDED.action_plan,assigned_to=EXCLUDED.assigned_to,updated_by=EXCLUDED.updated_by,updated_at=now()`
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `
                INSERT INTO responses(id,submission_item_id,answer_json,applicability,self_assessment,current_state,na_reason,action_plan,assigned_to,updated_by)
                SELECT gen_id.id,si.id,'{}'::jsonb,$1,$2,$3,$4,$5,NULLIF($6,''),$7
                FROM submission_items si
                JOIN submissions sub ON sub.id=si.submission_id
                CROSS JOIN LATERAL (SELECT gen_random_uuid()::text AS id) gen_id
                WHERE si.id = ANY($8) AND sub.review_request_id=$9
                  AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$9)
                `+conflict,
		in.Applicability, in.SelfAssessment, in.CurrentState, in.NAReason, in.ActionPlan, in.AssignedTo, session(r).User.ID, in.ItemIDs, reviewID)
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "일괄 적용에 실패했습니다.", err)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "BULK_UPDATE_RESPONSE", "REVIEW_REQUEST", reviewID, nil, map[string]any{"items": len(in.ItemIDs), "applied": tag.RowsAffected(), "applicability": in.Applicability, "overwrite": in.Overwrite}))
	jsonResponse(w, 200, map[string]any{"requested": len(in.ItemIDs), "applied": tag.RowsAffected(), "skipped": int64(len(in.ItemIDs)) - tag.RowsAffected()})
}

// bulkAssign records who is responsible for each of the selected items without
// writing an answer, so a long checklist can be divided up before anyone
// starts filling it in. The assignee is notified once for the whole batch.
func (s *Server) bulkAssign(w http.ResponseWriter, r *http.Request, reviewID string, itemIDs []string, assignee string) {
	if assignee != "" && !s.canAccessReviewAs(r.Context(), assignee, reviewID) {
		problem(w, 422, "NOT_A_PARTICIPANT", "이 심의에 참여하지 않는 사용자에게는 배정할 수 없습니다.", nil)
		return
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `
                INSERT INTO responses(id,submission_item_id,answer_json,assigned_to,updated_by)
                SELECT gen_random_uuid()::text,si.id,'{}'::jsonb,NULLIF($1,''),$2
                FROM submission_items si
                JOIN submissions sub ON sub.id=si.submission_id
                WHERE si.id = ANY($3) AND sub.review_request_id=$4
                  AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$4)
                ON CONFLICT(submission_item_id) DO UPDATE SET assigned_to=EXCLUDED.assigned_to,updated_at=now()`,
		assignee, session(r).User.ID, itemIDs, reviewID)
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "담당자를 배정하지 못했습니다.", err)
		return
	}
	if assignee != "" && tag.RowsAffected() > 0 {
		var number, service string
		_ = s.Store.Pool.QueryRow(r.Context(), `SELECT review_number,service_name FROM review_requests WHERE id=$1`, reviewID).Scan(&number, &service)
		s.addTargetedNotification(r.Context(), assignee, "ITEM_ASSIGNED", "체크리스트 항목 배정",
			fmt.Sprintf("%s(%s)의 체크리스트 항목 %d개가 배정되었습니다.", number, service, tag.RowsAffected()), "REVIEW_REQUEST", reviewID)
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "ASSIGN_ITEMS", "REVIEW_REQUEST", reviewID, nil, map[string]any{"items": tag.RowsAffected(), "assigned_to": assignee}))
	jsonResponse(w, 200, map[string]any{"requested": len(itemIDs), "applied": tag.RowsAffected(), "skipped": int64(len(itemIDs)) - tag.RowsAffected()})
}

// notificationEvents is the catalogue the preference screen renders. Keeping
// it here means a new event type has one place to be registered.
var notificationEvents = []map[string]string{
	{"code": "REVIEW_SUBMITTED", "label": "심의 제출·재제출", "description": "담당 심의가 제출되거나 재제출되었을 때"},
	{"code": "REVIEW_ASSIGNED", "label": "심의 배정", "description": "심의 담당자로 배정되었을 때"},
	{"code": "CHANGE_REQUEST", "label": "보완 요청", "description": "작성한 항목에 보완 요청이 등록되었을 때"},
	{"code": "CHANGE_DONE", "label": "보완 조치 완료", "description": "요청한 보완이 조치되었을 때"},
	{"code": "CHANGE_REQUEST_DUE", "label": "보완 기한 임박·초과", "description": "보완 조치 기한이 다가오거나 지났을 때"},
	{"code": "APPROVAL_PENDING", "label": "최종 승인 요청", "description": "승인자로서 결재가 필요할 때"},
	{"code": "APPROVED", "label": "심의 완료", "description": "심의가 승인되거나 검토 완료되었을 때"},
	{"code": "REJECTED", "label": "심의 반려", "description": "심의가 반려되었을 때"},
	{"code": "ITEM_ASSIGNED", "label": "체크리스트 항목 배정", "description": "체크리스트 항목의 담당자로 지정되었을 때"},
	{"code": "COMMENT_ADDED", "label": "체크리스트 코멘트", "description": "담당 심의의 항목에 코멘트가 달렸을 때"},
	{"code": "EVIDENCE_INFECTED", "label": "증적 악성코드 탐지", "description": "업로드한 증적에서 악성코드가 발견되었을 때"},
	{"code": "AUDIT_CHAIN_BROKEN", "label": "감사로그 무결성 실패", "description": "해시 체인 검증이 실패했을 때 (시스템 관리자)"},
	{"code": "FOLLOW_UP_DUE", "label": "후속조치 기한", "description": "판정과 함께 약속한 후속조치의 기한이 임박하거나 지났을 때"},
	{"code": "FOLLOW_UP_REPORTED", "label": "후속조치 이행 보고", "description": "담당 팀이 후속조치를 완료했다고 보고했을 때 (보안 담당자)"},
	{"code": "FOLLOW_UP_DONE", "label": "후속조치 이행 확인", "description": "보고한 후속조치가 확인되어 종료되었을 때"},
	{"code": "JOB_QUEUE_STALLED", "label": "작업 큐 정체", "description": "알림·검사 작업이 처리되지 않고 쌓일 때 (시스템 관리자)"},
	{"code": "JOB_FAILED", "label": "작업 재시도 소진", "description": "재시도를 모두 소진해 중단된 작업이 있을 때"},
	{"code": "REVIEW_STALLED", "label": "심의 정체", "description": "담당한 심의가 며칠째 다음 단계로 넘어가지 않을 때"},
	{"code": "OPEN_DATE_NEAR", "label": "오픈 예정일 임박", "description": "심의가 끝나지 않았는데 서비스 오픈 예정일이 다가왔을 때"},
	{"code": "STORAGE_LOW", "label": "저장 공간 부족", "description": "증적 볼륨의 남은 공간이 부족하거나 쓸 수 없을 때"},
}

type notificationPreference struct {
	EmailEnabled bool     `json:"email_enabled"`
	Digest       string   `json:"digest"`
	MutedEvents  []string `json:"muted_events"`
}

func (s *Server) getNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	pref := notificationPreference{EmailEnabled: true, Digest: "IMMEDIATE", MutedEvents: []string{}}
	var muted []string
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT email_enabled,digest,muted_events FROM notification_preferences WHERE user_id=$1`, session(r).User.ID).
		Scan(&pref.EmailEnabled, &pref.Digest, &muted)
	if err == nil && muted != nil {
		pref.MutedEvents = muted
	}
	var global struct {
		EmailEnabled bool `json:"email_enabled"`
	}
	_, _ = s.Store.Setting(r.Context(), "notification", &global)
	jsonResponse(w, 200, map[string]any{
		"preference":     pref,
		"events":         notificationEvents,
		"email_capable":  global.EmailEnabled,
		"email_address":  session(r).User.Email,
		"digest_options": []map[string]string{{"code": "IMMEDIATE", "label": "발생 즉시"}, {"code": "DAILY", "label": "하루 한 번 요약"}},
	})
}

func (s *Server) updateNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	var in notificationPreference
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Digest != "IMMEDIATE" && in.Digest != "DAILY" {
		problem(w, 422, "VALIDATION_FAILED", "수신 주기를 확인하세요.", nil)
		return
	}
	known := map[string]bool{}
	for _, event := range notificationEvents {
		known[event["code"]] = true
	}
	muted := []string{}
	for _, code := range in.MutedEvents {
		if !known[code] {
			problem(w, 422, "VALIDATION_FAILED", "알 수 없는 알림 유형입니다: "+code, nil)
			return
		}
		if !contains(muted, code) {
			muted = append(muted, code)
		}
	}
	_, err := s.Store.Pool.Exec(r.Context(), `INSERT INTO notification_preferences(user_id,email_enabled,digest,muted_events) VALUES($1,$2,$3,$4)
                ON CONFLICT(user_id) DO UPDATE SET email_enabled=EXCLUDED.email_enabled,digest=EXCLUDED.digest,muted_events=EXCLUDED.muted_events,updated_at=now()`,
		session(r).User.ID, in.EmailEnabled, in.Digest, muted)
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "알림 설정을 저장하지 못했습니다.", err)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_NOTIFICATION_PREFERENCE", "USER", session(r).User.ID, nil, map[string]any{"email_enabled": in.EmailEnabled, "digest": in.Digest, "muted": len(muted)}))
	w.WriteHeader(204)
}
