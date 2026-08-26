package web

import "sort"

// auditEventLabels names every audit event the service records. The audit
// screen used to show raw codes like UPDATE_SUBMISSION to an auditor reading a
// Korean report, and offered only a free-text filter to guess them with.
// A test keeps this list complete: any new event type has to be named here.
var auditEventLabels = map[string]string{
	"LOGIN":                          "로그인",
	"LOGIN_FAIL":                     "로그인 실패",
	"LOGIN_LOCKED":                   "계정 잠금",
	"LOGOUT":                         "로그아웃",
	"CHANGE_PASSWORD":                "비밀번호 변경",
	"RESET_PASSWORD":                 "비밀번호 재설정",
	"UNLOCK_USER":                    "계정 잠금 해제",
	"LOCK_INACTIVE_ACCOUNT":          "장기 미접속 계정 자동 잠금",
	"ACCESS_DENIED":                  "권한 없는 접근 시도",
	"TEST_CLAMAV":                    "ClamAV 연결 테스트",
	"REMOVE_PARTICIPANT":             "심의 참여자 해제",
	"RECOVER_ADMIN":                  "관리자 계정 복구 (CLI)",
	"PURGE_EVIDENCE":                 "증적 보존기간 만료 파기",
	"QUARANTINE_EVIDENCE":            "증적 악성코드 격리",
	"REASSIGN_APPROVER":              "최종 승인자 변경",
	"TRANSFER_REQUESTER":             "심의 요청자 인계",
	"REASSIGN_REVIEWER":              "보안 담당자 변경",
	"HANDOVER_WORK":                  "담당 업무 일괄 인계",
	"SYNC_OIDC_ROLES":                "디렉터리 역할 동기화",
	"TOTP_ENROLLMENT_STARTED":        "일회용 코드 등록 시작",
	"TOTP_ENABLED":                   "일회용 코드 활성화",
	"TOTP_DISABLED":                  "일회용 코드 해제",
	"TOTP_RESET":                     "일회용 코드 초기화",
	"REVOKE_SESSION":                 "세션 종료",
	"CREATE_USER":                    "사용자 생성",
	"CHANGE_PERMISSION":              "권한 변경",
	"UPDATE_PROFILE":                 "프로필 수정",
	"UPDATE_NOTIFICATION_PREFERENCE": "알림 수신 설정 변경",
	"UPDATE_SETTING":                 "서비스 설정 변경",
	"TEST_SMTP":                      "SMTP 테스트 발송",
	"TEST_OIDC":                      "OIDC Discovery 연결 테스트",
	"CREATE_API_KEY":                 "API 키 발급",
	"ROTATE_API_KEY":                 "API 키 회전",
	"REVOKE_API_KEY":                 "API 키 폐기",
	"ROTATE_ENCRYPTION_KEY":          "암호화 키 회전",
	"CREATE_SUBMISSION":              "심의 생성",
	"VIEW_SUBMISSION":                "심의 조회",
	"UPDATE_SUBMISSION":              "심의 정보 수정",
	"COPY_SUBMISSION":                "재심의 복사",
	"UPDATE_RESPONSE":                "체크리스트 작성",
	"BULK_UPDATE_RESPONSE":           "체크리스트 일괄 작성",
	"BULK_REVIEW_RESULT":             "검토 결과 일괄 판정",
	"FOLLOW_UP_REPORTED":             "조치 사항 이행 보고",
	"FOLLOW_UP_DONE":                 "조치 사항 이행 완료",
	"FOLLOW_UP_REOPENED":             "조치 사항 이행 완료 해제",
	"ASSIGN_ITEMS":                   "항목 담당자 배정",
	"ADD_PARTICIPANT":                "참여자 추가",
	"CREATE_COMMENT":                 "코멘트 작성",
	"OVERRIDE_RULE":                  "자동 배정 수동 조정",
	"BEGIN_REVIEW":                   "검토 시작",
	"REVIEW_ITEM":                    "항목 검토 결과 저장",
	"REQUEST_CHANGE":                 "보완 요청",
	"UPDATE_CHANGE_REQUEST":          "보완 요청 상태 변경",
	"CANCEL":                         "심의 취소",
	"REOPEN":                         "반려 심의 보완 재개",
	"CLOSE":                          "심의 종료",
	"UPLOAD_EVIDENCE":                "증적 업로드",
	"UPLOAD_EVIDENCE_VERSION":        "증적 새 버전 업로드",
	"DOWNLOAD_EVIDENCE":              "증적 다운로드",
	"DELETE_EVIDENCE":                "증적 삭제",
	"CARRY_OVER_EVIDENCE":            "이전 심의 증적 가져오기",
	"CREATE_TEMPLATE":                "템플릿 생성",
	"UPDATE_TEMPLATE":                "템플릿 수정",
	"CREATE_CHECKLIST_ITEM":          "체크리스트 항목 추가",
	"UPDATE_CHECKLIST_ITEM":          "체크리스트 항목 수정",
	"DELETE_CHECKLIST_ITEM":          "체크리스트 항목 삭제",
	"DELETE_TEMPLATE":                "템플릿 삭제",
	"CREATE_TEMPLATE_VERSION":        "템플릿 버전 생성",
	"PUBLISH_TEMPLATE":               "템플릿 버전 게시",
	"RETIRE_TEMPLATE":                "템플릿 버전 사용 중지",
	"CREATE_CONTROL":                 "Security Control 생성",
	"UPDATE_CONTROL":                 "Security Control 수정",
	"DELETE_CONTROL":                 "Security Control 삭제",
	"EXPORT_DATA":                    "심의 결과 내보내기",
	"EXPORT_AUDIT":                   "감사로그 내보내기",
	"EXPORT_REPORT":                  "심의 리포트 내보내기",
	"EXPORT_REVIEW_LIST":             "심의 목록 내보내기",
	"VERIFY_AUDIT_CHAIN":             "감사 체인 검증",
	"RETRY_JOB":                      "작업 재시도",
	"MCP_TOOL_CALL":                  "MCP 도구 호출",
}

func sortByLabel(items []map[string]string) {
	sort.Slice(items, func(i, j int) bool { return items[i]["label"] < items[j]["label"] })
}

// auditEventCatalogue backs the filter dropdown, sorted by label so the list
// reads in Korean order rather than by code.
func auditEventCatalogue() []map[string]string {
	out := make([]map[string]string, 0, len(auditEventLabels))
	for code, label := range auditEventLabels {
		out = append(out, map[string]string{"code": code, "label": label})
	}
	sortByLabel(out)
	return out
}
