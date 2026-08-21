package web

import (
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
		problem(w, 500, "QUERY_FAILED", "세션을 불러오지 못했습니다.", nil)
		return
	}
	jsonResponse(w, 200, scanDynamic(rows, []string{"id", "source_ip", "user_agent", "created_at", "last_seen_at", "expires_at", "current"}))
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	id := r.PathValue("id")
	if id == sess.ID {
		problem(w, 422, "CURRENT_SESSION", "현재 사용 중인 세션은 로그아웃으로 종료하세요.", nil)
		return
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE id=$1 AND user_id=$2`, id, sess.User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 404, "NOT_FOUND", "세션을 찾을 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "REVOKE_SESSION", "SESSION", id, nil, nil))
	w.WriteHeader(204)
}

func (s *Server) revokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	tag, err := s.Store.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`, sess.User.ID, sess.ID)
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "세션을 종료하지 못했습니다.", nil)
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
		problem(w, 500, "TOTP_FAILED", "일회용 코드 설정을 시작하지 못했습니다.", nil)
		return
	}
	if err = s.Auth.StoreTOTPSecret(r.Context(), sess.User.ID, secret); err != nil {
		problem(w, 500, "TOTP_FAILED", "일회용 코드 설정을 저장하지 못했습니다.", nil)
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
		problem(w, 500, "UPDATE_FAILED", "일회용 코드를 해제하지 못했습니다.", nil)
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
		Overwrite      bool     `json:"overwrite"`
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
	// Without overwrite, entries that already carry an answer are left alone so
	// a bulk action cannot silently discard someone's work.
	conflict := `ON CONFLICT(submission_item_id) DO NOTHING`
	if in.Overwrite {
		conflict = `ON CONFLICT(submission_item_id) DO UPDATE SET applicability=EXCLUDED.applicability,self_assessment=EXCLUDED.self_assessment,na_reason=EXCLUDED.na_reason,current_state=EXCLUDED.current_state,action_plan=EXCLUDED.action_plan,updated_by=EXCLUDED.updated_by,updated_at=now()`
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `
                INSERT INTO responses(id,submission_item_id,answer_json,applicability,self_assessment,current_state,na_reason,action_plan,updated_by)
                SELECT gen_id.id,si.id,'{}'::jsonb,$1,$2,$3,$4,$5,$6
                FROM submission_items si
                JOIN submissions sub ON sub.id=si.submission_id
                CROSS JOIN LATERAL (SELECT gen_random_uuid()::text AS id) gen_id
                WHERE si.id = ANY($7) AND sub.review_request_id=$8
                  AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$8)
                `+conflict,
		in.Applicability, in.SelfAssessment, in.CurrentState, in.NAReason, in.ActionPlan, session(r).User.ID, in.ItemIDs, reviewID)
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "일괄 적용에 실패했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "BULK_UPDATE_RESPONSE", "REVIEW_REQUEST", reviewID, nil, map[string]any{"items": len(in.ItemIDs), "applied": tag.RowsAffected(), "applicability": in.Applicability, "overwrite": in.Overwrite}))
	jsonResponse(w, 200, map[string]any{"requested": len(in.ItemIDs), "applied": tag.RowsAffected(), "skipped": int64(len(in.ItemIDs)) - tag.RowsAffected()})
}
