package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/auth"
	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]any{"status": "ok", "service": "SecCheck", "version": s.Version})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Pool.Ping(ctx); err != nil {
		problem(w, 503, "NOT_READY", "database unavailable", nil)
		return
	}
	jsonResponse(w, 200, map[string]any{"status": "ready"})
}
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	var users, reviews, pending, failedJobs, requests, requestErrors, loginOK, loginFail, storageBytes, scanFailures, submissionFailures, sessions, lockedAccounts int64
	var avgDuration float64
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM review_requests),(SELECT count(*) FROM jobs WHERE status='PENDING'),(SELECT count(*) FROM jobs WHERE status='FAILED'),(SELECT count(*) FROM application_logs WHERE component='http' AND timestamp>now()-interval '5 minutes'),(SELECT count(*) FROM application_logs WHERE component='http' AND timestamp>now()-interval '5 minutes' AND (fields->>'status')::int>=500),(SELECT COALESCE(avg((fields->>'duration_ms')::numeric),0) FROM application_logs WHERE component='http' AND timestamp>now()-interval '5 minutes' AND fields->>'duration_ms' ~ '^[0-9]+$'),(SELECT count(*) FROM audit_logs WHERE event_type='LOGIN' AND timestamp>now()-interval '24 hours'),(SELECT count(*) FROM audit_logs WHERE event_type='LOGIN_FAIL' AND timestamp>now()-interval '24 hours'),(SELECT COALESCE(sum(size_bytes),0) FROM evidence_versions),(SELECT count(*) FROM evidences WHERE scan_status NOT IN ('CLEAN','SKIPPED')),(SELECT count(*) FROM application_logs WHERE component='http' AND timestamp>now()-interval '24 hours' AND fields->>'path' LIKE '%/submit' AND (fields->>'status')::int>=400),(SELECT count(*) FROM sessions WHERE expires_at>now()),(SELECT count(*) FROM users WHERE locked_until>now())`).Scan(&users, &reviews, &pending, &failedJobs, &requests, &requestErrors, &avgDuration, &loginOK, &loginFail, &storageBytes, &scanFailures, &submissionFailures, &sessions, &lockedAccounts)
	pool := s.Store.Pool.Stat()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP seccheck_info SecCheck build information\n# TYPE seccheck_info gauge\nseccheck_info{version=%q} 1\n# TYPE seccheck_users_total gauge\nseccheck_users_total %d\n# TYPE seccheck_reviews_total gauge\nseccheck_reviews_total %d\n# TYPE seccheck_jobs_pending gauge\nseccheck_jobs_pending %d\n# TYPE seccheck_jobs_failed gauge\nseccheck_jobs_failed %d\n# TYPE seccheck_http_requests_5m gauge\nseccheck_http_requests_5m %d\n# TYPE seccheck_http_errors_5m gauge\nseccheck_http_errors_5m %d\n# TYPE seccheck_http_duration_ms_5m gauge\nseccheck_http_duration_ms_5m %.3f\n# TYPE seccheck_login_success_24h gauge\nseccheck_login_success_24h %d\n# TYPE seccheck_login_failure_24h gauge\nseccheck_login_failure_24h %d\n# TYPE seccheck_evidence_version_bytes gauge\nseccheck_evidence_version_bytes %d\n# TYPE seccheck_scan_failures gauge\nseccheck_scan_failures %d\n# TYPE seccheck_submission_failures_24h gauge\nseccheck_submission_failures_24h %d\n# TYPE seccheck_sessions_active gauge\nseccheck_sessions_active %d\n# TYPE seccheck_accounts_locked gauge\nseccheck_accounts_locked %d\n# TYPE seccheck_db_connections gauge\nseccheck_db_connections{state=\"total\"} %d\nseccheck_db_connections{state=\"acquired\"} %d\nseccheck_db_connections{state=\"idle\"} %d\n", s.Version, users, reviews, pending, failedJobs, requests, requestErrors, avgDuration, loginOK, loginFail, storageBytes, scanFailures, submissionFailures, sessions, lockedAccounts, pool.TotalConns(), pool.AcquiredConns(), pool.IdleConns())
}

func (s *Server) publicConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.Auth.OIDCConfig(r.Context())
	if err != nil {
		cfg = auth.OIDCSettings{}
	}
	jsonResponse(w, 200, map[string]any{"service_name": "SecCheck", "version": s.Version, "oidc_enabled": cfg.Enabled, "oidc_issuer": cfg.Issuer})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if !decodeJSON(w, r, &in) {
		return
	}
	// Only failed logins are counted, so credential spraying runs out of budget
	// while a shared office or reverse-proxy address never throttles people who
	// are typing the right password.
	policy := s.Auth.Policy(r.Context())
	if s.loginLimiter.blocked(clientIP(r), policy.LoginRateLimitPerMinute) {
		_ = s.Store.Audit(r.Context(), store.AuditEvent{UserName: in.Username, SourceIP: clientIP(r), EventType: "LOGIN_FAIL", TargetType: "USER", RequestID: requestID(r), Result: "FAILURE", After: map[string]any{"reason": "rate_limited"}})
		problem(w, 429, "LOGIN_RATE_LIMITED", "로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.", nil)
		return
	}
	u, token, csrf, expires, err := s.Auth.PasswordLogin(r.Context(), in.Username, in.Password, clientIP(r), r.UserAgent())
	if err != nil {
		s.loginLimiter.record(clientIP(r))
	}
	var locked *auth.LockedError
	if errors.As(err, &locked) {
		_ = s.Store.Audit(r.Context(), store.AuditEvent{UserID: u.ID, UserName: in.Username, SourceIP: clientIP(r), EventType: "LOGIN_LOCKED", TargetType: "USER", TargetID: u.ID, RequestID: requestID(r), Result: "FAILURE", After: map[string]any{"locked_until": locked.Until.UTC()}})
		problem(w, 423, "ACCOUNT_LOCKED", fmt.Sprintf("로그인 실패가 반복되어 계정이 잠겼습니다. %d분 후 또는 관리자 잠금 해제 후 다시 시도하세요.", policy.LockoutMinutes), map[string]any{"locked_until": locked.Until.UTC()})
		return
	}
	if err != nil {
		_ = s.Store.Audit(r.Context(), store.AuditEvent{UserName: in.Username, SourceIP: clientIP(r), EventType: "LOGIN_FAIL", TargetType: "USER", RequestID: requestID(r), Result: "FAILURE"})
		problem(w, 401, "INVALID_CREDENTIALS", "아이디 또는 비밀번호가 올바르지 않습니다.", nil)
		return
	}
	s.setSessionCookie(w, token, expires)
	_ = s.Store.Audit(r.Context(), store.AuditEvent{UserID: u.ID, UserName: u.DisplayName, SourceIP: clientIP(r), EventType: "LOGIN", TargetType: "USER", TargetID: u.ID, RequestID: requestID(r)})
	jsonResponse(w, 200, map[string]any{"user": publicUser(u), "csrf_token": csrf})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	secure := false
	var cfg struct {
		CookieSecure bool `json:"cookie_secure"`
	}
	_, _ = s.Store.Setting(context.Background(), "security", &cfg)
	secure = cfg.CookieSecure
	http.SetCookie(w, &http.Cookie{Name: auth.CookieName, Value: token, Path: "/", Expires: expires, MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.CookieName); err == nil {
		_ = s.Auth.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: auth.CookieName, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	_ = s.Store.Audit(r.Context(), auditFrom(r, "LOGOUT", "USER", session(r).User.ID, nil, nil))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	destination, err := s.Auth.BeginOIDC(r.Context(), r.URL.Query().Get("return_to"))
	if err != nil {
		problem(w, 400, "OIDC_UNAVAILABLE", err.Error(), nil)
		return
	}
	http.Redirect(w, r, destination, http.StatusFound)
}
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		http.Redirect(w, r, "/login?error="+url.QueryEscape(e), http.StatusFound)
		return
	}
	u, token, _, expires, returnTo, err := s.Auth.CompleteOIDC(r.Context(), r.URL.Query().Get("state"), r.URL.Query().Get("code"), clientIP(r), r.UserAgent())
	if err != nil {
		_ = s.Store.Audit(r.Context(), store.AuditEvent{SourceIP: clientIP(r), EventType: "LOGIN_FAIL", TargetType: "OIDC", RequestID: requestID(r), Result: "FAILURE", After: map[string]any{"error": err.Error()}})
		http.Redirect(w, r, "/login?error=oidc", http.StatusFound)
		return
	}
	s.ensureUserDataKey(r.Context(), u.ID)
	s.setSessionCookie(w, token, expires)
	_ = s.Store.Audit(r.Context(), store.AuditEvent{UserID: u.ID, UserName: u.DisplayName, SourceIP: clientIP(r), EventType: "LOGIN", TargetType: "OIDC", TargetID: u.ID, RequestID: requestID(r)})
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	jsonResponse(w, 200, map[string]any{"user": publicUser(sess.User), "csrf_token": sess.CSRF, "version": s.Version})
}
func (s *Server) updateMe(w http.ResponseWriter, r *http.Request) {
	var in struct{ DisplayName, Email, Department string }
	if !decodeJSON(w, r, &in) {
		return
	}
	sess := session(r)
	_, err := s.Store.Pool.Exec(r.Context(), `UPDATE users SET display_name=$2,email=$3,department=$4,updated_at=now() WHERE id=$1`, sess.User.ID, strings.TrimSpace(in.DisplayName), strings.TrimSpace(in.Email), strings.TrimSpace(in.Department))
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "프로필을 저장하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_PROFILE", "USER", sess.User.ID, nil, in))
	u, _ := s.Store.GetUser(r.Context(), sess.User.ID)
	jsonResponse(w, 200, publicUser(u))
}

// changePassword lets a local account rotate its own password. Every other
// session of the same user is dropped so a stolen cookie does not survive a
// deliberate password change.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	sess := session(r)
	if sess.APIKey {
		problem(w, 403, "SESSION_REQUIRED", "비밀번호 변경은 브라우저 로그인 세션에서만 가능합니다.", nil)
		return
	}
	if sess.User.AuthSource != "local" {
		problem(w, 422, "EXTERNAL_ACCOUNT", "SSO 계정의 비밀번호는 사내 인증 서버에서 변경하세요.", nil)
		return
	}
	if !verifyPassword(sess.User.PasswordHash, in.CurrentPassword) {
		_ = s.Store.Audit(r.Context(), auditFrom(r, "CHANGE_PASSWORD", "USER", sess.User.ID, nil, map[string]any{"reason": "current password mismatch"}))
		problem(w, 403, "INVALID_CREDENTIALS", "현재 비밀번호가 올바르지 않습니다.", nil)
		return
	}
	if in.NewPassword == in.CurrentPassword {
		problem(w, 422, "VALIDATION_FAILED", "새 비밀번호는 현재 비밀번호와 달라야 합니다.", nil)
		return
	}
	hash, err := auth.PasswordHash(in.NewPassword)
	if err != nil {
		problem(w, 422, "VALIDATION_FAILED", "새 비밀번호는 12자 이상이어야 합니다.", nil)
		return
	}
	if _, err = s.Store.Pool.Exec(r.Context(), `UPDATE users SET password_hash=$2,failed_login_count=0,locked_until=NULL,updated_at=now() WHERE id=$1`, sess.User.ID, hash); err != nil {
		problem(w, 500, "UPDATE_FAILED", "비밀번호를 변경하지 못했습니다.", nil)
		return
	}
	_, _ = s.Store.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`, sess.User.ID, sess.ID)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CHANGE_PASSWORD", "USER", sess.User.ID, nil, nil))
	w.WriteHeader(204)
}

func publicUser(u store.User) map[string]any {
	return map[string]any{"id": u.ID, "username": u.Username, "display_name": u.DisplayName, "email": u.Email, "department": u.Department, "auth_source": u.AuthSource, "active": u.Active, "roles": u.Roles}
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	admin := hasAnyRole(sess.User, "SYSTEM_ADMIN", "SECURITY_REVIEWER", "AUDITOR")
	where, args := accessFilter(sess, 1)
	if admin {
		where = "TRUE"
		args = nil
	}
	q := `SELECT status,count(*) FROM review_requests WHERE ` + where + ` GROUP BY status`
	rows, err := s.Store.Pool.Query(r.Context(), q, args...)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "대시보드를 불러오지 못했습니다.", nil)
		return
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		_ = rows.Scan(&status, &n)
		counts[status] = n
	}
	var overdue int
	args2 := append([]any{}, args...)
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM review_requests WHERE `+where+` AND planned_open_date BETWEEN current_date AND current_date+14`, args2...).Scan(&overdue)
	var openChanges int
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM change_requests c JOIN review_requests r ON r.id=c.review_request_id WHERE `+strings.ReplaceAll(where, "review_requests.", "r.")+` AND c.status='OPEN'`, args...).Scan(&openChanges)
	analytics := map[string]any{}
	if admin {
		var unassigned, longPending int
		_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM review_requests WHERE reviewer_id IS NULL AND status IN ('SUBMITTED','RESUBMITTED')`).Scan(&unassigned)
		_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM review_requests WHERE status IN ('SUBMITTED','RESUBMITTED','REVIEWING') AND updated_at<now()-interval '7 days'`).Scan(&longPending)
		rows, err := s.Store.Pool.Query(r.Context(), `SELECT si.category,rr.result,count(*) FROM review_results rr JOIN submission_items si ON si.id=rr.submission_item_id WHERE rr.result IN ('INSUFFICIENT','NON_COMPLIANT','CONDITIONAL') GROUP BY si.category,rr.result ORDER BY count(*) DESC LIMIT 20`)
		if err == nil {
			analytics["category_findings"] = scanDynamic(rows, []string{"category", "result", "count"})
		}
		rows, err = s.Store.Pool.Query(r.Context(), `SELECT si.item_code,si.title,count(*) AS failures FROM review_results rr JOIN submission_items si ON si.id=rr.submission_item_id WHERE rr.result IN ('INSUFFICIENT','NON_COMPLIANT') GROUP BY si.item_code,si.title ORDER BY failures DESC LIMIT 10`)
		if err == nil {
			analytics["recurring_controls"] = scanDynamic(rows, []string{"item_code", "title", "failures"})
		}
		analytics["unassigned"] = unassigned
		analytics["long_pending"] = longPending
	}
	jsonResponse(w, 200, map[string]any{"status_counts": counts, "opening_soon": overdue, "open_change_requests": openChanges, "security_analytics": analytics})
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	term := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(term) < 2 {
		jsonResponse(w, 200, map[string]any{"reviews": []any{}, "items": []any{}, "evidences": []any{}})
		return
	}
	like := "%" + term + "%"
	where, args := accessFilter(sess, 2)
	if hasAnyRole(sess.User, "SECURITY_REVIEWER", "AUDITOR") {
		where = "TRUE"
		args = nil
	}
	args = append([]any{like}, args...)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT review_requests.id,review_number,service_name,status,review_requests.department FROM review_requests JOIN users requester ON requester.id=review_requests.requester_id JOIN users builder ON builder.id=review_requests.builder_id JOIN users developer ON developer.id=review_requests.developer_id LEFT JOIN users reviewer ON reviewer.id=review_requests.reviewer_id LEFT JOIN users approver ON approver.id=review_requests.approver_id WHERE `+where+` AND (review_number ILIKE $1 OR service_name ILIKE $1 OR review_requests.department ILIKE $1 OR requester.display_name ILIKE $1 OR builder.display_name ILIKE $1 OR developer.display_name ILIKE $1 OR reviewer.display_name ILIKE $1 OR approver.display_name ILIKE $1 OR EXISTS(SELECT 1 FROM submissions sx JOIN submission_items six ON six.submission_id=sx.id WHERE sx.review_request_id=review_requests.id AND six.template_name ILIKE $1)) ORDER BY review_requests.updated_at DESC LIMIT 20`, args...)
	if err != nil {
		problem(w, 500, "SEARCH_FAILED", "검색하지 못했습니다.", nil)
		return
	}
	reviews := scanDynamic(rows, []string{"id", "review_number", "service_name", "status", "department"})
	itemWhere := strings.ReplaceAll(where, "review_requests.", "r.")
	rows, err = s.Store.Pool.Query(r.Context(), `SELECT DISTINCT r.id AS review_id,r.review_number,si.item_code,si.title,si.category FROM submission_items si JOIN submissions s ON s.id=si.submission_id JOIN review_requests r ON r.id=s.review_request_id LEFT JOIN review_results rr ON rr.submission_item_id=si.id WHERE `+itemWhere+` AND (si.item_code ILIKE $1 OR si.title ILIKE $1 OR si.question ILIKE $1 OR si.template_name ILIKE $1 OR rr.opinion ILIKE $1) LIMIT 20`, args...)
	if err != nil {
		problem(w, 500, "SEARCH_FAILED", "검색하지 못했습니다.", nil)
		return
	}
	items := scanDynamic(rows, []string{"review_id", "review_number", "item_code", "title", "category"})
	rows, err = s.Store.Pool.Query(r.Context(), `SELECT DISTINCT r.id AS review_id,r.review_number,e.id,e.original_filename,e.mime_type,e.created_at FROM evidences e JOIN submission_items si ON si.id=e.submission_item_id JOIN submissions sub ON sub.id=si.submission_id JOIN review_requests r ON r.id=sub.review_request_id WHERE e.deleted_at IS NULL AND `+itemWhere+` AND e.original_filename ILIKE $1 ORDER BY e.created_at DESC LIMIT 20`, args...)
	if err != nil {
		problem(w, 500, "SEARCH_FAILED", "검색하지 못했습니다.", nil)
		return
	}
	evidences := scanDynamic(rows, []string{"review_id", "review_number", "id", "original_filename", "mime_type", "created_at"})
	jsonResponse(w, 200, map[string]any{"reviews": reviews, "items": items, "evidences": evidences})
}

func accessFilter(sess auth.Session, start int) (string, []any) {
	return fmt.Sprintf(`(review_requests.requester_id=$%d OR review_requests.builder_id=$%d OR review_requests.developer_id=$%d OR review_requests.reviewer_id=$%d OR review_requests.approver_id=$%d OR EXISTS(SELECT 1 FROM review_participants rp WHERE rp.review_request_id=review_requests.id AND rp.user_id=$%d))`, start, start, start, start, start, start), []any{sess.User.ID}
}

// scanDynamic is used for small administrative lists where a stable JSON object is more useful than repetitive structs.
func scanDynamic(rows interface {
	Next() bool
	Values() ([]any, error)
	Close()
	Err() error
}, names []string) []map[string]any {
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			break
		}
		m := map[string]any{}
		for i, n := range names {
			if i < len(vals) {
				m[n] = vals[i]
			}
		}
		out = append(out, m)
	}
	return out
}

func (s *Server) notifications(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,event_type,title,body,status,read_at,created_at FROM notifications WHERE recipient_id=$1 ORDER BY created_at DESC LIMIT 50`, session(r).User.ID)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "알림을 불러오지 못했습니다.", nil)
		return
	}
	jsonResponse(w, 200, scanDynamic(rows, []string{"id", "event_type", "title", "body", "status", "read_at", "created_at"}))
}

func (s *Server) userDirectory(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,username,display_name,department FROM users WHERE active ORDER BY display_name`)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "사용자 목록을 불러오지 못했습니다.", nil)
		return
	}
	jsonResponse(w, 200, scanDynamic(rows, []string{"id", "username", "display_name", "department"}))
}

// unreadNotifications backs the badge in the header, so it stays a single
// counting query rather than the full list.
func (s *Server) unreadNotifications(w http.ResponseWriter, r *http.Request) {
	var count int64
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND read_at IS NULL`, session(r).User.ID).Scan(&count)
	jsonResponse(w, 200, map[string]any{"count": count})
}

func (s *Server) readAllNotifications(w http.ResponseWriter, r *http.Request) {
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE notifications SET read_at=now(),status='READ' WHERE recipient_id=$1 AND read_at IS NULL`, session(r).User.ID)
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "알림을 갱신하지 못했습니다.", nil)
		return
	}
	jsonResponse(w, 200, map[string]any{"updated": tag.RowsAffected()})
}

func (s *Server) readNotification(w http.ResponseWriter, r *http.Request) {
	_, err := s.Store.Pool.Exec(r.Context(), `UPDATE notifications SET read_at=now(),status='READ' WHERE id=$1 AND recipient_id=$2`, r.PathValue("id"), session(r).User.ID)
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "알림을 갱신하지 못했습니다.", nil)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) systemInfo(w http.ResponseWriter, r *http.Request) {
	var users, reviews, templates, evidences, logs int64
	var dbSize string
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM review_requests),(SELECT count(*) FROM checklist_templates),(SELECT count(*) FROM evidences WHERE deleted_at IS NULL),(SELECT count(*) FROM application_logs),pg_size_pretty(pg_database_size(current_database()))`).Scan(&users, &reviews, &templates, &evidences, &logs, &dbSize)
	jsonResponse(w, 200, map[string]any{"version": s.Version, "go_version": runtime.Version(), "users": users, "reviews": reviews, "templates": templates, "evidences": evidences, "logs": logs, "database_size": dbSize, "now": time.Now()})
}

func (s *Server) ensureUserDataKey(ctx context.Context, userID string) error {
	var n int
	if err := s.Store.Pool.QueryRow(ctx, `SELECT count(*) FROM user_data_keys WHERE user_id=$1`, userID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	key, err := cryptox.RandomBytes(32)
	if err != nil {
		return err
	}
	encrypted, err := s.Box.Encrypt(key, []byte("user-key:"+userID+":1"))
	if err != nil {
		return err
	}
	_, err = s.Store.Pool.Exec(ctx, `INSERT INTO user_data_keys(user_id,version,encrypted_key) VALUES($1,1,$2)`, userID, encrypted)
	return err
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,name,prefix,scopes,expires_at,last_used_at,revoked_at,created_at FROM api_keys WHERE user_id=$1 ORDER BY created_at DESC`, session(r).User.ID)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "API 키를 불러오지 못했습니다.", nil)
		return
	}
	jsonResponse(w, 200, scanDynamic(rows, []string{"id", "name", "prefix", "scopes", "expires_at", "last_used_at", "revoked_at", "created_at"}))
}
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	s.issueAPIKey(w, r, in.Name, in.Scopes, in.ExpiresAt, "")
}
func (s *Server) rotateAPIKey(w http.ResponseWriter, r *http.Request) {
	var name string
	var scopes []string
	var expires *time.Time
	err := s.Store.Pool.QueryRow(r.Context(), `UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL RETURNING name,scopes,expires_at`, r.PathValue("id"), session(r).User.ID).Scan(&name, &scopes, &expires)
	if err != nil {
		problem(w, 404, "NOT_FOUND", "API 키를 찾을 수 없습니다.", nil)
		return
	}
	s.issueAPIKey(w, r, name, scopes, expires, r.PathValue("id"))
}
func (s *Server) issueAPIKey(w http.ResponseWriter, r *http.Request, name string, scopes []string, expires *time.Time, rotatedFrom string) {
	if strings.TrimSpace(name) == "" {
		problem(w, 400, "VALIDATION_FAILED", "키 이름은 필수입니다.", nil)
		return
	}
	if len(scopes) == 0 {
		scopes = []string{"read"}
	}
	if len(scopes) != 1 || (scopes[0] != "read" && scopes[0] != "read:write") {
		problem(w, 422, "VALIDATION_FAILED", "API 키 범위는 read 또는 read:write여야 합니다.", nil)
		return
	}
	if expires != nil && !expires.After(time.Now()) {
		problem(w, 422, "VALIDATION_FAILED", "API 키 만료일은 현재 이후여야 합니다.", nil)
		return
	}
	raw, _ := cryptox.Token(32)
	token := "sck_" + raw
	h := sha256.Sum256([]byte(token))
	id := store.NewID()
	_, err := s.Store.Pool.Exec(r.Context(), `INSERT INTO api_keys(id,user_id,name,prefix,secret_hash,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, session(r).User.ID, name, token[:12], h[:], scopes, expires)
	if err != nil {
		problem(w, 500, "CREATE_FAILED", "API 키를 만들지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "ROTATE_API_KEY", "API_KEY", id, map[string]any{"rotated_from": rotatedFrom}, map[string]any{"name": name, "scopes": scopes}))
	jsonResponse(w, 201, map[string]any{"id": id, "name": name, "token": token, "prefix": token[:12], "scopes": scopes, "expires_at": expires, "warning": "이 키는 다시 표시되지 않습니다."})
}
func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, r.PathValue("id"), session(r).User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 404, "NOT_FOUND", "API 키를 찾을 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "REVOKE_API_KEY", "API_KEY", r.PathValue("id"), nil, nil))
	w.WriteHeader(204)
}
func (s *Server) rotateDataKey(w http.ResponseWriter, r *http.Request) {
	uid := session(r).User.ID
	var version int
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT COALESCE(max(version),0)+1 FROM user_data_keys WHERE user_id=$1`, uid).Scan(&version)
	key, _ := cryptox.RandomBytes(32)
	encrypted, err := s.Box.Encrypt(key, []byte(fmt.Sprintf("user-key:%s:%d", uid, version)))
	if err != nil {
		problem(w, 500, "ROTATE_FAILED", "암호화 키를 회전하지 못했습니다.", nil)
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE user_data_keys SET active=false,retired_at=now() WHERE user_id=$1 AND active`, uid)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO user_data_keys(user_id,version,encrypted_key) VALUES($1,$2,$3)`, uid, version, encrypted)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
	}
	if err != nil {
		problem(w, 500, "ROTATE_FAILED", "암호화 키를 회전하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "ROTATE_ENCRYPTION_KEY", "USER_KEY", uid, nil, map[string]any{"version": version}))
	jsonResponse(w, 200, map[string]any{"version": version, "rotated_at": time.Now()})
}

func hashString(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func verifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
