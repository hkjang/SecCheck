package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/auth"
	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/maintenance"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/jackc/pgx/v5"
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
	// The route is registered as public so a scrape needs no session, but an
	// installation that would rather not publish its counts can turn that off
	// and scrape with a read-scoped API key instead.
	if !s.runtimeSecurity(r.Context()).metricsPublic() {
		if _, err := s.Auth.Authenticate(r); err != nil {
			problem(w, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "지표 조회에 인증이 필요하도록 설정되어 있습니다.", nil)
			return
		}
	}
	var users, reviews, pending, failedJobs, requests, requestErrors, loginOK, loginFail, storageBytes, scanFailures, submissionFailures, sessions, lockedAccounts, pendingScans, unreadableEvidence, uncheckedEvidence int64
	var avgDuration, oldestPending float64
	// Reporting zeros because the query failed is a false all-clear: a scraper
	// would record "no failed jobs, no locked accounts, no audit write
	// failures" at the moment the database stopped answering. A failed scrape
	// marks the target down, which is the truth.
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM review_requests),(SELECT count(*) FROM jobs WHERE status='PENDING'),(SELECT count(*) FROM jobs WHERE status='FAILED'),(SELECT count(*) FROM application_logs WHERE component='http' AND timestamp>now()-interval '5 minutes'),(SELECT count(*) FROM application_logs WHERE component='http' AND timestamp>now()-interval '5 minutes' AND (fields->>'status')::int>=500),(SELECT COALESCE(avg((fields->>'duration_ms')::numeric),0) FROM application_logs WHERE component='http' AND timestamp>now()-interval '5 minutes' AND fields->>'duration_ms' ~ '^[0-9]+$'),(SELECT count(*) FROM audit_logs WHERE event_type='LOGIN' AND timestamp>now()-interval '24 hours'),(SELECT count(*) FROM audit_logs WHERE event_type='LOGIN_FAIL' AND timestamp>now()-interval '24 hours'),(SELECT COALESCE(sum(size_bytes),0) FROM evidence_versions WHERE purged_at IS NULL),(SELECT count(*) FROM evidences WHERE scan_status='ERROR' AND deleted_at IS NULL),(SELECT count(*) FROM application_logs WHERE component='http' AND timestamp>now()-interval '24 hours' AND fields->>'path' LIKE '%/submit' AND (fields->>'status')::int>=400),(SELECT count(*) FROM sessions WHERE expires_at>now()),(SELECT count(*) FROM users WHERE locked_until>now()),(SELECT count(*) FROM evidences WHERE scan_status='PENDING' AND deleted_at IS NULL),(SELECT coalesce(extract(epoch FROM now()-min(available_at)),0) FROM jobs WHERE status='PENDING' AND available_at<=now()),(SELECT count(*) FROM evidences WHERE verify_error<>'' AND deleted_at IS NULL AND purged_at IS NULL),(SELECT count(*) FROM evidences WHERE verified_at IS NULL AND deleted_at IS NULL AND purged_at IS NULL)`).Scan(&users, &reviews, &pending, &failedJobs, &requests, &requestErrors, &avgDuration, &loginOK, &loginFail, &storageBytes, &scanFailures, &submissionFailures, &sessions, &lockedAccounts, &pendingScans, &oldestPending, &unreadableEvidence, &uncheckedEvidence); err != nil {
		problem(w, http.StatusServiceUnavailable, "NOT_READY", "지표를 수집하지 못했습니다.", nil)
		return
	}
	pool := s.Store.Pool.Stat()
	// The disk the evidence lives on is the one that stops uploads when it
	// fills, and it was the one figure nothing exported.
	space := s.vault().Space()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP seccheck_info SecCheck build information\n# TYPE seccheck_info gauge\nseccheck_info{version=%q} 1\n# TYPE seccheck_users_total gauge\nseccheck_users_total %d\n# TYPE seccheck_reviews_total gauge\nseccheck_reviews_total %d\n# TYPE seccheck_jobs_pending gauge\nseccheck_jobs_pending %d\n# TYPE seccheck_jobs_failed gauge\nseccheck_jobs_failed %d\n# HELP seccheck_jobs_oldest_pending_seconds How long the oldest already-due job has waited; a queue that is draining keeps this near zero\n# TYPE seccheck_jobs_oldest_pending_seconds gauge\nseccheck_jobs_oldest_pending_seconds %.0f\n# HELP seccheck_audit_write_failures Audit events lost since start-up; any value above zero means an action happened with no record of it\n# TYPE seccheck_audit_write_failures gauge\nseccheck_audit_write_failures %d\n# TYPE seccheck_http_requests_5m gauge\nseccheck_http_requests_5m %d\n# TYPE seccheck_http_errors_5m gauge\nseccheck_http_errors_5m %d\n# TYPE seccheck_http_duration_ms_5m gauge\nseccheck_http_duration_ms_5m %.3f\n# TYPE seccheck_login_success_24h gauge\nseccheck_login_success_24h %d\n# TYPE seccheck_login_failure_24h gauge\nseccheck_login_failure_24h %d\n# TYPE seccheck_evidence_version_bytes gauge\nseccheck_evidence_version_bytes %d\n# TYPE seccheck_scan_failures gauge\nseccheck_scan_failures %d\n# TYPE seccheck_submission_failures_24h gauge\nseccheck_submission_failures_24h %d\n# TYPE seccheck_sessions_active gauge\nseccheck_sessions_active %d\n# TYPE seccheck_accounts_locked gauge\nseccheck_accounts_locked %d\n# TYPE seccheck_evidence_scan_pending gauge\nseccheck_evidence_scan_pending %d\n# TYPE seccheck_evidence_unreadable gauge\nseccheck_evidence_unreadable %d\n# TYPE seccheck_evidence_unverified gauge\nseccheck_evidence_unverified %d\n# TYPE seccheck_db_connections gauge\nseccheck_db_connections{state=\"total\"} %d\nseccheck_db_connections{state=\"acquired\"} %d\nseccheck_db_connections{state=\"idle\"} %d\n# TYPE seccheck_storage_free_bytes gauge\nseccheck_storage_free_bytes %d\n# TYPE seccheck_storage_writable gauge\nseccheck_storage_writable %d\n# HELP seccheck_maintenance_last_run_seconds Age of the last completed housekeeping sweep; it runs hourly, so a value that keeps climbing means reminders, evidence checks and the audit-chain check have all stopped\n# TYPE seccheck_maintenance_last_run_seconds gauge\nseccheck_maintenance_last_run_seconds %.0f\n", s.Version, users, reviews, pending, failedJobs, oldestPending, s.Store.AuditFailures(), requests, requestErrors, avgDuration, loginOK, loginFail, storageBytes, scanFailures, submissionFailures, sessions, lockedAccounts, pendingScans, unreadableEvidence, uncheckedEvidence, pool.TotalConns(), pool.AcquiredConns(), pool.IdleConns(), space.FreeBytes, boolGauge(space.Writable), s.maintenanceAge(r.Context()))
}

// boolGauge renders a yes/no fact the way Prometheus expects to read one.
func boolGauge(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *Server) publicConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.Auth.OIDCConfig(r.Context())
	if err != nil {
		cfg = auth.OIDCSettings{}
	}
	jsonResponse(w, 200, map[string]any{"service_name": "SecCheck", "version": s.Version, "oidc_enabled": cfg.Enabled, "oidc_issuer": cfg.Issuer, "timezone": s.Store.Location(r.Context()).String()})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
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
	u, token, csrf, expires, err := s.Auth.PasswordLogin(r.Context(), auth.Credentials{Username: in.Username, Password: in.Password, TOTPCode: in.TOTPCode, IP: clientIP(r), UserAgent: r.UserAgent()})
	// A correct password that is merely missing its one-time code is not a
	// failed attempt and must not spend the throttle budget.
	if errors.Is(err, auth.ErrTOTPRequired) {
		problem(w, 401, "TOTP_REQUIRED", "인증 앱의 6자리 코드를 입력하세요.", nil)
		return
	}
	if err != nil {
		s.loginLimiter.record(clientIP(r))
	}
	if errors.Is(err, auth.ErrTOTPInvalid) {
		_ = s.Store.Audit(r.Context(), store.AuditEvent{UserID: u.ID, UserName: in.Username, SourceIP: clientIP(r), EventType: "LOGIN_FAIL", TargetType: "USER", TargetID: u.ID, RequestID: requestID(r), Result: "FAILURE", After: map[string]any{"reason": "totp"}})
		problem(w, 401, "TOTP_INVALID", "일회용 코드가 올바르지 않습니다.", nil)
		return
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
		// The sign-in button is a link, so the browser navigates here. A JSON
		// problem document left the person staring at machine output on a page
		// that is not the service. They go back to the sign-in screen with
		// something to read, and the reason is recorded for the operator.
		s.Store.Log(r.Context(), "ERROR", requestID(r), "auth", "OIDC 인증을 시작하지 못했습니다.", map[string]any{"error": err.Error()})
		_ = s.Store.Audit(r.Context(), store.AuditEvent{SourceIP: clientIP(r), EventType: "LOGIN_FAIL", TargetType: "OIDC", RequestID: requestID(r), Result: "FAILURE", After: map[string]any{"stage": "start", "error": err.Error()}})
		http.Redirect(w, r, "/login?error=oidc_unavailable", http.StatusFound)
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
	// The upload rules the server enforces, so the screen can refuse a file
	// that is too large or of the wrong kind before spending minutes sending it
	// over a slow link only to be told no.
	var upload struct {
		MaxSizeMB         int      `json:"max_size_mb"`
		AllowedExtensions []string `json:"allowed_extensions"`
	}
	_, _ = s.Store.Setting(r.Context(), "upload", &upload)
	if upload.AllowedExtensions == nil {
		upload.AllowedExtensions = []string{}
	}
	// The same caps the write handlers refuse on, so a long paragraph is
	// stopped in the box instead of failing every auto-save.
	limits := map[string]any{"long_text": longTextLimit, "short_text": shortTextLimit}
	// The inactivity timeout is enforced on the next request and until now was
	// only known to the server: somebody reading a long checklist, which makes
	// no requests at all, was dropped at the login screen without warning and
	// lost whatever was typed but not yet auto-saved. The screen can only warn
	// if it knows the rule.
	session := map[string]any{"idle_timeout_minutes": s.Auth.Policy(r.Context()).IdleTimeoutMinutes}
	jsonResponse(w, 200, map[string]any{"user": publicUser(sess.User), "csrf_token": sess.CSRF, "version": s.Version, "totp_enrollment_required": sess.EnrollTOTP, "password_change_required": sess.User.MustChangePassword, "upload": map[string]any{"max_size_mb": upload.MaxSizeMB, "allowed_extensions": upload.AllowedExtensions}, "limits": limits, "session": session, "timezone": s.Store.Location(r.Context()).String()})
}
func (s *Server) updateMe(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DisplayName *string `json:"display_name"`
		Email       *string `json:"email"`
		Department  *string `json:"department"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	name, email, department := trimmedPatch(in.DisplayName), trimmedPatch(in.Email), trimmedPatch(in.Department)
	if blankedOut(name) {
		problem(w, 422, "VALIDATION_FAILED", "표시 이름은 비울 수 없습니다.", nil)
		return
	}
	// The display name is written into every audit entry and notification the
	// account touches, so its length is not only this person's business.
	for field, limits := range map[string]int{"display_name": 100, "email": 200, "department": 100} {
		value := map[string]*string{"display_name": name, "email": email, "department": department}[field]
		if value != nil && len([]rune(*value)) > limits {
			problem(w, 422, "VALIDATION_FAILED", fmt.Sprintf("%s는 %d자 이내로 입력하세요.", field, limits), map[string]string{field: "너무 깁니다."})
			return
		}
	}
	sess := session(r)
	_, err := s.Store.Pool.Exec(r.Context(), `UPDATE users SET display_name=COALESCE($2::text,display_name),email=COALESCE($3::text,email),department=COALESCE($4::text,department),updated_at=now() WHERE id=$1`, sess.User.ID, name, email, department)
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "프로필을 저장하지 못했습니다.", err)
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
		// Recorded as what it is. The result column defaults to SUCCESS, so a
		// refused attempt used to sit in the log looking exactly like a
		// password that was changed -- and a burst of them, which is what
		// somebody probing a hijacked session leaves behind, looked like a
		// burst of ordinary changes.
		refused := auditFrom(r, "CHANGE_PASSWORD", "USER", sess.User.ID, nil, map[string]any{"reason": "current password mismatch"})
		refused.Result = "FAILURE"
		_ = s.Store.Audit(r.Context(), refused)
		problem(w, 403, "INVALID_CREDENTIALS", "현재 비밀번호가 올바르지 않습니다.", nil)
		return
	}
	if in.NewPassword == in.CurrentPassword {
		problem(w, 422, "VALIDATION_FAILED", "새 비밀번호는 현재 비밀번호와 달라야 합니다.", nil)
		return
	}
	if reason := auth.PasswordProblem(in.NewPassword, sess.User.Username); reason != "" {
		problem(w, 422, "WEAK_PASSWORD", reason, map[string]string{"new_password": reason})
		return
	}
	hash, err := auth.PasswordHash(in.NewPassword)
	if err != nil {
		problem(w, 422, "VALIDATION_FAILED", "새 비밀번호는 12자 이상이어야 합니다.", nil)
		return
	}
	// Changing the password and signing the other devices out are one change.
	// Somebody changing it because a session was taken is told the other
	// sessions are gone, and half of that is worse than neither.
	if err = s.inTx(r.Context(), func(tx pgx.Tx) error {
		if _, txErr := tx.Exec(r.Context(), `UPDATE users SET password_hash=$2,must_change_password=false,failed_login_count=0,locked_until=NULL,updated_at=now() WHERE id=$1`, sess.User.ID, hash); txErr != nil {
			return txErr
		}
		_, txErr := tx.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`, sess.User.ID, sess.ID)
		return txErr
	}); err != nil {
		s.fault(w, r, "UPDATE_FAILED", "비밀번호를 변경하지 못했습니다. 기존 비밀번호와 세션이 그대로 유지됩니다.", err)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CHANGE_PASSWORD", "USER", sess.User.ID, nil, nil))
	w.WriteHeader(204)
}

func publicUser(u store.User) map[string]any {
	return map[string]any{"id": u.ID, "username": u.Username, "display_name": u.DisplayName, "email": u.Email, "department": u.Department, "auth_source": u.AuthSource, "active": u.Active, "roles": u.Roles}
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	// Who sees every review here is decided by the same rule as the review
	// list, because every number on this page opens that list. A system
	// administrator who is not also a reviewer used to be counted as reading
	// everything: the cards said 진행 중 42, the list behind them held their
	// own reviews only, and the rows in 보완 조치 기한 and 내 후속조치 linked
	// to reviews that answered 404. Oversight of the whole estate is what the
	// report is for; the dashboard is the reader's own desk and queue.
	admin := hasAnyRole(sess.User, "SECURITY_REVIEWER", "AUDITOR")
	where, args := accessFilter(sess, 1)
	if admin {
		where = "TRUE"
		args = nil
	}
	q := `SELECT status,count(*) FROM review_requests WHERE ` + where + ` GROUP BY status`
	rows, err := s.Store.Pool.Query(r.Context(), q, args...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "대시보드를 불러오지 못했습니다.", err)
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
	// The first query of this handler fails loudly; these did not, so a database
	// that started refusing mid-request answered "nothing opens soon, no launch
	// is at risk, no change request is open" -- the three numbers people act on
	// -- with the rest of the page intact.
	count := func(query string, args ...any) (int, bool) {
		var n int
		if err := s.Store.Pool.QueryRow(r.Context(), query, args...).Scan(&n); err != nil {
			s.fault(w, r, "QUERY_FAILED", "대시보드를 불러오지 못했습니다.", err)
			return 0, false
		}
		return n, true
	}
	overdue, ok := count(`SELECT count(*) FROM review_requests WHERE `+where+` AND planned_open_date BETWEEN display_today() AND display_today()+14`, append([]any{}, args...)...)
	if !ok {
		return
	}
	// The number that matters is not how many services open soon but how many
	// of them are opening with the review unfinished -- the count the alert
	// mails are about.
	openingUnfinished, ok := count(`SELECT count(*) FROM review_requests WHERE `+where+`
                AND planned_open_date IS NOT NULL AND planned_open_date <= display_today()+14
                AND status NOT IN ('APPROVED','CLOSED','CANCELLED','REJECTED')`, append([]any{}, args...)...)
	if !ok {
		return
	}
	// A cancelled review is a service that is not being built. The corrections
	// written on it were never withdrawn, so they went on being counted here,
	// listed as overdue below and mailed about every three days -- work nobody
	// could do on a review nobody could reopen.
	openChanges, ok := count(`SELECT count(*) FROM change_requests c JOIN review_requests r ON r.id=c.review_request_id WHERE `+strings.ReplaceAll(where, "review_requests.", "r.")+` AND c.status='OPEN' AND r.status<>'CANCELLED'`, args...)
	if !ok {
		return
	}
	// A correction the team has answered is waiting for the reviewer to accept
	// it, and until they do the review cannot be completed. That work was on
	// nobody's screen: 미처리 counts what the author still owes, 보완 조치 기한
	// only reaches a week ahead, and a correction answered in March with a
	// June deadline appeared in neither.
	awaiting, ok := count(`SELECT count(*) FROM change_requests c JOIN review_requests r ON r.id=c.review_request_id WHERE `+strings.ReplaceAll(where, "review_requests.", "r.")+` AND c.status='DONE' AND r.status<>'CANCELLED'`, args...)
	if !ok {
		return
	}
	// Two counts a security lead acts on, and links that lead to the exact list.
	// The two aggregations that used to sit here -- findings by category and the
	// most repeated failures -- were computed on every load of the busiest
	// screen and read by nobody: the report screen has both, and no other caller
	// asked for them.
	analytics := map[string]any{}
	if admin {
		unassigned, ok := count(`SELECT count(*) FROM review_requests WHERE ` + unownedClause())
		if !ok {
			return
		}
		longPending, ok := count(`SELECT count(*) FROM review_requests WHERE status = ANY($2) AND updated_at<now()-make_interval(days=>$1)`, maintenance.StalledReviewDays, maintenance.StalledStatuses)
		if !ok {
			return
		}
		analytics["unassigned"] = unassigned
		analytics["long_pending"] = longPending
		analytics["long_pending_days"] = maintenance.StalledReviewDays
	}
	// Each card says whether it is showing everything: a list that stops at
	// twelve without a word reads as the whole of somebody's work.
	queue, queueMore := s.myQueue(r)
	due, dueMore := s.dueChangeRequests(r)
	follows, followsMore := s.myFollowUps(r)
	mine, mineMore := s.myAssignedItems(r)
	jsonResponse(w, 200, map[string]any{"status_counts": counts, "opening_soon": overdue, "opening_soon_unfinished": openingUnfinished, "open_change_requests": openChanges, "awaiting_verification": awaiting, "security_analytics": analytics,
		"my_queue": queue, "due_soon": due, "my_follow_ups": follows, "my_items": mine,
		"has_more": map[string]bool{"my_queue": queueMore, "due_soon": dueMore, "my_follow_ups": followsMore, "my_items": mineMore}})
}

// myQueue lists the reviews that are actually waiting on the signed-in person,
// so the dashboard opens on work rather than on statistics.
func (s *Server) myQueue(r *http.Request) ([]map[string]any, bool) {
	sess := session(r)
	where := myTurnClause(sess, 1)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT review_requests.id,review_number,service_name,review_requests.status,planned_open_date,review_requests.updated_at,
                CASE
                  WHEN review_requests.status IN ('DRAFT','CHANGE_REQUESTED') THEN '작성·보완'
                  WHEN review_requests.status IN ('SUBMITTED','RESUBMITTED') THEN '검토 시작'
                  WHEN review_requests.status='REVIEWING' THEN '검토 진행'
                  ELSE '승인'
                END
                FROM review_requests WHERE `+where+` ORDER BY planned_open_date ASC NULLS LAST, review_requests.updated_at ASC LIMIT 13`, sess.User.ID)
	if err != nil {
		return []map[string]any{}, false
	}
	rows2, scanErr := scanDynamic(rows, []string{"id", "review_number", "service_name", "status", "planned_open_date", "updated_at", "action"})
	if scanErr != nil {
		return []map[string]any{}, false
	}
	return trimDashboard(rows2)
}

// dueChangeRequests surfaces the change requests whose due date has passed or
// is about to. The due date was previously captured and then never used.
// myFollowUps is the requester's side of the register. The report that
// collects outstanding actions is for the security team; the people who
// actually carry them out cannot open it, so their own commitments were
// visible only one review at a time.
func (s *Server) myFollowUps(r *http.Request) ([]map[string]any, bool) {
	sess := session(r)
	where, args := accessFilter(sess, 1)
	if hasAnyRole(sess.User, "SECURITY_REVIEWER", "AUDITOR") {
		where = "TRUE"
		args = nil
	}
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT rr.id,review_requests.id AS review_id,review_requests.review_number,review_requests.service_name,si.id AS item_id,si.item_code,si.title,
                rr.follow_up,to_char(rr.follow_up_due_date,'YYYY-MM-DD') AS due_date,
                (rr.follow_up_due_date IS NOT NULL AND rr.follow_up_due_date < display_today()) AS overdue,
                (rr.follow_up_reported_at IS NOT NULL) AS reported
                FROM review_results rr
                JOIN submission_items si ON si.id=rr.submission_item_id
                JOIN submissions sub ON sub.id=si.submission_id
                JOIN review_requests ON review_requests.id=sub.review_request_id
                WHERE btrim(rr.follow_up)<>'' AND rr.follow_up_done_at IS NULL AND review_requests.status<>'CANCELLED' AND `+where+`
                ORDER BY rr.follow_up_due_date NULLS LAST,review_requests.review_number LIMIT 13`, args...)
	if err != nil {
		return []map[string]any{}, false
	}
	rows2, scanErr := scanDynamic(rows, []string{"id", "review_id", "review_number", "service_name", "item_id", "item_code", "title", "follow_up", "due_date", "overdue", "reported"})
	if scanErr != nil {
		return []map[string]any{}, false
	}
	return trimDashboard(rows2)
}

// myAssignedItems answers "where is the work that is mine". Assigning items to
// the people who will fill them in is how a long checklist gets divided up,
// and the person on the receiving end could see their share only by opening
// each review and switching the filter -- there was no view across reviews at
// all, so a contributor with items in three reviews had to remember which
// three. A correction handed to somebody by name counts as theirs too, even
// when the item itself was written by someone else: it is work with their
// name on it and a date attached.
func (s *Server) myAssignedItems(r *http.Request) ([]map[string]any, bool) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT review_requests.id AS review_id,review_requests.review_number,review_requests.service_name,review_requests.status,
                count(*) AS items,
                count(*) FILTER (WHERE resp.assigned_to=$1 AND COALESCE(resp.applicability,'')='') AS unanswered,
                count(*) FILTER (WHERE mine.open_change) AS to_fix
                FROM submission_items si
                JOIN submissions sub ON sub.id=si.submission_id
                JOIN review_requests ON review_requests.id=sub.review_request_id
                LEFT JOIN responses resp ON resp.submission_item_id=si.id
                CROSS JOIN LATERAL (SELECT
                        EXISTS(SELECT 1 FROM change_requests cr WHERE cr.submission_item_id=si.id AND cr.status<>'VERIFIED') AS open_change,
                        EXISTS(SELECT 1 FROM change_requests cr WHERE cr.submission_item_id=si.id AND cr.status<>'VERIFIED' AND cr.assignee_id=$1) AS my_change) mine
                WHERE (resp.assigned_to=$1 OR mine.my_change)
                  AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=review_requests.id)
                  AND review_requests.status IN ('DRAFT','CHANGE_REQUESTED')
                GROUP BY review_requests.id,review_requests.review_number,review_requests.service_name,review_requests.status
                HAVING count(*) FILTER (WHERE resp.assigned_to=$1 AND COALESCE(resp.applicability,'')='') > 0
                    OR count(*) FILTER (WHERE mine.open_change) > 0
                ORDER BY count(*) FILTER (WHERE mine.open_change) DESC,count(*) FILTER (WHERE resp.assigned_to=$1 AND COALESCE(resp.applicability,'')='') DESC,review_requests.review_number LIMIT 13`, session(r).User.ID)
	if err != nil {
		return []map[string]any{}, false
	}
	out, scanErr := scanDynamic(rows, []string{"review_id", "review_number", "service_name", "status", "items", "unanswered", "to_fix"})
	if scanErr != nil {
		return []map[string]any{}, false
	}
	return trimDashboard(out)
}

func (s *Server) dueChangeRequests(r *http.Request) ([]map[string]any, bool) {
	sess := session(r)
	where, args := accessFilter(sess, 1)
	if hasAnyRole(sess.User, "SECURITY_REVIEWER", "AUDITOR") {
		where = "TRUE"
		args = nil
	}
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT c.id,c.review_request_id,review_requests.review_number,review_requests.service_name,si.id AS item_id,si.item_code,si.title,c.due_date,c.status,(c.due_date < display_today()) AS overdue
                FROM change_requests c
                JOIN review_requests ON review_requests.id=c.review_request_id
                JOIN submission_items si ON si.id=c.submission_item_id
                WHERE c.status<>'VERIFIED' AND c.due_date IS NOT NULL AND c.due_date <= display_today()+7 AND review_requests.status<>'CANCELLED' AND `+where+`
                ORDER BY c.due_date ASC LIMIT 13`, args...)
	if err != nil {
		return []map[string]any{}, false
	}
	rows2, scanErr := scanDynamic(rows, []string{"id", "review_request_id", "review_number", "service_name", "item_id", "item_code", "title", "due_date", "status", "overdue"})
	if scanErr != nil {
		return []map[string]any{}, false
	}
	return trimDashboard(rows2)
}

// searchPageSize is how many hits of each kind a search shows. One more than
// this is read from the database so the screen knows whether it is showing
// everything.
const searchPageSize = 20

// dashboardRows is how many rows a dashboard card shows. One more than that
// is fetched so the card can say there are more: a list that stops at twelve
// without a word reads as the whole of somebody's work, which is the number
// they then act on.
const dashboardRows = 12

func trimDashboard(rows []map[string]any) ([]map[string]any, bool) {
	if len(rows) > dashboardRows {
		return rows[:dashboardRows], true
	}
	return rows, false
}

func trimSearch(rows []map[string]any) ([]map[string]any, bool) {
	if len(rows) > searchPageSize {
		return rows[:searchPageSize], true
	}
	return rows, false
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	term := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(term) < 2 {
		jsonResponse(w, 200, map[string]any{"reviews": []any{}, "items": []any{}, "evidences": []any{}, "has_more": map[string]bool{}})
		return
	}
	like := "%" + term + "%"
	where, args := accessFilter(sess, 2)
	if hasAnyRole(sess.User, "SECURITY_REVIEWER", "AUDITOR") {
		where = "TRUE"
		args = nil
	}
	args = append([]any{like}, args...)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT review_requests.id,review_number,service_name,status,review_requests.department FROM review_requests JOIN users requester ON requester.id=review_requests.requester_id JOIN users builder ON builder.id=review_requests.builder_id JOIN users developer ON developer.id=review_requests.developer_id LEFT JOIN users operator ON operator.id=review_requests.operator_id LEFT JOIN users reviewer ON reviewer.id=review_requests.reviewer_id LEFT JOIN users approver ON approver.id=review_requests.approver_id WHERE `+where+` AND (review_number ILIKE $1 OR service_name ILIKE $1 OR review_requests.department ILIKE $1 OR requester.display_name ILIKE $1 OR builder.display_name ILIKE $1 OR developer.display_name ILIKE $1 OR operator.display_name ILIKE $1 OR reviewer.display_name ILIKE $1 OR approver.display_name ILIKE $1 OR EXISTS(SELECT 1 FROM submissions sx JOIN submission_items six ON six.submission_id=sx.id WHERE sx.review_request_id=review_requests.id AND six.template_name ILIKE $1)) ORDER BY review_requests.updated_at DESC LIMIT 21`, args...)
	if err != nil {
		s.fault(w, r, "SEARCH_FAILED", "검색하지 못했습니다.", err)
		return
	}
	reviews, err := scanDynamic(rows, []string{"id", "review_number", "service_name", "status", "department"})
	if err != nil {
		s.fault(w, r, "SEARCH_FAILED", "검색하지 못했습니다.", err)
		return
	}
	itemWhere := strings.ReplaceAll(where, "review_requests.", "r.")
	// What the team wrote is the largest body of text in the service and the
	// only part of a review that says what was actually done, and it was the
	// one part the search could not see: "which services said they use this
	// library" and "who answered N/A, and why" had no answer here. The hit is
	// labelled and quoted, because a result that matches on text the reader
	// cannot see reads as a mistake.
	rows, err = s.Store.Pool.Query(r.Context(), `SELECT DISTINCT r.id AS review_id,r.review_number,si.id AS item_id,si.item_code,si.title,si.category,
                CASE WHEN si.item_code ILIKE $1 OR si.title ILIKE $1 OR si.question ILIKE $1 OR si.template_name ILIKE $1 THEN '항목'
                     WHEN COALESCE(rr.opinion,'') ILIKE $1 THEN '검토 의견'
                     ELSE '답변' END AS matched,
                left(regexp_replace(CASE
                     WHEN si.item_code ILIKE $1 OR si.title ILIKE $1 OR si.question ILIKE $1 OR si.template_name ILIKE $1 THEN ''
                     WHEN COALESCE(rr.opinion,'') ILIKE $1 THEN rr.opinion
                     WHEN COALESCE(resp.current_state,'') ILIKE $1 THEN resp.current_state
                     WHEN COALESCE(resp.action_plan,'') ILIKE $1 THEN resp.action_plan
                     WHEN COALESCE(resp.na_reason,'') ILIKE $1 THEN resp.na_reason
                     ELSE '' END, '\s+', ' ', 'g'), 160) AS excerpt
                FROM submission_items si
                JOIN submissions s ON s.id=si.submission_id
                JOIN review_requests r ON r.id=s.review_request_id
                LEFT JOIN review_results rr ON rr.submission_item_id=si.id
                LEFT JOIN responses resp ON resp.submission_item_id=si.id
                WHERE `+itemWhere+` AND (si.item_code ILIKE $1 OR si.title ILIKE $1 OR si.question ILIKE $1 OR si.template_name ILIKE $1 OR rr.opinion ILIKE $1
                        OR resp.current_state ILIKE $1 OR resp.action_plan ILIKE $1 OR resp.na_reason ILIKE $1) LIMIT 21`, args...)
	if err != nil {
		s.fault(w, r, "SEARCH_FAILED", "검색하지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"review_id", "review_number", "item_id", "item_code", "title", "category", "matched", "excerpt"})
	if err != nil {
		s.fault(w, r, "SEARCH_FAILED", "검색하지 못했습니다.", err)
		return
	}
	rows, err = s.Store.Pool.Query(r.Context(), `SELECT DISTINCT r.id AS review_id,r.review_number,e.id,e.original_filename,e.mime_type,e.created_at FROM evidences e JOIN submission_items si ON si.id=e.submission_item_id JOIN submissions sub ON sub.id=si.submission_id JOIN review_requests r ON r.id=sub.review_request_id WHERE e.deleted_at IS NULL AND `+itemWhere+` AND e.original_filename ILIKE $1 ORDER BY e.created_at DESC LIMIT 21`, args...)
	if err != nil {
		s.fault(w, r, "SEARCH_FAILED", "검색하지 못했습니다.", err)
		return
	}
	evidences, err := scanDynamic(rows, []string{"review_id", "review_number", "id", "original_filename", "mime_type", "created_at"})
	if err != nil {
		s.fault(w, r, "SEARCH_FAILED", "검색하지 못했습니다.", err)
		return
	}
	// Twenty was a silent cap: somebody searching for a review that ranks
	// twenty-first was shown a full-looking page without it. One row past the
	// cap is fetched so the screen can say there is more to find.
	reviews, moreReviews := trimSearch(reviews)
	items, moreItems := trimSearch(items)
	evidences, moreEvidences := trimSearch(evidences)
	jsonResponse(w, 200, map[string]any{"reviews": reviews, "items": items, "evidences": evidences,
		"has_more": map[string]bool{"reviews": moreReviews, "items": moreItems, "evidences": moreEvidences}})
}

// accessFilter is the list-shaped half of canAccessReview: what a person may
// see in a list has to be what they may open, or a queue offers work that
// answers "심의를 찾을 수 없습니다" and a list hides work they are expected to
// do. The two are kept in step by TestListsAndDetailAgreeOnWhatIsVisible.
// approverJudgedItSQL is true when the review's named approver is also its
// reviewer. That is not a signature anybody may give -- the approval step is
// there to be a second look -- so, exactly like an approver who has lost the
// role, they count as unable to act and the review becomes visible to the
// other approvers instead of waiting for a signature nobody may give. The
// one-person installation that allows self-review keeps its escape hatch.
//
// Only the two columns of the review itself are read here. The stricter rule
// -- anybody who recorded a verdict may not sign the result off -- is applied
// where the decision is made, because a visibility check that depended on the
// verdict table would turn an unreadable table into "심의를 찾을 수 없습니다"
// rather than an error.
const approverJudgedItSQL = `(NOT COALESCE((SELECT (value_json->>'allow_self_review')::bool FROM settings WHERE key='workflow'),false)
                AND review_requests.reviewer_id=review_requests.approver_id)`

func accessFilter(sess auth.Session, start int) (string, []any) {
	// The operator belongs here with the builder and the developer: the form
	// asks for all three, an item may be assigned to any of them, and only
	// these two could open what they were assigned.
	return fmt.Sprintf(`(review_requests.requester_id=$%[1]d OR review_requests.builder_id=$%[1]d OR review_requests.developer_id=$%[1]d OR review_requests.operator_id=$%[1]d OR review_requests.reviewer_id=$%[1]d OR review_requests.approver_id=$%[1]d
                OR EXISTS(SELECT 1 FROM review_participants rp WHERE rp.review_request_id=review_requests.id AND rp.user_id=$%[1]d)
                OR ($%[2]d::bool AND review_requests.status='APPROVAL_PENDING' AND (review_requests.approver_id IS NULL OR NOT `+stillHolds("review_requests.approver_id", "APPROVER")+` OR `+approverJudgedItSQL+`)))`, start, start+1),
		[]any{sess.User.ID, hasAnyRole(sess.User, "APPROVER")}
}

// scanDynamic is used for small administrative lists where a stable JSON object is more useful than repetitive structs.
func scanDynamic(rows interface {
	Next() bool
	Values() ([]any, error)
	Close()
	Err() error
}, names []string) ([]map[string]any, error) {
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			// Stopping here used to hand back the rows read so far as if they
			// were the whole answer: a list that is short and looks complete.
			// In an audit log or a register of outstanding work, that is worse
			// than an error.
			return nil, err
		}
		m := map[string]any{}
		for i, n := range names {
			if i < len(vals) {
				m[n] = vals[i]
			}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Server) notifications(w http.ResponseWriter, r *http.Request) {
	where := "recipient_id=$1"
	args := []any{session(r).User.ID}
	if r.URL.Query().Get("unread") == "1" {
		where += " AND read_at IS NULL"
	}
	if event := strings.TrimSpace(r.URL.Query().Get("event")); event != "" {
		args = append(args, event)
		where += " AND event_type=$" + intString(len(args))
	}
	limit, offset := parsePage(r)
	var total int64
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM notifications WHERE `+where, args...).Scan(&total)
	args = append(args, limit, offset)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,event_type,title,body,status,target_type,target_id,COALESCE(item_id,'') AS item_id,read_at,created_at FROM notifications WHERE `+where+
		` ORDER BY created_at DESC,id DESC LIMIT $`+intString(len(args)-1)+` OFFSET $`+intString(len(args)), args...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "알림을 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"id", "event_type", "title", "body", "status", "target_type", "target_id", "item_id", "read_at", "created_at"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "알림을 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset, "has_more": int64(offset+len(items)) < total})
}

// userDirectory backs every assignee selector. An installation that syncs a
// whole staff directory from its IdP has thousands of active accounts, so the
// list can be narrowed by name, account or department instead of being handed
// over whole.
func (s *Server) userDirectory(w http.ResponseWriter, r *http.Request) {
	where, args := "active", []any{}
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		args = append(args, "%"+q+"%")
		where += ` AND (display_name ILIKE $1 OR username ILIKE $1 OR department ILIKE $1)`
	}
	// A picker that offers people the action will refuse teaches nothing. The
	// caller says which role the name has to hold and gets only those.
	if role := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("role"))); role != "" {
		args = append(args, role)
		where += ` AND EXISTS(SELECT 1 FROM user_roles ur WHERE ur.user_id=users.id AND ur.role_code=$` + intString(len(args)) + `)`
	}
	var total int64
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM users users WHERE `+where, args...).Scan(&total); err != nil {
		s.fault(w, r, "QUERY_FAILED", "사용자 목록을 불러오지 못했습니다.", err)
		return
	}
	// The picker is a list somebody reads, and a directory of thousands is not
	// one. It is capped, and the caller is told when the cap hid people so it
	// can ask for a name instead of pretending the list is everybody.
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,username,display_name,department FROM users users WHERE `+where+` ORDER BY display_name LIMIT $`+intString(len(args)+1), append(args, directoryLimit)...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "사용자 목록을 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"id", "username", "display_name", "department"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "목록을 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "has_more": total > int64(len(items))})
}

// maintenanceAge reports how long ago the housekeeping sweep last finished.
// A sweep that has never run reads as a very large age rather than as zero,
// because zero is what a healthy service looks like.
func (s *Server) maintenanceAge(ctx context.Context) float64 {
	var lastRun *time.Time
	if err := s.Store.Pool.QueryRow(ctx, `SELECT last_run_at FROM maintenance_state WHERE id=1`).Scan(&lastRun); err != nil || lastRun == nil {
		return neverRanSeconds
	}
	return time.Since(*lastRun).Seconds()
}

// neverRanSeconds stands in for "no sweep has ever finished" so a scrape can
// alert on the same threshold either way.
const neverRanSeconds = 99999999

// apiKeyMaxDays is how long a machine credential may live. It is a security
// setting rather than a constant because an installation that automates
// against SecCheck from a locked-down runner may reasonably want longer keys
// than one where they are pasted into a laptop.
func (s *Server) apiKeyMaxDays(ctx context.Context) int {
	var cfg struct {
		APIKeyMaxDays *int `json:"api_key_max_days"`
	}
	if _, err := s.Store.Setting(ctx, "security", &cfg); err != nil || cfg.APIKeyMaxDays == nil {
		return defaultAPIKeyMaxDays
	}
	if *cfg.APIKeyMaxDays < 0 {
		return defaultAPIKeyMaxDays
	}
	return *cfg.APIKeyMaxDays
}

// defaultAPIKeyMaxDays applies to an installation that has never set the
// value, including one upgrading from a version that had no such limit.
const defaultAPIKeyMaxDays = 365

// maintenanceStaleAfter is when a missing housekeeping run stops being a late
// one and starts being a stopped one. The sweep runs hourly, so three missed
// turns is not a slow night.
const maintenanceStaleAfter = 3 * time.Hour

// directoryLimit bounds one picker's worth of names.
const directoryLimit = 200

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
		s.fault(w, r, "UPDATE_FAILED", "알림을 갱신하지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, map[string]any{"updated": tag.RowsAffected()})
}

func (s *Server) readNotification(w http.ResponseWriter, r *http.Request) {
	_, err := s.Store.Pool.Exec(r.Context(), `UPDATE notifications SET read_at=now(),status='READ' WHERE id=$1 AND recipient_id=$2`, r.PathValue("id"), session(r).User.ID)
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "알림을 갱신하지 못했습니다.", err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) systemInfo(w http.ResponseWriter, r *http.Request) {
	var users, reviews, templates, evidences, logs, evidenceBytes int64
	var dbSize string
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM review_requests),(SELECT count(*) FROM checklist_templates),(SELECT count(*) FROM evidences WHERE deleted_at IS NULL),(SELECT count(*) FROM application_logs),pg_size_pretty(pg_database_size(current_database())),(SELECT COALESCE(sum(size_bytes),0) FROM evidence_versions WHERE purged_at IS NULL)`).Scan(&users, &reviews, &templates, &evidences, &logs, &dbSize, &evidenceBytes)
	// PDF export needs a Korean font from the host image. Reporting it here
	// means an operator running a customised image finds out before a user
	// does.
	pdfFont := findKoreanFont()
	// The evidence volume is the other half of the storage picture: the
	// database size has always been here, the disk the files live on has not,
	// and it is the one that stops uploads when it fills.
	storage := s.vault().Space()
	// Who can actually act. With self-review refused, a role held by one
	// person is a workflow that stops the moment that person is the one
	// asking, and a role held by nobody is one that never runs at all.
	coverage := []map[string]any{}
	if rows, err := s.Store.Pool.Query(r.Context(), `SELECT r.code,
                count(*) FILTER (WHERE u.id IS NOT NULL AND u.active) AS active,
                count(u.id) AS total
                FROM (VALUES ('SYSTEM_ADMIN'),('SECURITY_REVIEWER'),('APPROVER'),('TEMPLATE_ADMIN'),('AUDITOR')) AS r(code)
                LEFT JOIN user_roles ur ON ur.role_code=r.code
                LEFT JOIN users u ON u.id=ur.user_id
                GROUP BY r.code ORDER BY r.code`); err == nil {
		if counted, scanErr := scanDynamic(rows, []string{"code", "active", "total"}); scanErr == nil {
			coverage = counted
		}
	}
	// Whether the volume still holds what the database says is state somebody
	// has to be able to look up, not only a notification that ages out. The
	// sweep records the answer per file; this is the summary of it.
	integrity := map[string]any{"checked": 0, "unchecked": 0, "failed": 0}
	var checkedCount, uncheckedCount, failedCount int64
	var oldest *time.Time
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FILTER (WHERE verified_at IS NOT NULL),count(*) FILTER (WHERE verified_at IS NULL),count(*) FILTER (WHERE verify_error<>''),min(verified_at)
                FROM evidences WHERE deleted_at IS NULL AND purged_at IS NULL`).Scan(&checkedCount, &uncheckedCount, &failedCount, &oldest); err == nil {
		integrity = map[string]any{"checked": checkedCount, "unchecked": uncheckedCount, "failed": failedCount, "oldest_checked_at": oldest}
	}
	broken := []map[string]any{}
	if rows, err := s.Store.Pool.Query(r.Context(), `SELECT e.original_filename,COALESCE(r.review_number,''),e.verify_error,e.verified_at
                FROM evidences e
                LEFT JOIN submission_items si ON si.id=e.submission_item_id
                LEFT JOIN submissions sub ON sub.id=si.submission_id
                LEFT JOIN review_requests r ON r.id=sub.review_request_id
                WHERE e.deleted_at IS NULL AND e.purged_at IS NULL AND e.verify_error<>''
                ORDER BY e.verified_at DESC LIMIT 10`); err == nil {
		if listed, scanErr := scanDynamic(rows, []string{"filename", "review_number", "reason", "checked_at"}); scanErr == nil {
			broken = listed
		}
	}
	integrity["failures"] = broken
	// Housekeeping runs in a goroutine with nothing watching it. Reminders,
	// evidence sampling, retention purges and the audit-chain check all stop
	// together if it dies, and nothing else on any screen changes -- so the
	// time of the last completed run is reported here and in /metrics.
	maintenanceState := map[string]any{"last_run_at": nil, "stale": true}
	var lastRun *time.Time
	var lastSummary []byte
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT last_run_at,last_summary FROM maintenance_state WHERE id=1`).Scan(&lastRun, &lastSummary); err == nil {
		var summary map[string]any
		_ = json.Unmarshal(lastSummary, &summary)
		maintenanceState = map[string]any{"last_run_at": lastRun, "stale": lastRun == nil || time.Since(*lastRun) > maintenanceStaleAfter, "last_summary": summary}
	}
	jsonResponse(w, 200, map[string]any{"maintenance": maintenanceState, "evidence_bytes": evidenceBytes, "evidence_integrity": integrity, "version": s.Version, "schema_version": s.Store.SchemaVersion(r.Context()), "go_version": runtime.Version(), "users": users, "reviews": reviews, "templates": templates, "evidences": evidences, "logs": logs, "database_size": dbSize, "pdf_font": pdfFont, "pdf_export_available": pdfFont != "", "storage": storage, "role_coverage": coverage, "now": time.Now()})
}

func (s *Server) ensureUserDataKey(ctx context.Context, userID string) error {
	return s.vault().EnsureUserKey(ctx, userID)
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,name,prefix,scopes,expires_at,last_used_at,revoked_at,created_at FROM api_keys WHERE user_id=$1 ORDER BY created_at DESC`, session(r).User.ID)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "API 키를 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"id", "name", "prefix", "scopes", "expires_at", "last_used_at", "revoked_at", "created_at"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "목록을 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, items)
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
	// A machine credential that never expires is a finding in its own right:
	// it outlives the integration it was issued for, the person who issued it
	// and usually the memory of what it was for. The installation says how
	// long one may live; 0 keeps the old behaviour of allowing an endless key.
	if limit := s.apiKeyMaxDays(r.Context()); limit > 0 {
		latest := time.Now().AddDate(0, 0, limit)
		if expires == nil {
			expires = &latest
		} else if expires.After(latest) {
			problem(w, 422, "API_KEY_LIFETIME", fmt.Sprintf("API 키는 최대 %d일까지만 유효하도록 설정되어 있습니다. 더 짧은 만료일을 지정하세요.", limit),
				map[string]any{"max_days": limit, "latest": latest.Format(time.RFC3339)})
			return
		}
	}
	raw, _ := cryptox.Token(32)
	token := "sck_" + raw
	h := sha256.Sum256([]byte(token))
	id := store.NewID()
	_, err := s.Store.Pool.Exec(r.Context(), `INSERT INTO api_keys(id,user_id,name,prefix,secret_hash,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, session(r).User.ID, name, token[:12], h[:], scopes, expires)
	if err != nil {
		s.fault(w, r, "CREATE_FAILED", "API 키를 만들지 못했습니다.", err)
		return
	}
	// Issuing a credential and replacing one are different events. Both went
	// into the record as a rotation, so an auditor could not tell a new key
	// from a replaced one without noticing that rotated_from was empty.
	event, before := "CREATE_API_KEY", map[string]any(nil)
	if rotatedFrom != "" {
		event, before = "ROTATE_API_KEY", map[string]any{"rotated_from": rotatedFrom}
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, event, "API_KEY", id, before, map[string]any{"name": name, "scopes": scopes}))
	jsonResponse(w, 201, map[string]any{"id": id, "name": name, "token": token, "prefix": token[:12], "scopes": scopes, "expires_at": expires, "warning": "이 키는 다시 표시되지 않습니다."})
}
func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, r.PathValue("id"), session(r).User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 404, "NOT_FOUND", "API 키를 찾을 수 없습니다.", nil)
		return
	}
	// Which credential was withdrawn is the whole question when access is
	// reviewed, and an identifier alone does not answer it.
	var name, prefix string
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT name,prefix FROM api_keys WHERE id=$1`, r.PathValue("id")).Scan(&name, &prefix)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "REVOKE_API_KEY", "API_KEY", r.PathValue("id"), map[string]any{"name": name, "prefix": prefix}, nil))
	w.WriteHeader(204)
}
func (s *Server) rotateDataKey(w http.ResponseWriter, r *http.Request) {
	uid := session(r).User.ID
	var version int
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT COALESCE(max(version),0)+1 FROM user_data_keys WHERE user_id=$1`, uid).Scan(&version)
	key, _ := cryptox.RandomBytes(32)
	encrypted, err := s.Box.Encrypt(key, []byte(fmt.Sprintf("user-key:%s:%d", uid, version)))
	if err != nil {
		s.fault(w, r, "ROTATE_FAILED", "암호화 키를 회전하지 못했습니다.", err)
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
		s.fault(w, r, "ROTATE_FAILED", "암호화 키를 회전하지 못했습니다.", err)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "ROTATE_ENCRYPTION_KEY", "USER_KEY", uid, nil, map[string]any{"version": version}))
	jsonResponse(w, 200, map[string]any{"version": version, "rotated_at": time.Now()})
}

func hashString(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func verifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
