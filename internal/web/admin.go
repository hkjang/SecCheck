package web

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/auth"
	"github.com/hkjang/SecCheck/internal/notify"
	"github.com/hkjang/SecCheck/internal/scanner"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	// An installation that syncs a staff directory has thousands of accounts,
	// and this screen used to hand the browser every one of them with their
	// roles aggregated -- then filter in JavaScript, which also meant a filter
	// could only ever see what had already been downloaded.
	query := r.URL.Query()
	where, args := "TRUE", []any{}
	if term := strings.TrimSpace(query.Get("q")); term != "" {
		args = append(args, "%"+term+"%")
		where += fmt.Sprintf(" AND (u.display_name ILIKE $%[1]d OR u.username ILIKE $%[1]d OR u.email ILIKE $%[1]d OR u.department ILIKE $%[1]d)", len(args))
	}
	switch strings.ToUpper(strings.TrimSpace(query.Get("only"))) {
	case "LOCKED":
		where += " AND u.locked_until>now()"
	case "INACTIVE":
		where += " AND NOT u.active"
	case "OIDC":
		where += " AND u.auth_source='oidc'"
	case "LOCAL":
		where += " AND u.auth_source='local'"
	case "TEMPORARY":
		// The accounts whose password somebody else chose and nobody has
		// replaced yet. Until they do, the person who issued it holds working
		// credentials for that account, so this is a list an administrator
		// should be able to work down rather than remember.
		where += " AND u.must_change_password AND u.active"
	case "STALE":
		// The same question the account review asks: a working account with a
		// role that matters that nobody has signed into for the lock window.
		var cfg struct {
			InactiveAdminLockDays int `json:"inactive_admin_lock_days"`
		}
		_, _ = s.Store.Setting(r.Context(), "security", &cfg)
		if cfg.InactiveAdminLockDays <= 0 {
			cfg.InactiveAdminLockDays = 90
		}
		args = append(args, cfg.InactiveAdminLockDays)
		where += fmt.Sprintf(" AND u.active AND (u.last_login_at IS NULL OR u.last_login_at < now()-make_interval(days=>$%d))", len(args))
		where += " AND EXISTS(SELECT 1 FROM user_roles pr WHERE pr.user_id=u.id AND pr.role_code IN ('SYSTEM_ADMIN','TEMPLATE_ADMIN','SECURITY_REVIEWER','APPROVER'))"
	}
	var total int64
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM users u WHERE `+where, args...).Scan(&total); err != nil {
		s.fault(w, r, "QUERY_FAILED", "사용자를 불러오지 못했습니다.", err)
		return
	}
	limit, offset := parsePage(r)
	args = append(args, limit, offset)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT u.id,u.username,u.display_name,u.email,u.department,u.auth_source,u.active,u.last_login_at,u.created_at,u.failed_login_count,CASE WHEN u.locked_until>now() THEN u.locked_until END,u.totp_enabled,u.must_change_password,COALESCE(array_agg(ur.role_code ORDER BY ur.role_code) FILTER(WHERE ur.role_code IS NOT NULL),'{}') FROM users u LEFT JOIN user_roles ur ON ur.user_id=u.id WHERE `+where+` GROUP BY u.id ORDER BY u.display_name LIMIT $`+intString(len(args)-1)+` OFFSET $`+intString(len(args)), args...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "사용자를 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"id", "username", "display_name", "email", "department", "auth_source", "active", "last_login_at", "created_at", "failed_login_count", "locked_until", "totp_enabled", "must_change_password", "roles"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "목록을 불러오지 못했습니다.", err)
		return
	}
	var locked int64
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE locked_until>now()`).Scan(&locked); err != nil {
		s.fault(w, r, "QUERY_FAILED", "잠긴 계정 수를 확인하지 못했습니다.", err)
		return
	}
	// Counted over every account for the same reason as the locked ones: a
	// warning that only counts what is on the current page is not a warning.
	var temporary int64
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE must_change_password AND active`).Scan(&temporary); err != nil {
		s.fault(w, r, "QUERY_FAILED", "임시 비밀번호 계정 수를 확인하지 못했습니다.", err)
		return
	}
	// locked is counted over every account, not the page: the screen warns
	// about locked accounts and a warning that only counts what is on screen is
	// not a warning.
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "locked": locked, "temporary_passwords": temporary, "limit": limit, "offset": offset, "has_more": int64(offset+len(items)) < total})
}
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username    string   `json:"username"`
		DisplayName string   `json:"display_name"`
		Email       string   `json:"email"`
		Department  string   `json:"department"`
		Password    string   `json:"password"`
		Roles       []string `json:"roles"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Username) == "" || strings.TrimSpace(in.DisplayName) == "" {
		problem(w, 422, "VALIDATION_FAILED", "사용자명과 표시 이름이 필요합니다.", nil)
		return
	}
	// The service asks every other team whether they control weak passwords;
	// its own accounts accepted twelve of the same letter.
	if reason := auth.PasswordProblem(in.Password, in.Username); reason != "" {
		problem(w, 422, "WEAK_PASSWORD", reason, map[string]string{"password": reason})
		return
	}
	hash, err := auth.PasswordHash(in.Password)
	if err != nil {
		problem(w, 422, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	id := store.NewID()
	tx, err := s.Store.Pool.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO users(id,username,display_name,email,department,password_hash,must_change_password) VALUES($1,$2,$3,$4,$5,$6,true)`, id, in.Username, in.DisplayName, in.Email, in.Department, hash)
		for _, role := range in.Roles {
			if err != nil {
				break
			}
			_, err = tx.Exec(r.Context(), `INSERT INTO user_roles(user_id,role_code) VALUES($1,$2)`, id, role)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
	}
	if err != nil {
		problem(w, 409, "CREATE_FAILED", "사용자를 만들지 못했습니다. 사용자명과 역할을 확인하세요.", nil)
		return
	}
	_ = s.ensureUserDataKey(r.Context(), id)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CREATE_USER", "USER", id, nil, map[string]any{"username": in.Username, "roles": in.Roles}))
	jsonResponse(w, 201, map[string]string{"id": id})
}

func (s *Server) updateUserRoles(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Roles []string `json:"roles"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if id == session(r).User.ID && !contains(in.Roles, "SYSTEM_ADMIN") {
		problem(w, 422, "LAST_ADMIN_PROTECTION", "자신의 시스템 관리자 역할은 제거할 수 없습니다.", nil)
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM user_roles WHERE user_id=$1`, id)
		for _, role := range in.Roles {
			if err != nil {
				break
			}
			_, err = tx.Exec(r.Context(), `INSERT INTO user_roles(user_id,role_code) VALUES($1,$2)`, id, role)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
	}
	if err != nil {
		problem(w, 422, "UPDATE_FAILED", "역할을 저장하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CHANGE_PERMISSION", "USER", id, nil, map[string]any{"roles": in.Roles}))
	w.WriteHeader(204)
}

// openWorkOf counts what an account still owns that nobody else can finish:
// reviews it filed or is judging or approving that have not reached a final
// state, and outstanding follow-ups the register still chases it for.
// Deactivating an account releases its checklist items, but those roles stay
// on the row -- so an administrator closing an account was told how many items
// were freed and nothing at all about the reviews left without an owner.
func (s *Server) openWorkOf(ctx context.Context, userID string) (map[string]int, error) {
	out := map[string]int{}
	var requester, reviewer, approver, followUps int
	err := s.Store.Pool.QueryRow(ctx, `SELECT
                count(*) FILTER (WHERE r.requester_id=$1),
                count(*) FILTER (WHERE r.reviewer_id=$1),
                count(*) FILTER (WHERE r.approver_id=$1)
                FROM review_requests r
                WHERE r.status NOT IN ('APPROVED','CLOSED','CANCELLED','REJECTED')
                  AND (r.requester_id=$1 OR r.reviewer_id=$1 OR r.approver_id=$1)`, userID).
		Scan(&requester, &reviewer, &approver)
	if err != nil {
		return nil, err
	}
	// A follow-up outlives the review: it is chased after approval, and the
	// person it is chased from is the review's requester.
	if err = s.Store.Pool.QueryRow(ctx, `SELECT count(*) FROM review_results rr
                JOIN submission_items si ON si.id=rr.submission_item_id
                JOIN submissions sub ON sub.id=si.submission_id
                JOIN review_requests r ON r.id=sub.review_request_id
                WHERE r.requester_id=$1 AND btrim(rr.follow_up)<>'' AND rr.follow_up_done_at IS NULL`, userID).Scan(&followUps); err != nil {
		return nil, err
	}
	out["requester"], out["reviewer"], out["approver"], out["follow_ups"] = requester, reviewer, approver, followUps
	out["total"] = requester + reviewer + approver + followUps
	return out, nil
}

// userOpenWork answers the same question before the account is closed, so the
// administrator can hand the work over first rather than discover it later.
func (s *Server) userOpenWork(w http.ResponseWriter, r *http.Request) {
	work, err := s.openWorkOf(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "남은 업무를 확인하지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, work)
}

func (s *Server) setUserActive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Active bool `json:"active"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if id == session(r).User.ID && !in.Active {
		problem(w, 422, "SELF_LOCKOUT", "현재 로그인한 계정은 비활성화할 수 없습니다.", nil)
		return
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE users SET active=$2,updated_at=now() WHERE id=$1`, id, in.Active)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 404, "NOT_FOUND", "사용자를 찾을 수 없습니다.", nil)
		return
	}
	released := 0
	// What the account still owns is counted before it is closed, because a
	// deactivated reviewer no longer "holds" anything the queries can see.
	work := map[string]int{}
	if !in.Active {
		if counted, workErr := s.openWorkOf(r.Context(), id); workErr == nil {
			work = counted
		}
		if err = s.endSessions(r.Context(), id, ""); err != nil {
			s.fault(w, r, "SESSION_SWEEP_FAILED", "계정 상태는 바뀌었으나 로그인 세션을 종료하지 못했습니다. 다시 시도하세요.", err)
			return
		}
		// Checklist items stay assigned to a closed account otherwise: the row
		// carries a name the directory no longer returns, so the work reads as
		// owned by nobody in particular and nobody picks it up. Reviews the
		// account was reviewing already return to the queue on their own.
		var tag pgconn.CommandTag
		tag, err = s.Store.Pool.Exec(r.Context(), `UPDATE responses SET assigned_to=NULL,updated_at=now()
                WHERE assigned_to=$1 AND submission_item_id IN (
                  SELECT si.id FROM submission_items si
                  JOIN submissions sub ON sub.id=si.submission_id
                  JOIN review_requests rq ON rq.id=sub.review_request_id
                  WHERE rq.status NOT IN ('APPROVED','CLOSED','CANCELLED','REJECTED'))`, id)
		if err != nil {
			s.fault(w, r, "UPDATE_FAILED", "담당 항목을 정리하지 못했습니다.", err)
			return
		}
		released = int(tag.RowsAffected())
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CHANGE_PERMISSION", "USER", id, nil, map[string]any{"active": in.Active, "released_items": released, "open_work": work}))
	jsonResponse(w, 200, map[string]any{"active": in.Active, "released_items": released, "open_work": work})
}

// resetUserPassword gives administrators a recovery path for local accounts.
// Every session of the target user is dropped and the lockout counters are
// cleared so the temporary password can be used immediately.
func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	// A temporary password is a password: it is typed once by the person it
	// was handed to, and until they change it the account is only as safe as
	// this string.
	if reason := auth.PasswordProblem(in.Password, s.usernameOf(r.Context(), id)); reason != "" {
		problem(w, 422, "WEAK_PASSWORD", reason, map[string]string{"password": reason})
		return
	}
	hash, err := auth.PasswordHash(in.Password)
	if err != nil {
		problem(w, 422, "VALIDATION_FAILED", "임시 비밀번호는 12자 이상이어야 합니다.", nil)
		return
	}
	var source string
	if err = s.Store.Pool.QueryRow(r.Context(), `SELECT auth_source FROM users WHERE id=$1`, id).Scan(&source); err != nil {
		problem(w, 404, "NOT_FOUND", "사용자를 찾을 수 없습니다.", nil)
		return
	}
	if source != "local" {
		problem(w, 422, "EXTERNAL_ACCOUNT", "SSO 계정의 비밀번호는 사내 인증 서버에서 관리합니다.", nil)
		return
	}
	// The new password and the end of every session it replaces are one
	// change: an administrator resetting a compromised account is told the
	// sessions are gone, and a half-applied reset would leave the intruder
	// signed in behind a password the owner no longer knows.
	if err = s.inTx(r.Context(), func(tx pgx.Tx) error {
		if _, txErr := tx.Exec(r.Context(), `UPDATE users SET password_hash=$2,must_change_password=true,failed_login_count=0,locked_until=NULL,updated_at=now() WHERE id=$1`, id, hash); txErr != nil {
			return txErr
		}
		_, txErr := tx.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1`, id)
		return txErr
	}); err != nil {
		s.fault(w, r, "UPDATE_FAILED", "비밀번호를 재설정하지 못했습니다. 비밀번호는 그대로이고 세션도 유지됩니다.", err)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "RESET_PASSWORD", "USER", id, nil, map[string]any{"username": s.usernameOf(r.Context(), id)}))
	w.WriteHeader(204)
}

// usernameOf names the person an administrator acted on. The event already
// records who did it; without this the audit log says an account was reset or
// unlocked but leaves the reader to resolve an identifier to find out whose.
func (s *Server) usernameOf(ctx context.Context, id string) string {
	var username string
	_ = s.Store.Pool.QueryRow(ctx, `SELECT username FROM users WHERE id=$1`, id).Scan(&username)
	return username
}

func (s *Server) unlockUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Auth.Unlock(r.Context(), id); err != nil {
		problem(w, 404, "NOT_FOUND", "사용자를 찾을 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UNLOCK_USER", "USER", id, nil, map[string]any{"username": s.usernameOf(r.Context(), id)}))
	w.WriteHeader(204)
}

func (s *Server) listSettings(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT key,value_json,encrypted_value<>'',sensitive,updated_at FROM settings ORDER BY key`)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "설정을 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"key", "value", "secret_configured", "sensitive", "updated_at"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "목록을 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, items)
}

func (s *Server) updateSetting(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	allowed := map[string]bool{"general": true, "workflow": true, "upload": true, "oidc": true, "notification": true, "security": true}
	if !allowed[key] {
		problem(w, 404, "NOT_FOUND", "지원하지 않는 설정입니다.", nil)
		return
	}
	var raw map[string]any
	if !decodeJSON(w, r, &raw) {
		return
	}
	secret := ""
	if v, ok := raw["client_secret"].(string); ok {
		secret = v
		delete(raw, "client_secret")
	}
	if v, ok := raw["smtp_password"].(string); ok {
		secret = v
		delete(raw, "smtp_password")
	}
	if err := validateSetting(key, raw); err != "" {
		problem(w, 422, "VALIDATION_FAILED", err, nil)
		return
	}
	b, _ := json.Marshal(raw)
	encrypted := ""
	var err error
	if secret != "" {
		encrypted, err = s.Box.Encrypt([]byte(secret), []byte("setting:"+key))
		if err != nil {
			s.fault(w, r, "ENCRYPTION_FAILED", "비밀 설정을 암호화하지 못했습니다.", err)
			return
		}
	}
	if encrypted != "" {
		_, err = s.Store.Pool.Exec(r.Context(), `UPDATE settings SET value_json=$2,encrypted_value=$3,sensitive=true,updated_by=$4,updated_at=now() WHERE key=$1`, key, b, encrypted, session(r).User.ID)
	} else {
		_, err = s.Store.Pool.Exec(r.Context(), `UPDATE settings SET value_json=$2,updated_by=$3,updated_at=now() WHERE key=$1`, key, b, session(r).User.ID)
	}
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "설정을 저장하지 못했습니다.", err)
		return
	}
	safe := map[string]any{}
	for k, v := range raw {
		safe[k] = v
	}
	if secret != "" {
		safe["secret_configured"] = true
	}
	s.invalidateSettingCaches(key)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_SETTING", "SETTING", key, nil, safe))
	jsonResponse(w, 200, safe)
}

func validateSetting(key string, m map[string]any) string {
	switch key {
	case "general":
		if n := numericSetting(m["session_minutes"]); n < 15 || n > 10080 {
			return "세션 시간은 15~10080분이어야 합니다."
		}
		if n := numericSetting(m["retention_days"]); n < 30 || n > 36500 {
			return "보존 기간은 30~36500일이어야 합니다."
		}
		if tz := strings.TrimSpace(stringValue(m["timezone"])); tz != "" {
			if _, err := time.LoadLocation(tz); err != nil {
				return "표시 시간대는 IANA 이름이어야 합니다. 예: Asia/Seoul"
			}
		}
		if raw := strings.TrimSpace(stringValue(m["base_url"])); raw != "" {
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return "서비스 주소는 http(s)로 시작하는 완전한 URL이어야 합니다."
			}
		}
	case "workflow":
		if enabled, _ := m["approval_enabled"].(bool); enabled {
			// The approver itself is selected per review; no extra global secret is needed.
		}
	case "oidc":
		if enabled, _ := m["enabled"].(bool); enabled {
			if strings.TrimSpace(stringValue(m["issuer"])) == "" || strings.TrimSpace(stringValue(m["client_id"])) == "" || strings.TrimSpace(stringValue(m["redirect_url"])) == "" {
				return "OIDC 활성화 시 issuer, client_id, redirect_url이 필요합니다."
			}
			u := stringValue(m["issuer"])
			if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
				return "OIDC issuer는 유효한 HTTP(S) URL이어야 합니다."
			}
		}
		role := stringValue(m["default_role"])
		if role != "" && !contains([]string{"REQUESTER", "CONTRIBUTOR", "AUDITOR"}, role) {
			return "OIDC 기본 역할을 확인하세요."
		}
		if mappings, ok := m["role_mappings"].([]any); ok {
			seen := map[string]bool{}
			for _, raw := range mappings {
				entry, _ := raw.(map[string]any)
				group := strings.TrimSpace(stringValue(entry["group"]))
				mapped := stringValue(entry["role"])
				if group == "" {
					return "그룹 매핑의 그룹 이름을 입력하세요."
				}
				if !contains(auth.AssignableOIDCRoles(), mapped) {
					return "그룹 매핑에는 시스템 관리자를 제외한 역할만 지정할 수 있습니다."
				}
				key := strings.ToLower(group) + "\x00" + mapped
				if seen[key] {
					return "같은 그룹과 역할을 두 번 지정했습니다."
				}
				seen[key] = true
			}
		}
	case "upload":
		if n := numericSetting(m["max_size_mb"]); n < 1 || n > 1024 {
			return "업로드 제한은 1~1024MB여야 합니다."
		}
		if enabled, _ := m["clamav_enabled"].(bool); enabled && strings.TrimSpace(stringValue(m["clamav_address"])) == "" {
			return "ClamAV 활성화 시 서버 주소가 필요합니다."
		}
		if n := numericSetting(m["deleted_evidence_retention_days"]); n < 1 || n > 36500 {
			return "삭제 증적 보관 기간은 1~36500일이어야 합니다."
		}
	case "security":
		if n := numericSetting(m["rate_limit_per_minute"]); n < 30 || n > 10000 {
			return "분당 요청 제한은 30~10000이어야 합니다."
		}
		if n := numericSetting(m["inactive_admin_lock_days"]); n < 0 || n > 3650 {
			return "장기 미접속 잠금 기간은 0~3650일이어야 합니다."
		}
		if n := numericSetting(m["login_rate_limit_per_minute"]); n < 1 || n > 600 {
			return "분당 로그인 시도 제한은 1~600이어야 합니다."
		}
		if n := numericSetting(m["max_login_failures"]); n < 0 || n > 100 {
			return "계정 잠금 실패 횟수는 0~100이어야 합니다. 0은 잠금을 사용하지 않습니다."
		}
		if n := numericSetting(m["lockout_minutes"]); n < 1 || n > 1440 {
			return "계정 잠금 시간은 1~1440분이어야 합니다."
		}
		if _, present := m["api_key_max_days"]; present {
			if n := numericSetting(m["api_key_max_days"]); n < 0 || n > 3650 {
				return "API 키 최대 유효기간은 0~3650일이어야 합니다. 0은 제한을 두지 않습니다."
			}
		}
		if n := numericSetting(m["idle_timeout_minutes"]); n < 0 || n > 10080 {
			return "유휴 세션 만료는 0~10080분이어야 합니다. 0은 사용하지 않습니다."
		}
		if proxies, ok := m["trusted_proxies"].([]any); ok {
			for _, raw := range proxies {
				if _, err := parseProxyPrefix(stringValue(raw)); err != nil {
					return "신뢰 Reverse Proxy는 IP 주소 또는 CIDR이어야 합니다."
				}
			}
		}
		if origins, ok := m["cors_origins"].([]any); ok {
			for _, raw := range origins {
				u, err := url.Parse(strings.TrimSpace(stringValue(raw)))
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
					return "CORS 허용 원본은 경로가 없는 완전한 HTTP(S) origin이어야 합니다."
				}
			}
		}
	case "notification":
		if enabled, _ := m["email_enabled"].(bool); enabled {
			if strings.TrimSpace(stringValue(m["smtp_host"])) == "" || strings.TrimSpace(stringValue(m["from"])) == "" {
				return "이메일 알림 활성화 시 SMTP 호스트와 발신 주소가 필요합니다."
			}
			if n := numericSetting(m["smtp_port"]); n < 1 || n > 65535 {
				return "SMTP 포트 범위를 확인하세요."
			}
		}
		if n := numericSetting(m["digest_hour"]); n < 0 || n > 23 {
			return "요약 발송 시각은 0~23시여야 합니다."
		}
	}
	return ""
}
func stringValue(v any) string     { s, _ := v.(string); return s }
func numericSetting(v any) float64 { n, _ := v.(float64); return n }

func (s *Server) testOIDC(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Issuer string `json:"issuer"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Issuer == "" {
		cfg, err := s.Auth.OIDCConfig(r.Context())
		if err != nil {
			problem(w, 400, "OIDC_INVALID", err.Error(), nil)
			return
		}
		in.Issuer = cfg.Issuer
	}
	p, err := s.Auth.Discover(r.Context(), in.Issuer)
	if err != nil {
		problem(w, 422, "OIDC_DISCOVERY_FAILED", err.Error(), nil)
		return
	}
	// The SMTP test has always been recorded; this one causes the service to
	// reach an operator-supplied address just the same, which on an isolated
	// network is worth having in the record.
	_ = s.Store.Audit(r.Context(), auditFrom(r, "TEST_OIDC", "SETTING", "oidc", nil, map[string]any{"issuer": p.Issuer}))
	jsonResponse(w, 200, map[string]any{"ok": true, "issuer": p.Issuer, "authorization_endpoint": p.AuthorizationEndpoint, "token_endpoint": p.TokenEndpoint, "userinfo_endpoint": p.UserinfoEndpoint})
}

var auditColumns = []string{"event_id", "timestamp", "user_id", "user_name", "source_ip", "session_id", "event_type", "target_type", "target_id", "before_value", "after_value", "request_id", "result", "previous_hash", "event_hash"}

// The CSV carries the Korean label as well, because the spreadsheet is read
// outside the console where no lookup is available.
var auditCSVColumns = append([]string{"event_label"}, auditColumns...)

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	// The screen used to show the newest rows matching the filter and stop
	// there, with nothing saying more existed: an investigation that reached
	// the bottom of the page had no way to go further back except by guessing
	// at date filters. One row past the page tells the reader there is more
	// without counting a table that only grows.
	limit, offset := parsePage(r)
	query := r.URL.Query()
	where := "TRUE"
	args := []any{}
	// event_type is matched as a prefix so that typing "LOGIN" also finds
	// LOGIN_FAIL and LOGIN_LOCKED, which is what the filter box implies.
	if event := strings.TrimSpace(query.Get("event")); event != "" {
		args = append(args, event+"%")
		where += ` AND event_type ILIKE $` + intString(len(args))
	}
	if user := strings.TrimSpace(query.Get("user")); user != "" {
		args = append(args, "%"+user+"%")
		where += ` AND (user_name ILIKE $` + intString(len(args)) + ` OR source_ip ILIKE $` + intString(len(args)) + `)`
	}
	// "What happened to this Control?" was a question the log could answer and
	// the screen could not ask: the target is shown on every row but there was
	// no way to filter by it. Exact match, which is what the target index on
	// audit_logs is for.
	if target := strings.TrimSpace(query.Get("target")); target != "" {
		args = append(args, target)
		where += ` AND target_id=$` + intString(len(args))
	}
	if targetType := strings.TrimSpace(query.Get("target_type")); targetType != "" {
		args = append(args, strings.ToUpper(targetType))
		where += ` AND target_type=$` + intString(len(args))
	}
	// A chain-break alert names the event the verification stopped at, and an
	// administrator following that alert needs to land on that one event
	// rather than on a page of two hundred.
	if eventID := strings.TrimSpace(query.Get("event_id")); eventID != "" {
		args = append(args, eventID)
		where += ` AND event_id=$` + intString(len(args))
	}
	// "Show me what was refused" is the question an auditor opens this screen
	// with, and the column was there to read but not to filter by.
	if result := strings.ToUpper(strings.TrimSpace(query.Get("result"))); result != "" {
		args = append(args, result)
		where += ` AND result=$` + intString(len(args))
	}
	if from := strings.TrimSpace(query.Get("from")); from != "" {
		args = append(args, from)
		where += ` AND timestamp >= display_day_start($` + intString(len(args)) + `::date)`
	}
	if to := strings.TrimSpace(query.Get("to")); to != "" {
		args = append(args, to)
		where += ` AND timestamp < display_day_start($` + intString(len(args)) + `::date + 1)`
	}
	// One row past the cap tells us the export was cut short without a second
	// count query over a table that is only ever appended to.
	if query.Get("format") == "csv" {
		limit, offset = exportRowCap+1, 0
	}
	args = append(args, limit+1, offset)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT event_id,timestamp,user_id,user_name,source_ip,session_id,event_type,target_type,target_id,before_value,after_value,request_id,result,previous_hash,event_hash FROM audit_logs WHERE `+where+` ORDER BY timestamp DESC,chain_sequence DESC LIMIT $`+intString(len(args)-1)+` OFFSET $`+intString(len(args)), args...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "감사 로그를 불러오지 못했습니다.", err)
		return
	}
	records, err := scanDynamic(rows, auditColumns)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "감사 로그를 불러오지 못했습니다.", err)
		return
	}
	for _, record := range records {
		if code, ok := record["event_type"].(string); ok {
			record["event_label"] = auditEventLabels[code]
		}
	}
	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	if query.Get("format") == "csv" {
		records, truncated := capExport(w, records)
		_ = s.Store.Audit(r.Context(), auditFrom(r, "EXPORT_AUDIT", "AUDIT_LOG", "", nil, map[string]any{"rows": len(records), "truncated": truncated}))
		writeCSV(w, "seccheck-audit", s.Store.Location(r.Context()), auditCSVColumns, records)
		return
	}
	jsonResponse(w, 200, map[string]any{"items": records, "events": auditEventCatalogue(), "has_more": hasMore, "limit": limit, "offset": offset})
}

// exportRowCap bounds a single export so that one download cannot pull an
// installation's entire history into memory. Hitting it is reported rather
// than hidden: a compliance export that quietly stops at fifty thousand rows
// looks complete and is not.
const exportRowCap = 50000

func capExport(w http.ResponseWriter, records []map[string]any) ([]map[string]any, bool) {
	if len(records) <= exportRowCap {
		return records, false
	}
	w.Header().Set("X-Export-Truncated", intString(exportRowCap))
	return records[:exportRowCap], true
}

// writeCSV emits a UTF-8 BOM so that Excel on a Korean Windows desktop opens
// the download without mangling the text.
func writeCSV(w http.ResponseWriter, name string, zone *time.Location, columns []string, records []map[string]any) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	_, _ = w.Write([]byte("\ufeff"))
	out := csv.NewWriter(w)
	defer out.Flush()
	_ = out.Write(columns)
	row := make([]string, len(columns))
	for _, record := range records {
		for i, column := range columns {
			row[i] = csvValue(record[column], zone)
		}
		_ = out.Write(row)
	}
}

func csvValue(v any, zone *time.Location) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return csvText(value)
	case time.Time:
		// The screen shows the display timezone, so the download has to as
		// well: an auditor comparing the two must not have to add nine hours
		// in their head. The format is one a spreadsheet reads as a datetime.
		return value.In(zone).Format("2006-01-02 15:04:05")
	case []byte:
		return csvText(string(value))
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Sprint(value)
		}
		return strings.Trim(string(encoded), `"`)
	}
}

// Excel and LibreOffice read a cell that opens with =, +, -, @ or a control
// character as a formula, so text somebody else chose -- a review title, a
// display name, an audit payload -- runs on the desktop of whoever opens the
// export. The leading apostrophe marks the cell as text and is not displayed.
func csvText(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r', '\n':
		return "'" + v
	}
	return v
}

// verifyAudit proves the hash chain. A full pass re-reads and re-hashes every
// event ever written, which grows without bound, so the last proved position
// is remembered and the routine check covers only what has been appended
// since. `?full=1` forces the complete pass.
func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	full := r.URL.Query().Get("full") == "1"
	if full {
		// One at a time. The second caller is told to wait rather than
		// doubling the work and the connections it holds.
		if !s.verifying.CompareAndSwap(false, true) {
			problem(w, http.StatusConflict, "VERIFY_IN_PROGRESS", "전체 재검증이 이미 실행 중입니다. 완료된 뒤 다시 시도하세요.", nil)
			return
		}
		defer s.verifying.Store(false)
		// Re-hashing every event ever written takes minutes once an
		// installation has run for years, and the response deadline meant for
		// ordinary requests would cut the answer off exactly when the chain is
		// long enough to be worth proving.
		if rc := http.NewResponseController(w); rc != nil {
			_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Minute))
		}
	}
	var fromSequence int64
	previous := ""
	if !full {
		var err error
		if fromSequence, previous, err = s.Store.AuditCheckpoint(r.Context()); err != nil {
			s.fault(w, r, "VERIFY_FAILED", "감사로그를 검증하지 못했습니다.", err)
			return
		}
	}
	// The walk itself lives in the store, because the maintenance worker runs
	// the same check on its own schedule and two implementations of "is this
	// chain intact" would eventually disagree.
	result, err := s.Store.VerifyAuditChain(r.Context(), fromSequence, previous)
	if err != nil {
		s.fault(w, r, "VERIFY_FAILED", "감사로그를 검증하지 못했습니다.", err)
		return
	}
	if !result.Valid {
		s.reportChainBreak(r, result.FailedEventID, result.FailedSequence, result.Reason)
		out := map[string]any{"valid": false, "checked": result.Checked, "from_sequence": fromSequence, "reason": result.Reason}
		if result.FailedEventID != "" {
			out["failed_event_id"] = result.FailedEventID
		}
		jsonResponse(w, 200, out)
		return
	}
	// Record how far the chain is proved so the next routine check is cheap.
	_ = s.Store.MarkAuditChainVerified(r.Context(), result.HeadSequence, result.HeadHash)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "VERIFY_AUDIT_CHAIN", "AUDIT_LOG", "", nil, map[string]any{"checked": result.Checked, "from_sequence": fromSequence, "full": full, "head_sequence": result.HeadSequence}))
	jsonResponse(w, 200, map[string]any{"valid": true, "checked": result.Checked, "from_sequence": fromSequence, "total": result.HeadSequence, "full": full, "head_hash": result.HeadHash})
}

// reportChainBreak makes tampering loud: it is a server-log ERROR and an
// in-app notification to every system administrator, not just a red toast on
// whoever happened to press the button.
func (s *Server) reportChainBreak(r *http.Request, eventID string, sequence int64, reason string) {
	s.Store.Log(r.Context(), "ERROR", requestID(r), "audit", "audit chain verification failed", map[string]any{"event_id": eventID, "sequence": sequence, "reason": reason})
	// A closed account cannot act on it, and the alert is noise in a bell
	// nobody opens.
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT ur.user_id FROM user_roles ur JOIN users u ON u.id=ur.user_id WHERE ur.role_code='SYSTEM_ADMIN' AND u.active`)
	if err != nil {
		return
	}
	defer rows.Close()
	var admins []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			admins = append(admins, id)
		}
	}
	body := fmt.Sprintf("감사로그 %d번 이벤트에서 무결성 검증에 실패했습니다 (%s). 데이터베이스 직접 변경 여부를 즉시 확인하세요.", sequence, reason)
	for _, admin := range admins {
		// This used to insert the row by hand, which meant the one alert an
		// administrator most needs to receive away from the screen was the one
		// that never left the building -- the preference screen offers mail for
		// it all the same. Store.Notify is what keeps that promise, and it
		// carries the event the check stopped at so the bell links to it.
		if err := s.Store.Notify(r.Context(), admin, "AUDIT_CHAIN_BROKEN", "감사로그 체인 검증 실패", body, "AUDIT_LOG", eventID); err != nil {
			s.Store.Log(r.Context(), "ERROR", requestID(r), "audit", "could not notify an administrator of the chain break", map[string]any{"recipient": admin, "error": err.Error()})
		}
	}
}

// listAllAPIKeys answers "who holds machine credentials to this service".
// Keys were visible only to the person who issued them, so the one question an
// access review starts with -- which non-human credentials exist, who owns
// them and when they were last used -- could not be asked at all. Closing an
// account already stops its keys; this is for the ones on accounts that are
// still open.
func (s *Server) listAllAPIKeys(w http.ResponseWriter, r *http.Request) {
	where := "TRUE"
	if r.URL.Query().Get("only") == "ACTIVE" {
		where = "k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>now()) AND u.active"
	}
	limit, offset := parsePage(r)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT k.id,k.name,k.prefix,k.scopes,k.expires_at,k.last_used_at,k.revoked_at,k.created_at,
                u.id AS user_id,u.username,u.display_name,u.department,u.active AS owner_active,
                (k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>now()) AND u.active) AS usable
                FROM api_keys k JOIN users u ON u.id=k.user_id WHERE `+where+`
                ORDER BY (k.revoked_at IS NULL) DESC,k.last_used_at DESC NULLS LAST,k.created_at DESC LIMIT $1 OFFSET $2`, limit+1, offset)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "API 키를 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"id", "name", "prefix", "scopes", "expires_at", "last_used_at", "revoked_at", "created_at", "user_id", "username", "display_name", "department", "owner_active", "usable"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "목록을 불러오지 못했습니다.", err)
		return
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	var usable int64
	if err = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM api_keys k JOIN users u ON u.id=k.user_id WHERE k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>now()) AND u.active`).Scan(&usable); err != nil {
		s.fault(w, r, "QUERY_FAILED", "사용 가능한 키 수를 확인하지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "usable": usable, "has_more": hasMore, "limit": limit, "offset": offset})
}

// revokeAnyAPIKey withdraws somebody else's credential. The owner is told,
// because a key that stops working without explanation is an outage they will
// spend the afternoon debugging.
func (s *Server) revokeAnyAPIKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var owner, name, prefix string
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT user_id,name,prefix FROM api_keys WHERE id=$1 AND revoked_at IS NULL`, id).Scan(&owner, &name, &prefix); err != nil {
		problem(w, 404, "NOT_FOUND", "API 키를 찾을 수 없습니다.", nil)
		return
	}
	if _, err := s.Store.Pool.Exec(r.Context(), `UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id); err != nil {
		s.fault(w, r, "UPDATE_FAILED", "API 키를 폐기하지 못했습니다.", err)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "REVOKE_API_KEY", "API_KEY", id, map[string]any{"name": name, "prefix": prefix, "owner": owner}, nil))
	s.addTargetedNotification(r.Context(), owner, "API_KEY_REVOKED", "API 키 폐기",
		fmt.Sprintf("관리자가 API 키 %s(%s...)를 폐기했습니다. 이 키를 쓰는 연동은 즉시 중단됩니다.", name, prefix), "API_KEY", id)
	w.WriteHeader(204)
}

func (s *Server) listLogs(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePage(r)
	level := strings.TrimSpace(r.URL.Query().Get("level"))
	where := "TRUE"
	args := []any{}
	if level != "" {
		args = append(args, level)
		where = `level=$1`
	}
	if term := strings.TrimSpace(r.URL.Query().Get("q")); term != "" {
		args = append(args, "%"+term+"%")
		position := intString(len(args))
		where += ` AND (message ILIKE $` + position + ` OR component ILIKE $` + position + ` OR request_id ILIKE $` + position + ` OR fields::text ILIKE $` + position + `)`
	}
	args = append(args, limit+1, offset)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,timestamp,level,request_id,component,message,fields FROM application_logs WHERE `+where+` ORDER BY timestamp DESC,id DESC LIMIT $`+intString(len(args)-1)+` OFFSET $`+intString(len(args)), args...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "서버 로그를 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"id", "timestamp", "level", "request_id", "component", "message", "fields"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "목록을 불러오지 못했습니다.", err)
		return
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	jsonResponse(w, 200, map[string]any{"items": items, "has_more": hasMore, "limit": limit, "offset": offset})
}

func contains(items []string, v string) bool {
	for _, item := range items {
		if item == v {
			return true
		}
	}
	return false
}
func intString(v int) string {
	return strconv.Itoa(v)
}

// listJobs gives administrators the background queue that until now was only
// visible as two numbers on /metrics. A stuck e-mail or an evidence scan that
// never cleared has to be findable and retryable from the console.
// testSMTP sends one message with the saved settings so an administrator can
// confirm the path before the first real notification depends on it.
// testClamAV answers the question an administrator has at the moment they turn
// the scanner on: is anything listening there? The other two integrations have
// had this button from the start; this one was checked for a non-empty address
// and nothing else.
func (s *Server) testClamAV(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Address string `json:"address"`
	}
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	address := strings.TrimSpace(in.Address)
	if address == "" {
		var cfg struct {
			Address string `json:"clamav_address"`
		}
		_, _ = s.Store.Setting(r.Context(), "upload", &cfg)
		address = strings.TrimSpace(cfg.Address)
	}
	if address == "" {
		problem(w, 422, "VALIDATION_FAILED", "clamd 주소를 입력하거나 업로드 설정에 저장하세요.", nil)
		return
	}
	reply, err := scanner.Ping(address, 5*time.Second)
	if err != nil {
		_ = s.Store.Audit(r.Context(), auditFrom(r, "TEST_CLAMAV", "SETTING", "upload", nil, map[string]any{"address": address, "error": err.Error()}))
		problem(w, 502, "CLAMAV_FAILED", "clamd에 연결하지 못했습니다: "+err.Error(), nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "TEST_CLAMAV", "SETTING", "upload", nil, map[string]any{"address": address}))
	jsonResponse(w, 200, map[string]any{"address": address, "reply": reply})
}

func (s *Server) testSMTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Recipient string `json:"recipient"`
	}
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	recipient := strings.TrimSpace(in.Recipient)
	if recipient == "" {
		recipient = session(r).User.Email
	}
	if recipient == "" {
		problem(w, 422, "VALIDATION_FAILED", "받는 주소를 입력하거나 프로필에 이메일을 등록하세요.", nil)
		return
	}
	if err := notify.New(s.Store, s.Box).SendTest(r.Context(), recipient); err != nil {
		_ = s.Store.Audit(r.Context(), auditFrom(r, "TEST_SMTP", "SETTING", "notification", nil, map[string]any{"recipient": recipient, "error": err.Error()}))
		problem(w, 502, "SMTP_FAILED", "테스트 메일을 보내지 못했습니다: "+err.Error(), nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "TEST_SMTP", "SETTING", "notification", nil, map[string]any{"recipient": recipient}))
	jsonResponse(w, 200, map[string]any{"sent_to": recipient})
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePage(r)
	where := "TRUE"
	args := []any{}
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		args = append(args, status)
		where += ` AND status=$` + intString(len(args))
	}
	if jobType := strings.TrimSpace(r.URL.Query().Get("type")); jobType != "" {
		args = append(args, jobType)
		where += ` AND type=$` + intString(len(args))
	}
	args = append(args, limit+1, offset)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,type,status,attempts,available_at,locked_at,last_error,created_at,updated_at FROM jobs WHERE `+where+` ORDER BY updated_at DESC,id DESC LIMIT $`+intString(len(args)-1)+` OFFSET $`+intString(len(args)), args...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "작업 큐를 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"id", "type", "status", "attempts", "available_at", "locked_at", "last_error", "created_at", "updated_at"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "작업 큐를 불러오지 못했습니다.", err)
		return
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	summary := map[string]any{}
	counts, err := s.Store.Pool.Query(r.Context(), `SELECT type,status,count(*) FROM jobs GROUP BY type,status`)
	if err == nil {
		// A summary that cannot be read is left out rather than reported half
		// done; the list above it is the answer that matters here.
		if grouped, groupErr := scanDynamic(counts, []string{"type", "status", "count"}); groupErr == nil {
			summary["counts"] = grouped
		}
	}
	var pendingScans int64
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM evidences WHERE scan_status IN ('PENDING','ERROR') AND deleted_at IS NULL`).Scan(&pendingScans)
	summary["evidence_awaiting_scan"] = pendingScans
	// Workers poll every five seconds, so a job that has been due for minutes
	// means nothing is draining the queue -- the surest sign a worker died.
	// Without this an admin only sees PENDING rows that look perfectly normal.
	var oldestDue float64
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT coalesce(extract(epoch FROM now()-min(available_at)),0) FROM jobs WHERE status='PENDING' AND available_at<=now()`).Scan(&oldestDue)
	summary["oldest_pending_seconds"] = int64(oldestDue)
	jsonResponse(w, 200, map[string]any{"items": items, "summary": summary, "has_more": hasMore, "limit": limit, "offset": offset})
}

// retryJob puts a failed job back in the queue. Evidence stuck in ERROR is
// returned to PENDING at the same time so the gate reopens once it clears.
// A job still marked RUNNING long after its worker stopped counts as failed
// here: the hourly sweep frees it anyway, and an administrator looking at a
// blocked upload should not have to wait for that.
func (s *Server) retryJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var jobType string
	var payload []byte
	err := s.Store.Pool.QueryRow(r.Context(), `UPDATE jobs SET status='PENDING',attempts=0,available_at=now(),locked_at=NULL,last_error='',updated_at=now() WHERE id=$1 AND (status IN ('FAILED','PENDING') OR (status='RUNNING' AND locked_at<now()-interval '15 minutes')) RETURNING type,payload`, id).Scan(&jobType, &payload)
	if err != nil {
		problem(w, 404, "NOT_FOUND", "재시도할 작업을 찾을 수 없습니다.", nil)
		return
	}
	if jobType == "SCAN_EVIDENCE" {
		var job struct {
			EvidenceID string `json:"evidence_id"`
		}
		if json.Unmarshal(payload, &job) == nil && job.EvidenceID != "" {
			_, _ = s.Store.Pool.Exec(r.Context(), `UPDATE evidences SET scan_status='PENDING' WHERE id=$1 AND scan_status='ERROR'`, job.EvidenceID)
		}
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "RETRY_JOB", "JOB", id, nil, map[string]any{"type": jobType}))
	w.WriteHeader(204)
}

// requeueLostScans gives a scan job back to evidence that is waiting for one
// and has none. The same repair runs hourly in the maintenance sweep; it is
// done here as well because an administrator pressing 재시도 is asking for the
// queue to be put right now, not within the hour.
func (s *Server) requeueLostScans(ctx context.Context) int64 {
	tag, err := s.Store.Pool.Exec(ctx, `INSERT INTO jobs(id,type,payload)
                SELECT gen_random_uuid()::text,'SCAN_EVIDENCE',jsonb_build_object('evidence_id',e.id)
                FROM evidences e
                WHERE e.deleted_at IS NULL AND e.scan_status IN ('PENDING','ERROR')
                  AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.type='SCAN_EVIDENCE'
                        AND j.status IN ('PENDING','RUNNING') AND j.payload->>'evidence_id'=e.id)
                LIMIT 500`)
	if err != nil {
		s.Store.Log(ctx, "ERROR", "", "admin", "검사 대기 증적의 작업을 다시 넣지 못했습니다.", map[string]any{"error": err.Error()})
		return 0
	}
	return tag.RowsAffected()
}

// retryFailedJobs is the bulk form, for when an SMTP or clamd outage has
// filled the queue.
func (s *Server) retryFailedJobs(w http.ResponseWriter, r *http.Request) {
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE jobs SET status='PENDING',attempts=0,available_at=now(),locked_at=NULL,last_error='',updated_at=now() WHERE status='FAILED'`)
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "작업을 재시도하지 못했습니다.", err)
		return
	}
	_, _ = s.Store.Pool.Exec(r.Context(), `UPDATE evidences SET scan_status='PENDING' WHERE scan_status='ERROR' AND deleted_at IS NULL`)
	// Marking the evidence as waiting is only half of it. If the job that was
	// going to scan it has since been cleared out of the queue -- a failed job
	// is deleted after ninety days -- the file waits for ever and the review
	// it belongs to can never be submitted, so anything without a job gets one.
	requeued := s.requeueLostScans(r.Context())
	_ = s.Store.Audit(r.Context(), auditFrom(r, "RETRY_JOB", "JOB", "all-failed", nil, map[string]any{"requeued": tag.RowsAffected(), "rescheduled_scans": requeued}))
	jsonResponse(w, 200, map[string]any{"requeued": tag.RowsAffected(), "rescheduled_scans": requeued})
}

// handoverUserWork moves everything a departing account still holds to another
// person in one go. The open-work summary already told the administrator what
// was in the way before closing an account -- twelve reviews, four
// follow-ups -- and then left them to open all twelve and hand each one over
// by itself. The rules are the ones each individual handover applies, checked
// per review: a review whose new owner would end up judging their own work is
// left where it is and named, rather than moved into a state the workflow
// refuses.
func (s *Server) handoverUserWork(w http.ResponseWriter, r *http.Request) {
	from := r.PathValue("id")
	var in struct {
		ToUserID string `json:"to_user_id"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	to := strings.TrimSpace(in.ToUserID)
	if to == "" {
		problem(w, 422, "VALIDATION_FAILED", "넘겨받을 사람을 선택하세요.", map[string]string{"to_user_id": "필수 입력 항목입니다."})
		return
	}
	if to == from {
		problem(w, 422, "VALIDATION_FAILED", "같은 계정으로는 인계할 수 없습니다.", map[string]string{"to_user_id": "본인입니다."})
		return
	}
	var active bool
	var name string
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT active,display_name FROM users WHERE id=$1`, to).Scan(&active, &name); err != nil {
		problem(w, 404, "NOT_FOUND", "인계 대상 계정을 찾을 수 없습니다.", nil)
		return
	}
	if !active {
		problem(w, 422, "VALIDATION_FAILED", "비활성 계정에는 인계할 수 없습니다.", map[string]string{"to_user_id": "비활성 계정입니다."})
		return
	}
	roles, err := s.Store.UserRoles(r.Context(), to)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "인계 대상 권한을 확인하지 못했습니다.", err)
		return
	}
	var workflow struct {
		AllowSelfReview bool `json:"allow_self_review"`
	}
	_, _ = s.Store.Setting(r.Context(), "workflow", &workflow)

	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,review_number,status,requester_id,COALESCE(reviewer_id,''),COALESCE(approver_id,'')
                FROM review_requests
                WHERE status NOT IN ('APPROVED','CLOSED','CANCELLED','REJECTED')
                  AND (requester_id=$1 OR reviewer_id=$1 OR approver_id=$1)
                ORDER BY review_number`, from)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "인계할 심의를 불러오지 못했습니다.", err)
		return
	}
	type held struct{ id, number, status, requester, reviewer, approver string }
	var open []held
	for rows.Next() {
		var item held
		if rows.Scan(&item.id, &item.number, &item.status, &item.requester, &item.reviewer, &item.approver) == nil {
			open = append(open, item)
		}
	}
	rows.Close()

	moved := map[string]int{"requester": 0, "reviewer": 0, "approver": 0, "items": 0, "change_requests": 0}
	skipped := []map[string]string{}
	refuse := func(number, role, reason string) {
		skipped = append(skipped, map[string]string{"review_number": number, "role": role, "reason": reason})
	}
	for _, item := range open {
		// Each column is decided on its own: one review can hand over its
		// requester and keep its reviewer, which is what happens when the
		// departing person held both and the new owner may only hold one.
		if item.requester == from {
			switch {
			case !slices.Contains(roles, "REQUESTER"):
				refuse(item.number, "requester", "요청자 권한이 없습니다.")
			case !workflow.AllowSelfReview && (to == item.reviewer || to == item.approver):
				refuse(item.number, "requester", "이 심의의 검토자 또는 승인자입니다.")
			default:
				if s.moveReviewOwner(r, item.id, "requester_id", from, to, "TRANSFER_REQUESTER") {
					moved["requester"]++
				} else {
					refuse(item.number, "requester", "변경하지 못했습니다.")
				}
			}
		}
		if item.reviewer == from {
			switch {
			case !slices.Contains(roles, "SECURITY_REVIEWER"):
				refuse(item.number, "reviewer", "보안 검토 권한이 없습니다.")
			case !workflow.AllowSelfReview && to == item.requester:
				refuse(item.number, "reviewer", "이 심의의 요청자입니다.")
			default:
				if s.moveReviewOwner(r, item.id, "reviewer_id", from, to, "REASSIGN_REVIEWER") {
					moved["reviewer"]++
				} else {
					refuse(item.number, "reviewer", "변경하지 못했습니다.")
				}
			}
		}
		if item.approver == from {
			switch {
			case !slices.Contains(roles, "APPROVER"):
				refuse(item.number, "approver", "승인 권한이 없습니다.")
			case !workflow.AllowSelfReview && to == item.requester:
				refuse(item.number, "approver", "이 심의의 요청자입니다.")
			default:
				if s.moveReviewOwner(r, item.id, "approver_id", from, to, "REASSIGN_APPROVER") {
					moved["approver"]++
				} else {
					refuse(item.number, "approver", "변경하지 못했습니다.")
				}
			}
		}
	}

	// Item assignments and corrections follow only into reviews the new owner
	// can actually open, which is the same rule the assignment screens apply.
	// Anything else would put their name on work they cannot reach.
	moved["items"] = s.moveAssignments(r, `UPDATE responses SET assigned_to=$2,updated_at=now() WHERE assigned_to=$1 AND submission_item_id IN (
                SELECT si.id FROM submission_items si JOIN submissions sub ON sub.id=si.submission_id
                WHERE sub.review_request_id = ANY($3))`, from, to, s.reachableReviews(r, to, from))
	moved["change_requests"] = s.moveAssignments(r, `UPDATE change_requests SET assignee_id=$2,updated_at=now() WHERE assignee_id=$1 AND status<>'VERIFIED' AND review_request_id = ANY($3)`, from, to, s.reachableReviews(r, to, from))

	total := 0
	for _, n := range moved {
		total += n
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "HANDOVER_WORK", "USER", from, map[string]any{"user_id": from}, map[string]any{"to_user_id": to, "moved": moved, "skipped": skipped}))
	if total > 0 {
		// One notice for one handover: a person who has just inherited a
		// dozen reviews does not need a dozen mails to find that out.
		s.addTargetedNotification(r.Context(), to, "REVIEW_TRANSFERRED", "업무 인계",
			fmt.Sprintf("담당자 변경으로 심의 %d건(요청 %d · 검토 %d · 승인 %d)과 항목 %d건, 보완 요청 %d건을 넘겨받았습니다.",
				moved["requester"]+moved["reviewer"]+moved["approver"], moved["requester"], moved["reviewer"], moved["approver"], moved["items"], moved["change_requests"]),
			"USER", to)
	}
	jsonResponse(w, 200, map[string]any{"moved": moved, "skipped": skipped, "total": total})
}

// moveReviewOwner swaps one owner column and records it in that review's own
// history, so the change is visible where the review is read rather than only
// in the administrative log.
func (s *Server) moveReviewOwner(r *http.Request, reviewID, column, from, to, event string) bool {
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE review_requests SET `+column+`=$2,updated_at=now() WHERE id=$1 AND `+column+`=$3`, reviewID, to, from)
	if err != nil || tag.RowsAffected() == 0 {
		return false
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, event, "REVIEW_REQUEST", reviewID, map[string]string{column: from}, map[string]string{column: to}))
	return true
}

// reachableReviews lists the open reviews the new owner can open, which is
// where their name may appear on an item.
func (s *Server) reachableReviews(r *http.Request, to, from string) []string {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT r.id FROM review_requests r
                WHERE r.status NOT IN ('APPROVED','CLOSED','CANCELLED','REJECTED')
                  AND (r.requester_id=$1 OR r.builder_id=$1 OR r.developer_id=$1 OR r.operator_id=$1 OR r.reviewer_id=$1 OR r.approver_id=$1
                       OR EXISTS(SELECT 1 FROM review_participants rp WHERE rp.review_request_id=r.id AND rp.user_id=$1 AND rp.participant_role<>'VIEWER'))
                  AND (EXISTS(SELECT 1 FROM change_requests c WHERE c.review_request_id=r.id AND c.assignee_id=$2)
                       OR EXISTS(SELECT 1 FROM submission_items si JOIN submissions sub ON sub.id=si.submission_id JOIN responses resp ON resp.submission_item_id=si.id
                                 WHERE sub.review_request_id=r.id AND resp.assigned_to=$2))`, to, from)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out = append(out, id)
		}
	}
	return out
}

func (s *Server) moveAssignments(r *http.Request, query, from, to string, reviews []string) int {
	if len(reviews) == 0 {
		return 0
	}
	tag, err := s.Store.Pool.Exec(r.Context(), query, from, to, reviews)
	if err != nil {
		s.Store.Log(r.Context(), "ERROR", requestID(r), "admin", "인계 대상 배정을 옮기지 못했습니다.", map[string]any{"error": err.Error()})
		return 0
	}
	return int(tag.RowsAffected())
}
