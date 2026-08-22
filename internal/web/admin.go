package web

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/auth"
	"github.com/hkjang/SecCheck/internal/notify"
	"github.com/hkjang/SecCheck/internal/store"
)

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT u.id,u.username,u.display_name,u.email,u.department,u.auth_source,u.active,u.last_login_at,u.created_at,u.failed_login_count,CASE WHEN u.locked_until>now() THEN u.locked_until END,u.totp_enabled,COALESCE(array_agg(ur.role_code ORDER BY ur.role_code) FILTER(WHERE ur.role_code IS NOT NULL),'{}') FROM users u LEFT JOIN user_roles ur ON ur.user_id=u.id GROUP BY u.id ORDER BY u.display_name`)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "사용자를 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, scanDynamic(rows, []string{"id", "username", "display_name", "email", "department", "auth_source", "active", "last_login_at", "created_at", "failed_login_count", "locked_until", "totp_enabled", "roles"}))
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
	if strings.TrimSpace(in.Username) == "" || strings.TrimSpace(in.DisplayName) == "" || len(in.Password) < 12 {
		problem(w, 422, "VALIDATION_FAILED", "사용자명, 표시 이름 및 12자 이상의 비밀번호가 필요합니다.", nil)
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
		_, err = tx.Exec(r.Context(), `INSERT INTO users(id,username,display_name,email,department,password_hash) VALUES($1,$2,$3,$4,$5,$6)`, id, in.Username, in.DisplayName, in.Email, in.Department, hash)
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
	if !in.Active {
		_, _ = s.Store.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1`, id)
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CHANGE_PERMISSION", "USER", id, nil, in))
	w.WriteHeader(204)
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
	if _, err = s.Store.Pool.Exec(r.Context(), `UPDATE users SET password_hash=$2,failed_login_count=0,locked_until=NULL,updated_at=now() WHERE id=$1`, id, hash); err != nil {
		s.fault(w, r, "UPDATE_FAILED", "비밀번호를 재설정하지 못했습니다.", err)
		return
	}
	_, _ = s.Store.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1`, id)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "RESET_PASSWORD", "USER", id, nil, nil))
	w.WriteHeader(204)
}

func (s *Server) unlockUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Auth.Unlock(r.Context(), id); err != nil {
		problem(w, 404, "NOT_FOUND", "사용자를 찾을 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UNLOCK_USER", "USER", id, nil, nil))
	w.WriteHeader(204)
}

func (s *Server) listSettings(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT key,value_json,encrypted_value<>'',sensitive,updated_at FROM settings ORDER BY key`)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "설정을 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, scanDynamic(rows, []string{"key", "value", "secret_configured", "sensitive", "updated_at"}))
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
	jsonResponse(w, 200, map[string]any{"ok": true, "issuer": p.Issuer, "authorization_endpoint": p.AuthorizationEndpoint, "token_endpoint": p.TokenEndpoint, "userinfo_endpoint": p.UserinfoEndpoint})
}

var auditColumns = []string{"event_id", "timestamp", "user_id", "user_name", "source_ip", "session_id", "event_type", "target_type", "target_id", "before_value", "after_value", "request_id", "result", "previous_hash", "event_hash"}

// The CSV carries the Korean label as well, because the spreadsheet is read
// outside the console where no lookup is available.
var auditCSVColumns = append([]string{"event_label"}, auditColumns...)

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r)
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
	if from := strings.TrimSpace(query.Get("from")); from != "" {
		args = append(args, from)
		where += ` AND timestamp >= $` + intString(len(args)) + `::date`
	}
	if to := strings.TrimSpace(query.Get("to")); to != "" {
		args = append(args, to)
		where += ` AND timestamp < $` + intString(len(args)) + `::date + 1`
	}
	// One row past the cap tells us the export was cut short without a second
	// count query over a table that is only ever appended to.
	if query.Get("format") == "csv" {
		limit = exportRowCap + 1
	}
	args = append(args, limit)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT event_id,timestamp,user_id,user_name,source_ip,session_id,event_type,target_type,target_id,before_value,after_value,request_id,result,previous_hash,event_hash FROM audit_logs WHERE `+where+` ORDER BY timestamp DESC LIMIT $`+intString(len(args)), args...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "감사 로그를 불러오지 못했습니다.", err)
		return
	}
	records := scanDynamic(rows, auditColumns)
	for _, record := range records {
		if code, ok := record["event_type"].(string); ok {
			record["event_label"] = auditEventLabels[code]
		}
	}
	if query.Get("format") == "csv" {
		records, truncated := capExport(w, records)
		_ = s.Store.Audit(r.Context(), auditFrom(r, "EXPORT_AUDIT", "AUDIT_LOG", "", nil, map[string]any{"rows": len(records), "truncated": truncated}))
		writeCSV(w, "seccheck-audit", auditCSVColumns, records)
		return
	}
	jsonResponse(w, 200, map[string]any{"items": records, "events": auditEventCatalogue()})
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
func writeCSV(w http.ResponseWriter, name string, columns []string, records []map[string]any) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	_, _ = w.Write([]byte("\ufeff"))
	out := csv.NewWriter(w)
	defer out.Flush()
	_ = out.Write(columns)
	row := make([]string, len(columns))
	for _, record := range records {
		for i, column := range columns {
			row[i] = csvValue(record[column])
		}
		_ = out.Write(row)
	}
}

func csvValue(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case time.Time:
		return value.Format(time.RFC3339)
	case []byte:
		return string(value)
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Sprint(value)
		}
		return strings.Trim(string(encoded), `"`)
	}
}

// verifyAudit proves the hash chain. A full pass re-reads and re-hashes every
// event ever written, which grows without bound, so the last proved position
// is remembered and the routine check covers only what has been appended
// since. `?full=1` forces the complete pass.
func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	full := r.URL.Query().Get("full") == "1"
	var fromSequence int64
	previous := ""
	if !full {
		_ = s.Store.Pool.QueryRow(r.Context(), `SELECT verified_sequence,verified_hash FROM audit_chain_state WHERE id=1`).Scan(&fromSequence, &previous)
		if previous == "" {
			// Nothing has been proved yet, so an incremental run has no anchor.
			fromSequence = 0
		}
	}
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT event_id,previous_hash,canonical_payload,event_hash,chain_sequence FROM audit_logs WHERE chain_sequence>$1 ORDER BY chain_sequence`, fromSequence)
	if err != nil {
		s.fault(w, r, "VERIFY_FAILED", "감사로그를 검증하지 못했습니다.", err)
		return
	}
	defer rows.Close()
	checked := 0
	expectedSequence := fromSequence + 1
	for rows.Next() {
		var id, linked, payload, storedHash string
		var sequence int64
		if err = rows.Scan(&id, &linked, &payload, &storedHash, &sequence); err != nil {
			s.fault(w, r, "VERIFY_FAILED", "감사로그를 검증하지 못했습니다.", err)
			return
		}
		checked++
		if payload == "" || linked != previous || sequence != expectedSequence {
			s.reportChainBreak(r, id, sequence, "chain link or canonical payload mismatch")
			jsonResponse(w, 200, map[string]any{"valid": false, "checked": checked, "from_sequence": fromSequence, "failed_event_id": id, "reason": "chain link or canonical payload mismatch"})
			return
		}
		hash := sha256.Sum256([]byte(payload))
		if hex.EncodeToString(hash[:]) != storedHash {
			s.reportChainBreak(r, id, sequence, "event hash mismatch")
			jsonResponse(w, 200, map[string]any{"valid": false, "checked": checked, "from_sequence": fromSequence, "failed_event_id": id, "reason": "event hash mismatch"})
			return
		}
		previous = storedHash
		expectedSequence++
	}
	if err = rows.Err(); err != nil {
		s.fault(w, r, "VERIFY_FAILED", "감사로그를 검증하지 못했습니다.", err)
		return
	}
	var head string
	var sequence int64
	if err = s.Store.Pool.QueryRow(r.Context(), `SELECT head_hash,sequence FROM audit_chain_state WHERE id=1`).Scan(&head, &sequence); err != nil || head != previous || sequence != expectedSequence-1 {
		s.reportChainBreak(r, "", sequence, "chain head state mismatch")
		jsonResponse(w, 200, map[string]any{"valid": false, "checked": checked, "from_sequence": fromSequence, "reason": "chain head state mismatch"})
		return
	}
	// Record how far the chain is proved so the next routine check is cheap.
	_, _ = s.Store.Pool.Exec(r.Context(), `UPDATE audit_chain_state SET verified_sequence=$1,verified_hash=$2,verified_at=now() WHERE id=1`, sequence, head)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "VERIFY_AUDIT_CHAIN", "AUDIT_LOG", "", nil, map[string]any{"checked": checked, "from_sequence": fromSequence, "full": full, "head_sequence": sequence}))
	jsonResponse(w, 200, map[string]any{"valid": true, "checked": checked, "from_sequence": fromSequence, "total": sequence, "full": full, "head_hash": previous})
}

// reportChainBreak makes tampering loud: it is a server-log ERROR and an
// in-app notification to every system administrator, not just a red toast on
// whoever happened to press the button.
func (s *Server) reportChainBreak(r *http.Request, eventID string, sequence int64, reason string) {
	s.Store.Log(r.Context(), "ERROR", requestID(r), "audit", "audit chain verification failed", map[string]any{"event_id": eventID, "sequence": sequence, "reason": reason})
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT user_id FROM user_roles WHERE role_code='SYSTEM_ADMIN'`)
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
	for _, admin := range admins {
		_, _ = s.Store.Pool.Exec(r.Context(), `INSERT INTO notifications(id,recipient_id,event_type,title,body) VALUES($1,$2,'AUDIT_CHAIN_BROKEN',$3,$4)`,
			store.NewID(), admin, "감사로그 체인 검증 실패",
			fmt.Sprintf("감사로그 %d번 이벤트에서 무결성 검증에 실패했습니다 (%s). 데이터베이스 직접 변경 여부를 즉시 확인하세요.", sequence, reason))
	}
}

func (s *Server) listLogs(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r)
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
	args = append(args, limit)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,timestamp,level,request_id,component,message,fields FROM application_logs WHERE `+where+` ORDER BY timestamp DESC LIMIT $`+intString(len(args)), args...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "서버 로그를 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, scanDynamic(rows, []string{"id", "timestamp", "level", "request_id", "component", "message", "fields"}))
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
	limit := parseLimit(r)
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
	args = append(args, limit)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,type,status,attempts,available_at,locked_at,last_error,created_at,updated_at FROM jobs WHERE `+where+` ORDER BY updated_at DESC LIMIT $`+intString(len(args)), args...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "작업 큐를 불러오지 못했습니다.", err)
		return
	}
	items := scanDynamic(rows, []string{"id", "type", "status", "attempts", "available_at", "locked_at", "last_error", "created_at", "updated_at"})
	summary := map[string]any{}
	counts, err := s.Store.Pool.Query(r.Context(), `SELECT type,status,count(*) FROM jobs GROUP BY type,status`)
	if err == nil {
		summary["counts"] = scanDynamic(counts, []string{"type", "status", "count"})
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
	jsonResponse(w, 200, map[string]any{"items": items, "summary": summary})
}

// retryJob puts a failed job back in the queue. Evidence stuck in ERROR is
// returned to PENDING at the same time so the gate reopens once it clears.
func (s *Server) retryJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var jobType string
	var payload []byte
	err := s.Store.Pool.QueryRow(r.Context(), `UPDATE jobs SET status='PENDING',attempts=0,available_at=now(),locked_at=NULL,last_error='',updated_at=now() WHERE id=$1 AND status IN ('FAILED','PENDING') RETURNING type,payload`, id).Scan(&jobType, &payload)
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

// retryFailedJobs is the bulk form, for when an SMTP or clamd outage has
// filled the queue.
func (s *Server) retryFailedJobs(w http.ResponseWriter, r *http.Request) {
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE jobs SET status='PENDING',attempts=0,available_at=now(),locked_at=NULL,last_error='',updated_at=now() WHERE status='FAILED'`)
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "작업을 재시도하지 못했습니다.", err)
		return
	}
	_, _ = s.Store.Pool.Exec(r.Context(), `UPDATE evidences SET scan_status='PENDING' WHERE scan_status='ERROR' AND deleted_at IS NULL`)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "RETRY_JOB", "JOB", "all-failed", nil, map[string]any{"requeued": tag.RowsAffected()}))
	jsonResponse(w, 200, map[string]any{"requeued": tag.RowsAffected()})
}
