package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/hkjang/SecCheck/internal/auth"
	"github.com/hkjang/SecCheck/internal/store"
)

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT u.id,u.username,u.display_name,u.email,u.department,u.auth_source,u.active,u.last_login_at,u.created_at,COALESCE(array_agg(ur.role_code ORDER BY ur.role_code) FILTER(WHERE ur.role_code IS NOT NULL),'{}') FROM users u LEFT JOIN user_roles ur ON ur.user_id=u.id GROUP BY u.id ORDER BY u.display_name`)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "사용자를 불러오지 못했습니다.", nil)
		return
	}
	jsonResponse(w, 200, scanDynamic(rows, []string{"id", "username", "display_name", "email", "department", "auth_source", "active", "last_login_at", "created_at", "roles"}))
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

func (s *Server) listSettings(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT key,value_json,encrypted_value<>'',sensitive,updated_at FROM settings ORDER BY key`)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "설정을 불러오지 못했습니다.", nil)
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
			problem(w, 500, "ENCRYPTION_FAILED", "비밀 설정을 암호화하지 못했습니다.", nil)
			return
		}
	}
	if encrypted != "" {
		_, err = s.Store.Pool.Exec(r.Context(), `UPDATE settings SET value_json=$2,encrypted_value=$3,sensitive=true,updated_by=$4,updated_at=now() WHERE key=$1`, key, b, encrypted, session(r).User.ID)
	} else {
		_, err = s.Store.Pool.Exec(r.Context(), `UPDATE settings SET value_json=$2,updated_by=$3,updated_at=now() WHERE key=$1`, key, b, session(r).User.ID)
	}
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "설정을 저장하지 못했습니다.", nil)
		return
	}
	safe := map[string]any{}
	for k, v := range raw {
		safe[k] = v
	}
	if secret != "" {
		safe["secret_configured"] = true
	}
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
	case "upload":
		if n := numericSetting(m["max_size_mb"]); n < 1 || n > 1024 {
			return "업로드 제한은 1~1024MB여야 합니다."
		}
		if enabled, _ := m["clamav_enabled"].(bool); enabled && strings.TrimSpace(stringValue(m["clamav_address"])) == "" {
			return "ClamAV 활성화 시 서버 주소가 필요합니다."
		}
	case "security":
		if n := numericSetting(m["rate_limit_per_minute"]); n < 30 || n > 10000 {
			return "분당 요청 제한은 30~10000이어야 합니다."
		}
		if n := numericSetting(m["inactive_admin_lock_days"]); n < 0 || n > 3650 {
			return "장기 미접속 잠금 기간은 0~3650일이어야 합니다."
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

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r)
	event := strings.TrimSpace(r.URL.Query().Get("event"))
	user := strings.TrimSpace(r.URL.Query().Get("user"))
	where := "TRUE"
	args := []any{}
	if event != "" {
		args = append(args, event)
		where += ` AND event_type=$1`
	}
	if user != "" {
		args = append(args, "%"+user+"%")
		where += ` AND user_name ILIKE $` + intString(len(args))
	}
	args = append(args, limit)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT event_id,timestamp,user_id,user_name,source_ip,session_id,event_type,target_type,target_id,before_value,after_value,request_id,result,previous_hash,event_hash FROM audit_logs WHERE `+where+` ORDER BY timestamp DESC LIMIT $`+intString(len(args)), args...)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "감사 로그를 불러오지 못했습니다.", nil)
		return
	}
	jsonResponse(w, 200, scanDynamic(rows, []string{"event_id", "timestamp", "user_id", "user_name", "source_ip", "session_id", "event_type", "target_type", "target_id", "before_value", "after_value", "request_id", "result", "previous_hash", "event_hash"}))
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT event_id,previous_hash,canonical_payload,event_hash,chain_sequence FROM audit_logs ORDER BY chain_sequence`)
	if err != nil {
		problem(w, 500, "VERIFY_FAILED", "감사로그를 검증하지 못했습니다.", nil)
		return
	}
	defer rows.Close()
	previous := ""
	count := 0
	var expectedSequence int64 = 1
	for rows.Next() {
		var id, linked, payload, storedHash string
		var sequence int64
		if err = rows.Scan(&id, &linked, &payload, &storedHash, &sequence); err != nil {
			problem(w, 500, "VERIFY_FAILED", "감사로그를 검증하지 못했습니다.", nil)
			return
		}
		count++
		if payload == "" || linked != previous || sequence != expectedSequence {
			jsonResponse(w, 200, map[string]any{"valid": false, "checked": count, "failed_event_id": id, "reason": "chain link or canonical payload mismatch"})
			return
		}
		hash := sha256.Sum256([]byte(payload))
		if hex.EncodeToString(hash[:]) != storedHash {
			jsonResponse(w, 200, map[string]any{"valid": false, "checked": count, "failed_event_id": id, "reason": "event hash mismatch"})
			return
		}
		previous = storedHash
		expectedSequence++
	}
	var head string
	var sequence int64
	if err = s.Store.Pool.QueryRow(r.Context(), `SELECT head_hash,sequence FROM audit_chain_state WHERE id=1`).Scan(&head, &sequence); err != nil || head != previous || sequence != int64(count) {
		jsonResponse(w, 200, map[string]any{"valid": false, "checked": count, "reason": "chain head state mismatch"})
		return
	}
	jsonResponse(w, 200, map[string]any{"valid": true, "checked": count, "head_hash": previous})
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
	args = append(args, limit)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,timestamp,level,request_id,component,message,fields FROM application_logs WHERE `+where+` ORDER BY timestamp DESC LIMIT $`+intString(len(args)), args...)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "서버 로그를 불러오지 못했습니다.", nil)
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
