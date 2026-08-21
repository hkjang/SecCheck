package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
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

type Server struct {
	Options
	blobs        *vault.Vault
	mux          *http.ServeMux
	limiter      *rateLimiter
	loginLimiter *rateLimiter
	securityMu   sync.Mutex
	securityAt   time.Time
	securityConf runtimeSecurity
}

type runtimeSecurity struct {
	CORSOrigins        []string `json:"cors_origins"`
	RateLimitPerMinute int      `json:"rate_limit_per_minute"`
	TrustedProxies     []string `json:"trusted_proxies"`

	trusted []netip.Prefix
}

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
	s.mux.HandleFunc("GET /health", s.health)
	s.mux.HandleFunc("GET /ready", s.ready)
	s.mux.HandleFunc("GET /metrics", s.metrics)
	s.mux.HandleFunc("GET /api/v1/public/config", s.publicConfig)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.login)
	s.mux.HandleFunc("GET /api/v1/auth/oidc/start", s.oidcStart)
	s.mux.HandleFunc("GET /api/v1/auth/oidc/callback", s.oidcCallback)

	// Authenticated user, dashboard, review lifecycle, evidence, exports and search.
	s.mux.Handle("POST /api/v1/auth/logout", s.require(nil, http.HandlerFunc(s.logout)))
	s.mux.Handle("GET /api/v1/me", s.require(nil, http.HandlerFunc(s.me)))
	s.mux.Handle("PATCH /api/v1/me", s.require(nil, http.HandlerFunc(s.updateMe)))
	s.mux.Handle("PUT /api/v1/me/password", s.require(nil, http.HandlerFunc(s.changePassword)))
	s.mux.Handle("GET /api/v1/me/security", s.require(nil, http.HandlerFunc(s.accountSecurity)))
	s.mux.Handle("GET /api/v1/me/sessions", s.require(nil, http.HandlerFunc(s.listSessions)))
	s.mux.Handle("DELETE /api/v1/me/sessions/{id}", s.require(nil, http.HandlerFunc(s.revokeSession)))
	s.mux.Handle("POST /api/v1/me/sessions/revoke-others", s.require(nil, http.HandlerFunc(s.revokeOtherSessions)))
	s.mux.Handle("POST /api/v1/me/totp/setup", s.require(nil, http.HandlerFunc(s.startTOTPEnrollment)))
	s.mux.Handle("POST /api/v1/me/totp/enable", s.require(nil, http.HandlerFunc(s.enableTOTP)))
	s.mux.Handle("POST /api/v1/me/totp/disable", s.require(nil, http.HandlerFunc(s.disableTOTP)))
	s.mux.Handle("GET /api/v1/dashboard", s.require(nil, http.HandlerFunc(s.dashboard)))
	s.mux.Handle("GET /api/v1/search", s.require(nil, http.HandlerFunc(s.search)))
	s.mux.Handle("GET /api/v1/notifications", s.require(nil, http.HandlerFunc(s.notifications)))
	s.mux.Handle("GET /api/v1/notifications/unread-count", s.require(nil, http.HandlerFunc(s.unreadNotifications)))
	s.mux.Handle("POST /api/v1/notifications/read-all", s.require(nil, http.HandlerFunc(s.readAllNotifications)))
	s.mux.Handle("GET /api/v1/users/directory", s.require(nil, http.HandlerFunc(s.userDirectory)))
	s.mux.Handle("POST /api/v1/notifications/{id}/read", s.require(nil, http.HandlerFunc(s.readNotification)))
	s.mux.Handle("GET /api/v1/review-requests", s.require(nil, http.HandlerFunc(s.listReviewRequests)))
	s.mux.Handle("POST /api/v1/review-requests", s.require([]string{"REQUESTER"}, http.HandlerFunc(s.createReviewRequest)))
	s.mux.Handle("GET /api/v1/review-requests/{id}", s.require(nil, http.HandlerFunc(s.getReviewRequest)))
	s.mux.Handle("PATCH /api/v1/review-requests/{id}", s.require(nil, http.HandlerFunc(s.updateReviewRequest)))
	s.mux.Handle("GET /api/v1/review-requests/{id}/items", s.require(nil, http.HandlerFunc(s.listSubmissionItems)))
	s.mux.Handle("PUT /api/v1/review-requests/{id}/responses/{itemID}", s.require(nil, http.HandlerFunc(s.saveResponse)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/responses/bulk", s.require(nil, http.HandlerFunc(s.bulkSaveResponses)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/submit", s.require(nil, http.HandlerFunc(s.submitReview)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/begin-review", s.require([]string{"SECURITY_REVIEWER"}, http.HandlerFunc(s.beginReview)))
	s.mux.Handle("PUT /api/v1/review-requests/{id}/review-results/{itemID}", s.require([]string{"SECURITY_REVIEWER"}, http.HandlerFunc(s.saveReviewResult)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/change-requests", s.require([]string{"SECURITY_REVIEWER"}, http.HandlerFunc(s.createChangeRequest)))
	s.mux.Handle("PATCH /api/v1/change-requests/{id}", s.require(nil, http.HandlerFunc(s.updateChangeRequest)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/complete-review", s.require([]string{"SECURITY_REVIEWER"}, http.HandlerFunc(s.completeReview)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/approve", s.require([]string{"APPROVER"}, http.HandlerFunc(s.approveReview)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/reject", s.require([]string{"APPROVER"}, http.HandlerFunc(s.rejectReview)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/cancel", s.require([]string{"REQUESTER"}, http.HandlerFunc(s.cancelReview)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/close", s.require([]string{"SECURITY_REVIEWER"}, http.HandlerFunc(s.closeReview)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/participants", s.require(nil, http.HandlerFunc(s.addParticipant)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/copy", s.require([]string{"REQUESTER"}, http.HandlerFunc(s.copyReview)))
	s.mux.Handle("GET /api/v1/review-requests/{id}/rule-candidates", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.listRuleCandidates)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/rule-overrides", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.overrideRuleResult)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/items/{itemID}/evidences", s.require(nil, http.HandlerFunc(s.uploadEvidence)))
	s.mux.Handle("POST /api/v1/review-requests/{id}/items/{itemID}/comments", s.require(nil, http.HandlerFunc(s.addComment)))
	s.mux.Handle("GET /api/v1/evidences/{id}/download", s.require(nil, http.HandlerFunc(s.downloadEvidence)))
	s.mux.Handle("POST /api/v1/evidences/{id}/versions", s.require(nil, http.HandlerFunc(s.newEvidenceVersion)))
	s.mux.Handle("DELETE /api/v1/evidences/{id}", s.require(nil, http.HandlerFunc(s.deleteEvidence)))
	s.mux.Handle("GET /api/v1/review-requests/{id}/export/{format}", s.require(nil, http.HandlerFunc(s.exportReview)))

	// Personal key management is deliberately separate from administrative configuration.
	s.mux.Handle("GET /api/v1/me/api-keys", s.require(nil, http.HandlerFunc(s.listAPIKeys)))
	s.mux.Handle("POST /api/v1/me/api-keys", s.require(nil, http.HandlerFunc(s.createAPIKey)))
	s.mux.Handle("POST /api/v1/me/api-keys/{id}/rotate", s.require(nil, http.HandlerFunc(s.rotateAPIKey)))
	s.mux.Handle("DELETE /api/v1/me/api-keys/{id}", s.require(nil, http.HandlerFunc(s.revokeAPIKey)))
	s.mux.Handle("POST /api/v1/me/encryption-key/rotate", s.require(nil, http.HandlerFunc(s.rotateDataKey)))

	// Template administration and workbook migration.
	s.mux.Handle("GET /api/v1/templates", s.require(nil, http.HandlerFunc(s.listTemplates)))
	s.mux.Handle("POST /api/v1/templates", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.createTemplate)))
	s.mux.Handle("GET /api/v1/templates/{id}", s.require(nil, http.HandlerFunc(s.getTemplate)))
	s.mux.Handle("PATCH /api/v1/templates/{id}", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.updateTemplate)))
	s.mux.Handle("POST /api/v1/templates/{id}/copy", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.copyTemplate)))
	s.mux.Handle("POST /api/v1/templates/{id}/versions", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.createTemplateVersion)))
	s.mux.Handle("POST /api/v1/templates/{id}/versions/{versionID}/items", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.createTemplateItem)))
	s.mux.Handle("PATCH /api/v1/templates/{id}/versions/{versionID}/items/{itemID}", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.updateTemplateItem)))
	s.mux.Handle("DELETE /api/v1/templates/{id}/versions/{versionID}/items/{itemID}", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.deleteTemplateItem)))
	s.mux.Handle("POST /api/v1/templates/{id}/versions/{versionID}/publish", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.publishVersion)))
	s.mux.Handle("POST /api/v1/templates/{id}/versions/{versionID}/retire", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.retireVersion)))
	s.mux.Handle("GET /api/v1/templates/{id}/versions/{versionID}/diff", s.require(nil, http.HandlerFunc(s.versionDiff)))
	s.mux.Handle("GET /api/v1/templates/{id}/versions/{versionID}/changes", s.require(nil, http.HandlerFunc(s.versionChanges)))
	s.mux.Handle("POST /api/v1/templates/import/preview", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.previewImport)))
	s.mux.Handle("POST /api/v1/templates/import", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.importTemplate)))
	s.mux.Handle("GET /api/v1/templates/{id}/export", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.exportTemplate)))

	// Unified Security Controls and impact tracking across checklist versions.
	s.mux.Handle("GET /api/v1/security-controls", s.require(nil, http.HandlerFunc(s.listControls)))
	s.mux.Handle("POST /api/v1/security-controls", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.createControl)))
	s.mux.Handle("PATCH /api/v1/security-controls/{id}", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.updateControl)))
	s.mux.Handle("DELETE /api/v1/security-controls/{id}", s.require([]string{"TEMPLATE_ADMIN"}, http.HandlerFunc(s.deleteControl)))
	s.mux.Handle("GET /api/v1/security-controls/{id}/impact", s.require(nil, http.HandlerFunc(s.controlImpact)))

	// Administrative plane.
	s.mux.Handle("GET /api/v1/admin/users", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.listUsers)))
	s.mux.Handle("POST /api/v1/admin/users", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.createUser)))
	s.mux.Handle("PUT /api/v1/admin/users/{id}/roles", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.updateUserRoles)))
	s.mux.Handle("POST /api/v1/admin/users/{id}/active", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.setUserActive)))
	s.mux.Handle("POST /api/v1/admin/users/{id}/unlock", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.unlockUser)))
	s.mux.Handle("POST /api/v1/admin/users/{id}/password", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.resetUserPassword)))
	s.mux.Handle("POST /api/v1/admin/users/{id}/totp/reset", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.resetUserTOTP)))
	s.mux.Handle("GET /api/v1/admin/settings", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.listSettings)))
	s.mux.Handle("PUT /api/v1/admin/settings/{key}", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.updateSetting)))
	s.mux.Handle("POST /api/v1/admin/settings/oidc/test", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.testOIDC)))
	s.mux.Handle("GET /api/v1/admin/audit", s.require([]string{"SYSTEM_ADMIN", "AUDITOR"}, http.HandlerFunc(s.listAudit)))
	s.mux.Handle("GET /api/v1/admin/audit/verify", s.require([]string{"SYSTEM_ADMIN", "AUDITOR"}, http.HandlerFunc(s.verifyAudit)))
	s.mux.Handle("GET /api/v1/admin/logs", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.listLogs)))
	s.mux.Handle("GET /api/v1/admin/jobs", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.listJobs)))
	s.mux.Handle("POST /api/v1/admin/jobs/{id}/retry", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.retryJob)))
	s.mux.Handle("POST /api/v1/admin/jobs/retry-failed", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.retryFailedJobs)))
	s.mux.Handle("GET /api/v1/admin/system", s.require([]string{"SYSTEM_ADMIN"}, http.HandlerFunc(s.systemInfo)))

	// Machine interfaces.
	s.mux.Handle("GET /api/openapi.json", s.require(nil, http.HandlerFunc(s.openAPI)))
	s.mux.Handle("POST /mcp", s.require(nil, http.HandlerFunc(s.mcp)))
	s.mux.Handle("/", SPA{Dir: s.WebDir})
}

func (s *Server) require(roles []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.Auth.Authenticate(r)
		if err != nil {
			problem(w, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", err.Error(), nil)
			return
		}
		if len(roles) > 0 && !auth.HasRole(sess, roles...) {
			problem(w, http.StatusForbidden, "FORBIDDEN", "이 작업을 수행할 권한이 없습니다.", nil)
			return
		}
		// A privileged account that policy requires to hold a one-time code can
		// reach only the enrolment endpoints until it has one.
		if sess.EnrollTOTP && !totpEnrollmentPath(r.URL.Path) {
			problem(w, http.StatusForbidden, "TOTP_ENROLLMENT_REQUIRED", "보안 정책에 따라 일회용 코드를 먼저 등록해야 합니다.", nil)
			return
		}
		if sess.APIKey && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && r.URL.Path != "/mcp" && !contains(sess.Scopes, "read:write") {
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
func problem(w http.ResponseWriter, status int, code, message string, details any) {
	jsonResponse(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "details": details}})
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
