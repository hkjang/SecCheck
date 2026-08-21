package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

const CookieName = "seccheck_session"

// lastSeenWriteInterval keeps session liveness tracking cheap: a busy user
// would otherwise cause one UPDATE per API request.
const lastSeenWriteInterval = time.Minute

// decoyHash is a bcrypt hash of random bytes generated at start-up. Comparing
// against it when the account does not exist keeps the failed-login response
// time indistinguishable from a wrong password, so the login form cannot be
// used to enumerate usernames.
var decoyHash = func() []byte {
	secret, _ := cryptox.RandomBytes(32)
	h, _ := bcrypt.GenerateFromPassword(secret, bcrypt.DefaultCost)
	return h
}()

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrTOTPRequired tells the sign-in screen to ask for the six digit code
	// rather than reporting a wrong password.
	ErrTOTPRequired = errors.New("one-time code required")
	ErrTOTPInvalid  = errors.New("one-time code is not valid")
)

// Credentials is the sign-in payload. It is a struct because the one-time code
// made the positional argument list unreadable.
type Credentials struct {
	Username  string
	Password  string
	TOTPCode  string
	IP        string
	UserAgent string
}

// LockedError reports that an account is temporarily closed to password logins
// after repeated failures.
type LockedError struct{ Until time.Time }

func (e *LockedError) Error() string {
	return "account locked until " + e.Until.UTC().Format(time.RFC3339)
}

// SecurityPolicy is the effective access-security configuration shared by the
// authentication service and the HTTP layer.
type SecurityPolicy struct {
	LoginRateLimitPerMinute int
	MaxLoginFailures        int // zero disables account lockout
	LockoutMinutes          int
	IdleTimeoutMinutes      int
	RequireTOTPForAdmins    bool
}

// securitySettings mirrors the stored JSON. MaxLoginFailures is a pointer so a
// deliberate 0, meaning lockout is switched off, stays distinguishable from a
// settings row written before the option existed, which has to fall back to
// the secure default instead.
type securitySettings struct {
	LoginRateLimitPerMinute int  `json:"login_rate_limit_per_minute"`
	MaxLoginFailures        *int `json:"max_login_failures"`
	LockoutMinutes          int  `json:"lockout_minutes"`
	IdleTimeoutMinutes      int  `json:"idle_timeout_minutes"`
	RequireTOTPForAdmins    bool `json:"require_totp_for_admins"`
}

// policy applies the supported ranges, replacing every out-of-range or missing
// value with its default.
func (c securitySettings) policy() SecurityPolicy {
	p := SecurityPolicy{LoginRateLimitPerMinute: c.LoginRateLimitPerMinute, MaxLoginFailures: 5, LockoutMinutes: c.LockoutMinutes, IdleTimeoutMinutes: c.IdleTimeoutMinutes, RequireTOTPForAdmins: c.RequireTOTPForAdmins}
	if p.LoginRateLimitPerMinute < 1 || p.LoginRateLimitPerMinute > 600 {
		p.LoginRateLimitPerMinute = 30
	}
	if c.MaxLoginFailures != nil && *c.MaxLoginFailures >= 0 && *c.MaxLoginFailures <= 100 {
		p.MaxLoginFailures = *c.MaxLoginFailures
	}
	if p.LockoutMinutes < 1 || p.LockoutMinutes > 1440 {
		p.LockoutMinutes = 15
	}
	if p.IdleTimeoutMinutes < 0 || p.IdleTimeoutMinutes > 10080 {
		p.IdleTimeoutMinutes = 0
	}
	return p
}

type Service struct {
	Store *store.Store
	Box   *cryptox.Box
	HTTP  *http.Client

	policyMu     sync.Mutex
	policyAt     time.Time
	policyLoaded bool
	policy       SecurityPolicy
}

type Session struct {
	ID, CSRF  string
	User      store.User
	ExpiresAt time.Time
	APIKey    bool
	Scopes    []string
	// EnrollTOTP is set when policy requires this account to hold a one-time
	// code but it has not enrolled yet. The HTTP layer then allows only the
	// enrolment endpoints.
	EnrollTOTP bool
}

type OIDCSettings struct {
	Enabled       bool     `json:"enabled"`
	Issuer        string   `json:"issuer"`
	ClientID      string   `json:"client_id"`
	RedirectURL   string   `json:"redirect_url"`
	Scopes        []string `json:"scopes"`
	UsernameClaim string   `json:"username_claim"`
	DefaultRole   string   `json:"default_role"`
	GroupsClaim   string   `json:"groups_claim"`
	RoleMappings  []struct {
		Group string `json:"group"`
		Role  string `json:"role"`
	} `json:"role_mappings"`
	ClientSecret string `json:"client_secret,omitempty"`
}

type Provider struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	Issuer                string `json:"issuer"`
}

func New(s *store.Store, b *cryptox.Box) *Service {
	return &Service{Store: s, Box: b, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

// Policy returns the effective access-security policy, refreshed from the
// settings table at most every 15 seconds so it can be changed at runtime
// without adding a query to every authenticated request.
func (a *Service) Policy(ctx context.Context) SecurityPolicy {
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	if a.policyLoaded && time.Since(a.policyAt) < 15*time.Second {
		return a.policy
	}
	var raw securitySettings
	if _, err := a.Store.Setting(ctx, "security", &raw); err != nil {
		raw = securitySettings{}
	}
	a.policy, a.policyAt, a.policyLoaded = raw.policy(), time.Now(), true
	return a.policy
}

// InvalidatePolicy drops the cached copy so a saved setting takes effect on
// the next request instead of up to fifteen seconds later. An administrator
// who changes a security setting and immediately tests it should not see the
// old behaviour and conclude the setting does not work.
func (a *Service) InvalidatePolicy() {
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	a.policyLoaded = false
}

func PasswordHash(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must have at least 12 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

func (a *Service) PasswordLogin(ctx context.Context, in Credentials) (store.User, string, string, time.Time, error) {
	policy := a.Policy(ctx)
	u, err := a.Store.GetUserByUsername(ctx, strings.TrimSpace(in.Username))
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(decoyHash, []byte(in.Password))
		return u, "", "", time.Time{}, ErrInvalidCredentials
	}
	if until, locked := a.lockedUntil(ctx, u.ID); locked {
		return u, "", "", time.Time{}, &LockedError{Until: until}
	}
	passwordOK := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)) == nil
	if !passwordOK || !u.Active || u.AuthSource != "local" {
		if until, locked := a.registerLoginFailure(ctx, u.ID, policy); locked {
			return u, "", "", time.Time{}, &LockedError{Until: until}
		}
		return u, "", "", time.Time{}, ErrInvalidCredentials
	}
	secret, enabled, err := a.totpSecret(ctx, u.ID)
	if err != nil {
		return u, "", "", time.Time{}, err
	}
	if enabled {
		if strings.TrimSpace(in.TOTPCode) == "" {
			// The password was right, so this is not a failed attempt; it is a
			// prompt for the second factor.
			return u, "", "", time.Time{}, ErrTOTPRequired
		}
		if !VerifyTOTP(secret, in.TOTPCode, time.Now()) {
			if until, locked := a.registerLoginFailure(ctx, u.ID, policy); locked {
				return u, "", "", time.Time{}, &LockedError{Until: until}
			}
			return u, "", "", time.Time{}, ErrTOTPInvalid
		}
	}
	token, csrf, expires, err := a.NewSession(ctx, u.ID, in.IP, in.UserAgent)
	if err == nil {
		_, _ = a.Store.Pool.Exec(ctx, `UPDATE users SET last_login_at=now(),failed_login_count=0,locked_until=NULL,updated_at=now() WHERE id=$1`, u.ID)
	}
	return u, token, csrf, expires, err
}

// totpSecret returns the account's decrypted one-time-password secret.
func (a *Service) totpSecret(ctx context.Context, userID string) (string, bool, error) {
	var encrypted string
	var enabled bool
	if err := a.Store.Pool.QueryRow(ctx, `SELECT totp_secret,totp_enabled FROM users WHERE id=$1`, userID).Scan(&encrypted, &enabled); err != nil {
		return "", false, err
	}
	if encrypted == "" {
		return "", false, nil
	}
	plain, err := a.Box.Decrypt(encrypted, []byte("totp:"+userID))
	if err != nil {
		return "", enabled, err
	}
	return string(plain), enabled, nil
}

// StoreTOTPSecret saves an enrolment secret encrypted under the master key.
// The secret is written before it is enabled, so a half-finished enrolment
// never locks anybody out.
func (a *Service) StoreTOTPSecret(ctx context.Context, userID, secret string) error {
	encrypted, err := a.Box.Encrypt([]byte(secret), []byte("totp:"+userID))
	if err != nil {
		return err
	}
	_, err = a.Store.Pool.Exec(ctx, `UPDATE users SET totp_secret=$2,totp_enabled=false,totp_enrolled_at=NULL,updated_at=now() WHERE id=$1`, userID, encrypted)
	return err
}

// EnableTOTP turns on the second factor once the user has proved they can
// generate a code from the stored secret.
func (a *Service) EnableTOTP(ctx context.Context, userID, code string) error {
	secret, _, err := a.totpSecret(ctx, userID)
	if err != nil {
		return err
	}
	if secret == "" {
		return errors.New("no enrolment in progress")
	}
	if !VerifyTOTP(secret, code, time.Now()) {
		return ErrTOTPInvalid
	}
	_, err = a.Store.Pool.Exec(ctx, `UPDATE users SET totp_enabled=true,totp_enrolled_at=now(),updated_at=now() WHERE id=$1`, userID)
	return err
}

func (a *Service) DisableTOTP(ctx context.Context, userID string) error {
	_, err := a.Store.Pool.Exec(ctx, `UPDATE users SET totp_secret='',totp_enabled=false,totp_enrolled_at=NULL,updated_at=now() WHERE id=$1`, userID)
	return err
}

// RequiresTOTPEnrollment reports whether policy expects this account to hold a
// second factor that it has not set up yet.
func RequiresTOTPEnrollment(policy SecurityPolicy, u store.User, enabled bool) bool {
	if !policy.RequireTOTPForAdmins || enabled || u.AuthSource != "local" {
		return false
	}
	for _, role := range u.Roles {
		if role == "SYSTEM_ADMIN" || role == "TEMPLATE_ADMIN" || role == "SECURITY_REVIEWER" || role == "APPROVER" {
			return true
		}
	}
	return false
}

func (a *Service) lockedUntil(ctx context.Context, userID string) (time.Time, bool) {
	var until *time.Time
	if err := a.Store.Pool.QueryRow(ctx, `SELECT locked_until FROM users WHERE id=$1`, userID).Scan(&until); err != nil || until == nil {
		return time.Time{}, false
	}
	if until.After(time.Now()) {
		return *until, true
	}
	// The window has elapsed. Clear the counter now so the user starts from a
	// full budget instead of being locked again by a single mistyped password.
	_, _ = a.Store.Pool.Exec(ctx, `UPDATE users SET failed_login_count=0,locked_until=NULL WHERE id=$1 AND locked_until<=now()`, userID)
	return time.Time{}, false
}

// registerLoginFailure counts the attempt and locks the account once the
// configured threshold is reached. Existing sessions are deliberately left
// alone so that a third party cannot use the lockout to sign a user out.
func (a *Service) registerLoginFailure(ctx context.Context, userID string, policy SecurityPolicy) (time.Time, bool) {
	if policy.MaxLoginFailures <= 0 {
		return time.Time{}, false
	}
	var until *time.Time
	err := a.Store.Pool.QueryRow(ctx, `UPDATE users SET failed_login_count=failed_login_count+1,
                locked_until=CASE WHEN failed_login_count+1>=$2 THEN now()+make_interval(mins=>$3) ELSE locked_until END,
                updated_at=now() WHERE id=$1 RETURNING locked_until`, userID, policy.MaxLoginFailures, policy.LockoutMinutes).Scan(&until)
	if err != nil || until == nil {
		return time.Time{}, false
	}
	return *until, until.After(time.Now())
}

// Unlock clears a lockout so an administrator can restore access before the
// window elapses.
func (a *Service) Unlock(ctx context.Context, userID string) error {
	tag, err := a.Store.Pool.Exec(ctx, `UPDATE users SET failed_login_count=0,locked_until=NULL,updated_at=now() WHERE id=$1`, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (a *Service) NewSession(ctx context.Context, userID, ip, userAgent string) (string, string, time.Time, error) {
	token, err := cryptox.Token(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	csrf, err := cryptox.Token(24)
	if err != nil {
		return "", "", time.Time{}, err
	}
	var general struct {
		SessionMinutes int `json:"session_minutes"`
	}
	_, _ = a.Store.Setting(ctx, "general", &general)
	if general.SessionMinutes < 15 || general.SessionMinutes > 10080 {
		general.SessionMinutes = 480
	}
	expires := time.Now().Add(time.Duration(general.SessionMinutes) * time.Minute)
	h := sha256.Sum256([]byte(token))
	_, err = a.Store.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_token,source_ip,user_agent,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, store.NewID(), userID, h[:], csrf, ip, userAgent, expires)
	return token, csrf, expires, err
}

func (a *Service) Authenticate(r *http.Request) (Session, error) {
	if authz := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		return a.authenticateAPIKey(r.Context(), strings.TrimSpace(authz[7:]))
	}
	c, err := r.Cookie(CookieName)
	if err != nil {
		return Session{}, errors.New("authentication required")
	}
	h := sha256.Sum256([]byte(c.Value))
	var sess Session
	var uid string
	var lastSeen time.Time
	err = a.Store.Pool.QueryRow(r.Context(), `SELECT id,user_id,csrf_token,expires_at,last_seen_at FROM sessions WHERE token_hash=$1 AND expires_at>now()`, h[:]).Scan(&sess.ID, &uid, &sess.CSRF, &sess.ExpiresAt, &lastSeen)
	if err != nil {
		return Session{}, errors.New("authentication required")
	}
	idle := time.Since(lastSeen)
	if timeout := a.Policy(r.Context()).IdleTimeoutMinutes; timeout > 0 && idle > time.Duration(timeout)*time.Minute {
		_, _ = a.Store.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE id=$1`, sess.ID)
		return Session{}, errors.New("session expired after inactivity")
	}
	sess.User, err = a.Store.GetUser(r.Context(), uid)
	if err != nil || !sess.User.Active {
		return Session{}, errors.New("authentication required")
	}
	var totpEnabled bool
	_ = a.Store.Pool.QueryRow(r.Context(), `SELECT totp_enabled FROM users WHERE id=$1`, uid).Scan(&totpEnabled)
	sess.EnrollTOTP = RequiresTOTPEnrollment(a.Policy(r.Context()), sess.User, totpEnabled)
	if idle >= lastSeenWriteInterval && !passiveRequest(r.URL.Path) {
		_, _ = a.Store.Pool.Exec(r.Context(), `UPDATE sessions SET last_seen_at=now() WHERE id=$1`, sess.ID)
	}
	return sess, nil
}

// passiveRequest reports whether a request is the browser polling in the
// background rather than somebody using the service. The unread-notification
// badge refreshes once a minute, which kept last_seen_at moving forever and
// meant an idle session on an unattended desk never timed out — the polling
// defeated the very setting meant to close it. The list is server-side so a
// client cannot extend its own session by omitting a header.
func passiveRequest(path string) bool {
	switch path {
	case "/api/v1/notifications/unread-count":
		return true
	}
	return false
}

func (a *Service) authenticateAPIKey(ctx context.Context, token string) (Session, error) {
	h := sha256.Sum256([]byte(token))
	var uid string
	var scopes []string
	err := a.Store.Pool.QueryRow(ctx, `UPDATE api_keys SET last_used_at=now() WHERE secret_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now()) RETURNING user_id,scopes`, h[:]).Scan(&uid, &scopes)
	if err != nil {
		return Session{}, errors.New("invalid API key")
	}
	u, err := a.Store.GetUser(ctx, uid)
	if err != nil || !u.Active {
		return Session{}, errors.New("invalid API key")
	}
	return Session{ID: "api-key", User: u, APIKey: true, Scopes: scopes}, nil
}

func (a *Service) DeleteSession(ctx context.Context, token string) error {
	h := sha256.Sum256([]byte(token))
	_, err := a.Store.Pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, h[:])
	return err
}

func HasRole(s Session, roles ...string) bool {
	for _, have := range s.User.Roles {
		for _, want := range roles {
			if subtle.ConstantTimeCompare([]byte(have), []byte(want)) == 1 {
				return true
			}
		}
	}
	return false
}

func (a *Service) OIDCConfig(ctx context.Context) (OIDCSettings, error) {
	var cfg OIDCSettings
	encrypted, err := a.Store.Setting(ctx, "oidc", &cfg)
	if err != nil {
		return cfg, err
	}
	if encrypted != "" {
		p, err := a.Box.Decrypt(encrypted, []byte("setting:oidc"))
		if err != nil {
			return cfg, err
		}
		cfg.ClientSecret = string(p)
	}
	return cfg, nil
}

func (a *Service) Discover(ctx context.Context, issuer string) (Provider, error) {
	var p Provider
	issuer = strings.TrimRight(issuer, "/")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	res, err := a.HTTP.Do(req)
	if err != nil {
		return p, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return p, fmt.Errorf("OIDC discovery returned %s", res.Status)
	}
	if err = json.NewDecoder(res.Body).Decode(&p); err != nil {
		return p, err
	}
	if p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" || p.UserinfoEndpoint == "" {
		return p, errors.New("OIDC discovery document is incomplete")
	}
	return p, nil
}

func (a *Service) BeginOIDC(ctx context.Context, returnTo string) (string, error) {
	cfg, err := a.OIDCConfig(ctx)
	if err != nil {
		return "", err
	}
	if !cfg.Enabled {
		return "", errors.New("OIDC is disabled")
	}
	p, err := a.Discover(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}
	state, _ := cryptox.Token(32)
	nonce, _ := cryptox.Token(24)
	verifier, _ := cryptox.Token(48)
	h := sha256.Sum256([]byte(state))
	challenge := sha256.Sum256([]byte(verifier))
	if !strings.HasPrefix(returnTo, "/") {
		returnTo = "/"
	}
	_, err = a.Store.Pool.Exec(ctx, `INSERT INTO oidc_states(state_hash,nonce,code_verifier,return_to,expires_at) VALUES($1,$2,$3,$4,now()+interval '10 minutes')`, h[:], nonce, verifier, returnTo)
	if err != nil {
		return "", err
	}
	q := url.Values{"response_type": {"code"}, "client_id": {cfg.ClientID}, "redirect_uri": {cfg.RedirectURL}, "scope": {strings.Join(cfg.Scopes, " ")}, "state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
	return p.AuthorizationEndpoint + "?" + q.Encode(), nil
}

func (a *Service) CompleteOIDC(ctx context.Context, state, code, ip, userAgent string) (store.User, string, string, time.Time, string, error) {
	var verifier, returnTo, expectedNonce string
	h := sha256.Sum256([]byte(state))
	err := a.Store.Pool.QueryRow(ctx, `DELETE FROM oidc_states WHERE state_hash=$1 AND expires_at>now() RETURNING code_verifier,return_to,nonce`, h[:]).Scan(&verifier, &returnTo, &expectedNonce)
	if err != nil {
		return store.User{}, "", "", time.Time{}, "", errors.New("invalid or expired OIDC state")
	}
	cfg, err := a.OIDCConfig(ctx)
	if err != nil {
		return store.User{}, "", "", time.Time{}, "", err
	}
	p, err := a.Discover(ctx, cfg.Issuer)
	if err != nil {
		return store.User{}, "", "", time.Time{}, "", err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cfg.RedirectURL}, "client_id": {cfg.ClientID}, "client_secret": {cfg.ClientSecret}, "code_verifier": {verifier}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := a.HTTP.Do(req)
	if err != nil {
		return store.User{}, "", "", time.Time{}, "", err
	}
	defer res.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if res.StatusCode != http.StatusOK {
		return store.User{}, "", "", time.Time{}, "", fmt.Errorf("OIDC token exchange returned %s", res.Status)
	}
	if err = json.NewDecoder(res.Body).Decode(&tok); err != nil {
		return store.User{}, "", "", time.Time{}, "", err
	}
	if tok.IDToken == "" {
		return store.User{}, "", "", time.Time{}, "", errors.New("OIDC provider did not return an ID token")
	}
	oidcProvider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return store.User{}, "", "", time.Time{}, "", fmt.Errorf("OIDC verifier discovery: %w", err)
	}
	verified, err := oidcProvider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, tok.IDToken)
	if err != nil {
		return store.User{}, "", "", time.Time{}, "", fmt.Errorf("verify OIDC ID token: %w", err)
	}
	claims := map[string]any{}
	if err = verified.Claims(&claims); err != nil {
		return store.User{}, "", "", time.Time{}, "", err
	}
	nonce, _ := claims["nonce"].(string)
	if nonce == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(expectedNonce)) != 1 {
		return store.User{}, "", "", time.Time{}, "", errors.New("OIDC nonce validation failed")
	}
	username, _ := claims[cfg.UsernameClaim].(string)
	if username == "" {
		username, _ = claims["sub"].(string)
	}
	if username == "" {
		return store.User{}, "", "", time.Time{}, "", errors.New("OIDC username claim missing")
	}
	display, _ := claims["name"].(string)
	if display == "" {
		display = username
	}
	email, _ := claims["email"].(string)
	u, lookupErr := a.Store.GetUserByUsername(ctx, username)
	if lookupErr == nil {
		// Never link an IdP identity to an existing local account merely because
		// the usernames match. That would let an IdP claim inherit local roles.
		if u.AuthSource != "oidc" {
			return store.User{}, "", "", time.Time{}, "", errors.New("OIDC username is reserved by another authentication source")
		}
		if !u.Active {
			return u, "", "", time.Time{}, "", errors.New("OIDC account is disabled")
		}
		if err = a.enforceInactiveAdminLock(ctx, u); err != nil {
			return u, "", "", time.Time{}, "", err
		}
		_, err = a.Store.Pool.Exec(ctx, `UPDATE users SET display_name=$2,email=$3,last_login_at=now(),updated_at=now() WHERE id=$1 AND auth_source='oidc' AND active`, u.ID, display, email)
	} else if errors.Is(lookupErr, pgx.ErrNoRows) {
		_, err = a.Store.Pool.Exec(ctx, `INSERT INTO users(id,username,display_name,email,auth_source,last_login_at) VALUES($1,$2,$3,$4,'oidc',now())`, store.NewID(), username, display, email)
	} else {
		err = lookupErr
	}
	if err != nil {
		return store.User{}, "", "", time.Time{}, "", err
	}
	u, err = a.Store.GetUserByUsername(ctx, username)
	if err != nil {
		return u, "", "", time.Time{}, "", err
	}
	if len(cfg.RoleMappings) > 0 {
		// Keycloak only puts groups in the token when the client has a group
		// membership mapper, and getting that wrong looks exactly like a
		// mapping that does not work. Recording what actually arrived is the
		// only way an administrator can tell the two apart.
		groups := groupsFromClaims(cfg, claims)
		a.Store.Log(ctx, "INFO", "", "oidc", "directory groups received", map[string]any{"username": username, "groups": groups})
		if err = a.syncOIDCRoles(ctx, u, rolesFromGroups(cfg, claims), ip); err != nil {
			return u, "", "", time.Time{}, "", err
		}
		u, _ = a.Store.GetUser(ctx, u.ID)
	} else if len(u.Roles) == 0 {
		_, err = a.Store.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,$2) ON CONFLICT DO NOTHING`, u.ID, cfg.DefaultRole)
		if err != nil {
			return u, "", "", time.Time{}, "", err
		}
		u, _ = a.Store.GetUser(ctx, u.ID)
	}
	token, csrf, expires, err := a.NewSession(ctx, u.ID, ip, userAgent)
	return u, token, csrf, expires, returnTo, err
}

// rolesFromGroups reads the group claim and returns the roles it maps to.
// Keycloak writes realm groups with a leading slash, so both forms match, and
// the comparison ignores case because directory exports rarely agree on it.
func rolesFromGroups(cfg OIDCSettings, claims map[string]any) []string {
	member := map[string]bool{}
	for _, name := range groupsFromClaims(cfg, claims) {
		member[normalizeGroup(name)] = true
	}
	seen := map[string]bool{}
	roles := []string{}
	for _, mapping := range cfg.RoleMappings {
		if !member[normalizeGroup(mapping.Group)] || seen[mapping.Role] {
			continue
		}
		seen[mapping.Role] = true
		roles = append(roles, mapping.Role)
	}
	// Somebody who matches no mapped group still has to be able to work, so
	// they get the same role a first-time sign-in would have given them.
	if len(roles) == 0 && cfg.DefaultRole != "" {
		roles = append(roles, cfg.DefaultRole)
	}
	return roles
}

// groupsFromClaims reads the configured claim, which providers write either
// as a list or, when somebody belongs to one group, as a bare string.
func groupsFromClaims(cfg OIDCSettings, claims map[string]any) []string {
	claim := strings.TrimSpace(cfg.GroupsClaim)
	if claim == "" {
		claim = "groups"
	}
	out := []string{}
	switch value := claims[claim].(type) {
	case string:
		out = append(out, value)
	case []any:
		for _, entry := range value {
			if name, ok := entry.(string); ok {
				out = append(out, name)
			}
		}
	case []string:
		out = append(out, value...)
	}
	return out
}

func normalizeGroup(name string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "/"))
}

// syncOIDCRoles makes the directory the source of truth for this account: a
// role that no mapped group grants is removed. Without that, taking somebody
// out of a group in the IdP left their access here untouched. Roles the
// mapping never mentions are left alone, so an administrator can still grant
// something by hand that the directory does not know about.
func (a *Service) syncOIDCRoles(ctx context.Context, u store.User, roles []string, ip string) error {
	governed := map[string]bool{}
	for _, role := range assignableOIDCRoles {
		governed[role] = true
	}
	tx, err := a.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, role := range roles {
		if !governed[role] {
			continue
		}
		if _, err = tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,$2) ON CONFLICT DO NOTHING`, u.ID, role); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1 AND role_code=ANY($2) AND NOT (role_code=ANY($3))`, u.ID, assignableOIDCRoles, roles); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	// A privilege that changes without anyone deciding it still has to appear
	// in the audit log, or the directory becomes a way to alter access here
	// without leaving a trace.
	after, _ := a.Store.GetUser(ctx, u.ID)
	if !sameRoles(u.Roles, after.Roles) {
		_ = a.Store.Audit(ctx, store.AuditEvent{UserID: u.ID, UserName: u.DisplayName, SourceIP: ip, EventType: "SYNC_OIDC_ROLES", TargetType: "USER", TargetID: u.ID,
			Before: map[string]any{"roles": u.Roles}, After: map[string]any{"roles": after.Roles}})
	}
	return nil
}

func sameRoles(before, after []string) bool {
	if len(before) != len(after) {
		return false
	}
	a1, a2 := append([]string(nil), before...), append([]string(nil), after...)
	sort.Strings(a1)
	sort.Strings(a2)
	return slices.Equal(a1, a2)
}

// SYSTEM_ADMIN is deliberately absent. Role sync runs at every sign-in with
// nobody in the loop, so mapping it would let anyone who can edit a directory
// group become an administrator of the audit system without leaving a trace
// here first. Administrators stay a deliberate in-app assignment.
var assignableOIDCRoles = []string{"TEMPLATE_ADMIN", "SECURITY_REVIEWER", "REQUESTER", "CONTRIBUTOR", "APPROVER", "AUDITOR"}

// AssignableOIDCRoles is the set a group mapping may grant.
func AssignableOIDCRoles() []string { return append([]string(nil), assignableOIDCRoles...) }

func (a *Service) enforceInactiveAdminLock(ctx context.Context, u store.User) error {
	privileged := false
	for _, role := range u.Roles {
		if role == "SYSTEM_ADMIN" || role == "TEMPLATE_ADMIN" || role == "SECURITY_REVIEWER" || role == "APPROVER" {
			privileged = true
			break
		}
	}
	if !privileged {
		return nil
	}
	var cfg struct {
		InactiveAdminLockDays int `json:"inactive_admin_lock_days"`
	}
	_, _ = a.Store.Setting(ctx, "security", &cfg)
	if cfg.InactiveAdminLockDays <= 0 {
		return nil
	}
	var stale bool
	err := a.Store.Pool.QueryRow(ctx, `SELECT COALESCE(last_login_at < now()-make_interval(days=>$2),false) FROM users WHERE id=$1`, u.ID, cfg.InactiveAdminLockDays).Scan(&stale)
	if err != nil || !stale {
		return err
	}
	_, _ = a.Store.Pool.Exec(ctx, `UPDATE users SET active=false,updated_at=now() WHERE id=$1`, u.ID)
	_, _ = a.Store.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, u.ID)
	return errors.New("privileged OIDC account locked after prolonged inactivity")
}

func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
