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
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

const CookieName = "seccheck_session"

type Service struct {
	Store *store.Store
	Box   *cryptox.Box
	HTTP  *http.Client
}

type Session struct {
	ID, CSRF  string
	User      store.User
	ExpiresAt time.Time
	APIKey    bool
	Scopes    []string
}

type OIDCSettings struct {
	Enabled       bool     `json:"enabled"`
	Issuer        string   `json:"issuer"`
	ClientID      string   `json:"client_id"`
	RedirectURL   string   `json:"redirect_url"`
	Scopes        []string `json:"scopes"`
	UsernameClaim string   `json:"username_claim"`
	DefaultRole   string   `json:"default_role"`
	ClientSecret  string   `json:"client_secret,omitempty"`
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

func PasswordHash(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must have at least 12 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

func (a *Service) PasswordLogin(ctx context.Context, username, password, ip, userAgent string) (store.User, string, string, time.Time, error) {
	u, err := a.Store.GetUserByUsername(ctx, strings.TrimSpace(username))
	if err != nil {
		return u, "", "", time.Time{}, errors.New("invalid credentials")
	}
	if !u.Active || u.AuthSource != "local" || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return u, "", "", time.Time{}, errors.New("invalid credentials")
	}
	token, csrf, expires, err := a.NewSession(ctx, u.ID, ip, userAgent)
	if err == nil {
		_, _ = a.Store.Pool.Exec(ctx, `UPDATE users SET last_login_at=now(),updated_at=now() WHERE id=$1`, u.ID)
	}
	return u, token, csrf, expires, err
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
	err = a.Store.Pool.QueryRow(r.Context(), `SELECT id,user_id,csrf_token,expires_at FROM sessions WHERE token_hash=$1 AND expires_at>now()`, h[:]).Scan(&sess.ID, &uid, &sess.CSRF, &sess.ExpiresAt)
	if err != nil {
		return Session{}, errors.New("authentication required")
	}
	sess.User, err = a.Store.GetUser(r.Context(), uid)
	if err != nil || !sess.User.Active {
		return Session{}, errors.New("authentication required")
	}
	_, _ = a.Store.Pool.Exec(r.Context(), `UPDATE sessions SET last_seen_at=now() WHERE id=$1`, sess.ID)
	return sess, nil
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
	if len(u.Roles) == 0 {
		_, err = a.Store.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,$2) ON CONFLICT DO NOTHING`, u.ID, cfg.DefaultRole)
		if err != nil {
			return u, "", "", time.Time{}, "", err
		}
		u, _ = a.Store.GetUser(ctx, u.ID)
	}
	token, csrf, expires, err := a.NewSession(ctx, u.ID, ip, userAgent)
	return u, token, csrf, expires, returnTo, err
}

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
