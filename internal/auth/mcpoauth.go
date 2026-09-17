package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
)

// MCP 를 SSO 로 — 개인 키 없이, Keycloak 이 발급한 액세스 토큰으로.
//
// The MCP authorization specification (2025-06-18 and later) is OAuth 2.1:
// this server is a *resource server* that says where its authorization server
// is, and a client refused with 401 reads that, sends the person through
// Keycloak with PKCE, and comes back with an access token whose audience is
// this server. Nothing about issuing tokens happens here. What this file
// answers is one question -- is this token one Keycloak issued for this
// deployment, for an account that already exists -- and it answers it on
// every request without keeping anything.
//
// The personal key stays. A token from SSO is a second door into the same
// room: it authenticates an existing account, carries the scopes the
// administrator chose, and is held to the same write-scope rule a key is. It
// never creates an account, never wakes a disabled one, and never reads a
// role out of the token.

// MCPOAuthSettingKey is the settings row that holds the MCP SSO switch. The
// standard names the keys mcp.oauth.enabled and so on; every settings row
// here is one flat JSON object, so they live as oauth_enabled ... under the
// mcp row, the way mail.enabled lives as enabled under mail.
const MCPOAuthSettingKey = "mcp"

// MCPPath is the endpoint the token opens, and the only one it opens.
const MCPPath = "/mcp"

// APIKeyPrefix is what every personal key starts with, which is how a bearer
// that is a key is told from one that is a token without touching the
// database.
const APIKeyPrefix = "sck_"

// mcpSettings mirrors the stored JSON of the mcp row.
type mcpSettings struct {
	OAuthEnabled  bool   `json:"oauth_enabled"`
	OAuthResource string `json:"oauth_resource"`
	OAuthAudience string `json:"oauth_audience"`
	OAuthScopes   string `json:"oauth_scopes"`
}

// MCPOAuthConfig is the effective configuration: the mcp row joined with the
// parts of the web sign-in it reuses. Nothing new is asked of the operator
// that Keycloak already told them for the web login.
type MCPOAuthConfig struct {
	Enabled bool
	// Issuer is the authorization server, shared with the web sign-in.
	Issuer string
	// Resource is the identifier this deployment claims for /mcp (RFC 8707):
	// what the metadata document advertises and what a token's aud may name.
	// It comes from the setting, or the service address the mail tab holds,
	// and never from a request's Host header, which anybody can set.
	Resource string
	// Audiences are the client IDs an administrator accepts in aud or azp.
	Audiences []string
	// Scopes are what a valid token may do, in this service's vocabulary
	// (read, read:write). A token does not carry that vocabulary unless
	// somebody teaches Keycloak it, so the administrator states it once.
	Scopes        []string
	UsernameClaim string
	// Reason says why Enabled is false although the switch is on, for the log.
	Reason string
}

// MetadataURL is where a refused client is sent to learn the above.
func (c MCPOAuthConfig) MetadataURL() string {
	return strings.TrimSuffix(c.Resource, MCPPath) + "/.well-known/oauth-protected-resource" + MCPPath
}

// MCPOAuthConfig reads the switch and everything it depends on. The switch
// being on is not enough: without an issuer there is nobody to verify a token
// against, and without a resource identifier there is nothing for a token to
// be for, so either leaves the feature off with the reason on the config.
func (a *Service) MCPOAuthConfig(ctx context.Context) MCPOAuthConfig {
	var raw mcpSettings
	_, _ = a.Store.Setting(ctx, MCPOAuthSettingKey, &raw)
	var oidcCfg OIDCSettings
	_, _ = a.Store.Setting(ctx, "oidc", &oidcCfg)
	var mailCfg struct {
		BaseURL string `json:"base_url"`
	}
	_, _ = a.Store.Setting(ctx, "mail", &mailCfg)

	cfg := MCPOAuthConfig{
		Issuer:        strings.TrimRight(strings.TrimSpace(oidcCfg.Issuer), "/"),
		Resource:      MCPResource(raw.OAuthResource, mailCfg.BaseURL),
		Audiences:     SplitList(raw.OAuthAudience),
		Scopes:        SplitList(raw.OAuthScopes),
		UsernameClaim: strings.TrimSpace(oidcCfg.UsernameClaim),
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"read"}
	}
	switch {
	case !raw.OAuthEnabled:
		cfg.Reason = "mcp.oauth.enabled is off"
	case !oidcCfg.Enabled || cfg.Issuer == "":
		cfg.Reason = "Keycloak OIDC is not enabled, so there is no issuer to verify tokens against"
	case cfg.Resource == "":
		cfg.Reason = "no resource identifier: set mcp.oauth.resource or the service address in the mail tab"
	default:
		cfg.Enabled = true
	}
	return cfg
}

// MCPResource builds the resource identifier from the explicit setting, or
// from the service address plus the MCP path. Empty when neither is set.
func MCPResource(explicit, baseURL string) string {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		return explicit
	}
	if baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/"); baseURL != "" {
		return baseURL + MCPPath
	}
	return ""
}

// SplitList reads a setting people type by hand: space- or comma-separated.
func SplitList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool { return r == ' ' || r == ',' || r == '\n' || r == '\r' || r == '\t' })
}

// ValidMCPResource says whether a value can be this deployment's identifier:
// an absolute https address (http only for a local development host) ending
// in the MCP path, with no credentials, query or fragment that a client
// would carry into the authorization request.
func ValidMCPResource(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != MCPPath {
		return false
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	return u.Scheme == "https" || (u.Scheme == "http" && local)
}

// LooksLikeJWT is the cheap shape test that separates "a key that is wrong"
// from "a token": three non-empty dot-separated parts.
func LooksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}

// mcpProviders caches discovery per issuer. Discovery is a round trip to
// Keycloak and the JWKS behind it verifies every token; doing that per
// request would put Keycloak's latency in front of every MCP call. go-oidc
// refetches the key set on an unknown key id, so key rotation needs no
// invalidation here -- and that refetch is throttled below so a stream of
// forged tokens with made-up key ids cannot turn into a stream of requests
// at Keycloak.
type mcpProviders struct {
	mu       sync.Mutex
	byIssuer map[string]*oidc.Provider
}

func (a *Service) mcpProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	a.providers.mu.Lock()
	defer a.providers.mu.Unlock()
	if p := a.providers.byIssuer[issuer]; p != nil {
		return p, nil
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &jwksThrottle{base: http.DefaultTransport, issuer: issuer}}
	// Discovery must outlive this request: the provider keeps the context
	// for later key fetches.
	p, err := oidc.NewProvider(oidc.ClientContext(context.WithoutCancel(ctx), client), issuer)
	if err != nil {
		return nil, err
	}
	if a.providers.byIssuer == nil {
		a.providers.byIssuer = map[string]*oidc.Provider{}
	}
	a.providers.byIssuer[issuer] = p
	return p, nil
}

// InvalidateMCPProviders forgets cached discovery so a changed issuer is
// read on the next token rather than never.
func (a *Service) InvalidateMCPProviders() {
	a.providers.mu.Lock()
	a.providers.byIssuer = nil
	a.providers.mu.Unlock()
}

// jwksThrottle lets at most one key-set fetch a second reach the issuer.
// Discovery itself is not delayed. A legitimate rotation waits a second at
// most; a forged-token flood waits in line instead of becoming Keycloak's
// problem.
type jwksThrottle struct {
	base   http.RoundTripper
	issuer string
	mu     sync.Mutex
	next   time.Time
}

func (t *jwksThrottle) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() != strings.TrimSuffix(t.issuer, "/")+"/.well-known/openid-configuration" {
		t.mu.Lock()
		delay := time.Until(t.next)
		if delay < 0 {
			delay = 0
		}
		t.next = time.Now().Add(delay + time.Second)
		t.mu.Unlock()
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-timer.C:
			}
		}
	}
	return t.base.RoundTrip(r)
}

// mcpAccessClaims is what is read beyond what go-oidc verifies.
type mcpAccessClaims struct {
	Type         string `json:"typ"`
	ClientID     string `json:"azp"`
	Scope        string `json:"scope"`
	NotBefore    int64  `json:"nbf"`
	Confirmation any    `json:"cnf"`
}

// ErrMCPOAuthOff is what a token meets on an installation that does not take
// tokens: the same refusal a wrong key gets, so that nothing new is said.
var ErrMCPOAuthOff = errors.New("invalid API key")

// authenticateMCPToken turns a bearer access token into a session for /mcp,
// or says exactly why it will not. The messages are for the person at the
// MCP client and the administrator reading the log; the audience refusal in
// particular names what the token carried and what to put where, because
// that one message is how an operator finishes the Keycloak side.
func (a *Service) authenticateMCPToken(ctx context.Context, token string) (Session, error) {
	cfg := a.MCPOAuthConfig(ctx)
	if !cfg.Enabled {
		a.Store.Log(ctx, "INFO", "", "mcp_oauth", "sso token refused: feature off", map[string]any{"reason": cfg.Reason})
		return Session{}, ErrMCPOAuthOff
	}
	provider, err := a.mcpProvider(ctx, cfg.Issuer)
	if err != nil {
		a.Store.Log(ctx, "WARN", "", "mcp_oauth", "keycloak discovery failed", map[string]any{"issuer": cfg.Issuer, "error": err.Error()})
		return Session{}, errors.New("Keycloak 발급자 정보를 읽지 못해 SSO 토큰을 확인할 수 없습니다. 잠시 후 다시 시도하거나 관리자에게 알리세요.")
	}
	// Signature, issuer and expiry, with only asymmetric algorithms accepted:
	// an HS256 token signed with a public key would otherwise verify. The
	// audience is checked by hand below because more than one value is
	// acceptable and go-oidc compares one, and does not know azp.
	verified, err := provider.Verifier(&oidc.Config{SkipClientIDCheck: true,
		SupportedSigningAlgs: []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256, oidc.PS384, oidc.PS512}}).Verify(ctx, token)
	if err != nil {
		a.Store.Log(ctx, "INFO", "", "mcp_oauth", "sso token refused: verification", map[string]any{"error": err.Error()})
		return Session{}, errors.New("SSO 액세스 토큰이 유효하지 않습니다(서명·발급자·만료). 클라이언트에서 다시 로그인하세요.")
	}
	var claims mcpAccessClaims
	if err := verified.Claims(&claims); err != nil {
		return Session{}, errors.New("SSO 토큰의 내용을 읽을 수 없습니다.")
	}
	// An ID token proves a sign-in happened; it is not an API credential and
	// a client that sends one has the wrong token in hand.
	if strings.EqualFold(claims.Type, "ID") {
		return Session{}, errors.New("ID 토큰은 MCP 자격이 아닙니다. 액세스 토큰을 보내세요.")
	}
	if claims.NotBefore > 0 && time.Now().Unix() < claims.NotBefore {
		return Session{}, errors.New("SSO 액세스 토큰이 아직 유효하지 않습니다(nbf).")
	}
	// A token bound to a proof of possession (DPoP, mTLS) this server cannot
	// check would be accepted as a plain bearer, which is the thing the
	// binding exists to prevent.
	if claims.Confirmation != nil {
		return Session{}, errors.New("소지자 증명(cnf)이 묶인 토큰은 받지 않습니다.")
	}
	if strings.TrimSpace(verified.Subject) == "" {
		return Session{}, errors.New("SSO 토큰에 sub 가 없습니다.")
	}
	// Whom the token was minted for. A real Keycloak 26 puts `account` in
	// aud and the client in azp -- the client id is not in aud whatever an
	// ID token does -- so the administrator's list applies to both, and the
	// plain path needs no mapper: put the MCP client's id in the list.
	if !audienceAccepted(cfg, verified.Audience, claims.ClientID) {
		a.Store.Log(ctx, "INFO", "", "mcp_oauth", "sso token refused: audience", map[string]any{"aud": verified.Audience, "azp": claims.ClientID, "resource": cfg.Resource, "accepted": cfg.Audiences})
		return Session{}, fmt.Errorf("SSO 토큰이 이 서버를 위해 발급된 것이 아닙니다(aud %v, azp %q). 관리자가 허용 대상에 %q 를 더하거나, Keycloak 클라이언트의 Audience 매퍼에 %q 를 넣어야 합니다.",
			verified.Audience, claims.ClientID, claims.ClientID, cfg.Resource)
	}
	// The same lookup the web sign-in uses, without the provisioning half:
	// the account the web sign-in made for this claim, active, and nothing
	// else. A local account with the same username is not the same person.
	username := ""
	var all map[string]any
	if verified.Claims(&all) == nil {
		username, _ = all[cfg.UsernameClaim].(string)
	}
	if username == "" {
		username = verified.Subject
	}
	u, err := a.Store.GetUserByUsername(ctx, username)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (u.AuthSource != "oidc" || !u.Active)) {
		a.Store.Log(ctx, "INFO", "", "mcp_oauth", "sso token refused: no account", map[string]any{"username": username, "sub": verified.Subject})
		return Session{}, errors.New("이 SSO 계정은 SecCheck 에 등록되지 않았거나 비활성입니다. 먼저 웹으로 한 번 로그인하세요.")
	}
	if err != nil {
		return Session{}, err
	}
	return Session{ID: "sso-token", User: u, APIKey: true, OAuth: true, Scopes: grantedScopes(cfg.Scopes, claims.Scope)}, nil
}

// audienceAccepted is the binding: aud names this resource, or aud or azp is
// a client the administrator listed.
func audienceAccepted(cfg MCPOAuthConfig, aud []string, azp string) bool {
	for _, value := range aud {
		if value == cfg.Resource {
			return true
		}
		for _, accepted := range cfg.Audiences {
			if value == accepted {
				return true
			}
		}
	}
	for _, accepted := range cfg.Audiences {
		if azp != "" && azp == accepted {
			return true
		}
	}
	return false
}

// grantedScopes is the administrator's ceiling, narrowed by the token if the
// token speaks this service's vocabulary at all. A Keycloak token normally
// says "openid profile email", which is not about this service and leaves
// the ceiling as it is.
func grantedScopes(admin []string, tokenScope string) []string {
	spoken := map[string]bool{}
	for _, scope := range strings.Fields(tokenScope) {
		if scope == "read" || scope == "read:write" {
			spoken[scope] = true
		}
	}
	if len(spoken) == 0 {
		return append([]string(nil), admin...)
	}
	out := []string{}
	for _, scope := range admin {
		if spoken[scope] {
			out = append(out, scope)
		}
	}
	return out
}

// ValidateMCPSettings is what the settings screen is held to before the row
// is written, so that "on but silently off" is a state an operator has to
// work to reach. oidcCfg is the current web sign-in configuration.
func ValidateMCPSettings(m map[string]any, oidcCfg OIDCSettings, baseURL string) string {
	resource, _ := m["oauth_resource"].(string)
	if resource = strings.TrimSpace(resource); resource != "" && !ValidMCPResource(resource) {
		return "리소스 식별자는 https://<공개 주소>/mcp 형식이어야 합니다(인증정보·쿼리 없이)."
	}
	audience, _ := m["oauth_audience"].(string)
	for _, id := range SplitList(audience) {
		if len(id) > 128 || strings.ContainsAny(id, "\"\\<>") {
			return "허용 대상의 클라이언트 ID 형식이 올바르지 않습니다."
		}
	}
	scopes, _ := m["oauth_scopes"].(string)
	for _, scope := range SplitList(scopes) {
		if scope != "read" && scope != "read:write" {
			return "SSO 토큰 범위는 read 또는 read:write 만 쓸 수 있습니다."
		}
	}
	if enabled, _ := m["oauth_enabled"].(bool); enabled {
		if !oidcCfg.Enabled || strings.TrimSpace(oidcCfg.Issuer) == "" {
			return "MCP SSO 를 켜려면 먼저 Keycloak OIDC 를 켜고 Issuer URL 을 저장하세요."
		}
		if MCPResource(resource, baseURL) == "" {
			return "MCP SSO 를 켜려면 리소스 식별자를 적거나 메일 탭의 서비스 주소를 채우세요."
		}
	}
	return ""
}
