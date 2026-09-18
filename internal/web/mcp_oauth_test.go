package web_test

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// MCP 를 개인 키 없이 Keycloak 토큰으로.
//
// The authorization flow itself -- PKCE, the redirect, the code exchange --
// is Keycloak's and the client's. What is this server's is the resource-server
// half, and that is what these tests hold it to: it says where the
// authorization server is, it turns a 401 into a pointer there, and it
// accepts exactly the tokens that server issued for this resource, for a
// person SecCheck already knows, with the powers a key would have and no
// more. The identity provider is a real key pair behind a discovery document
// and a JWKS, so the signature check is the one production runs.

// signingIDP serves discovery and a JWKS for one RSA key, and signs tokens
// with it.
type signingIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newSigningIDP(t *testing.T) *signingIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &signingIDP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": idp.server.URL, "authorization_endpoint": idp.server.URL + "/auth",
			"token_endpoint": idp.server.URL + "/token", "userinfo_endpoint": idp.server.URL + "/userinfo",
			"jwks_uri": idp.server.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// sign produces a JWT with the given header and claims. alg RS256 uses the
// realm key; HS256 signs with the realm's public modulus as the secret, which
// is the classic confusion attack a verifier must not fall for; none carries
// an arbitrary third part, because an empty one is not even the shape of a
// token and never reaches the verifier.
func (idp *signingIDP) sign(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	if header["alg"] == nil {
		header["alg"] = "RS256"
	}
	if header["kid"] == nil {
		header["kid"] = "test"
	}
	signingInput := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signingInput))
	var signature []byte
	switch header["alg"] {
	case "RS256":
		var err error
		signature, err = rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
	case "HS256":
		mac := hmac.New(sha256.New, idp.key.Public().(*rsa.PublicKey).N.Bytes())
		mac.Write([]byte(signingInput))
		signature = mac.Sum(nil)
	case "none":
		signature = []byte("not-a-signature")
	default:
		t.Fatalf("unsupported alg %v", header["alg"])
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// accessToken is what Keycloak hands an MCP client after the person signed
// in: issued by the realm, for an audience, typ Bearer, an hour to live.
func (idp *signingIDP) accessToken(t *testing.T, audience any, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": idp.server.URL, "aud": audience, "sub": "subject-mcp",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"typ": "Bearer", "preferred_username": "ssomember", "scope": "openid profile email",
	}
	for k, v := range extra {
		claims[k] = v
	}
	return idp.sign(t, map[string]any{"typ": "JWT"}, claims)
}

const listTools = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

// mcpWith sends one MCP call with the given bearer.
func mcpWith(t *testing.T, h *harness, bearer string) response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/mcp", strings.NewReader(listTools))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return (&client{h: h}).send(req)
}

// restWith sends one REST read with the given bearer.
func restWith(t *testing.T, h *harness, bearer string) response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	return (&client{h: h}).send(req)
}

// refusalLogged is what an administrator does with "my token was refused":
// takes the X-Request-ID off the response and looks for the mcp_oauth entry
// under it. It returns the latest mcp_oauth entry, holds its request id to
// the response's, and fails when the refusal left nothing behind.
func refusalLogged(t *testing.T, h *harness, res response) (message string, fields map[string]any) {
	t.Helper()
	requestID := res.raw.Header.Get("X-Request-ID")
	if requestID == "" {
		t.Fatal("the response carries no X-Request-ID")
	}
	var logged string
	var raw []byte
	err := h.db.Pool.QueryRow(context.Background(), `SELECT message, request_id, fields FROM application_logs
		WHERE component='mcp_oauth' ORDER BY id DESC LIMIT 1`).Scan(&message, &logged, &raw)
	if err != nil {
		t.Fatalf("the refusal left no mcp_oauth log entry: %v", err)
	}
	if logged != requestID {
		t.Fatalf("the latest mcp_oauth entry (%q) is under request %q, not this response's %q", message, logged, requestID)
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("the log entry's fields are not an object: %v", err)
	}
	return message, fields
}

func metadata(t *testing.T, h *harness, path string) *http.Response {
	t.Helper()
	res, err := http.Get(h.server.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

// ssoUser is an account the web sign-in made: auth_source oidc, no password.
func (h *harness) ssoUser(username string, active bool) string {
	h.t.Helper()
	id := username + "-id"
	if _, err := h.db.Pool.Exec(context.Background(), `INSERT INTO users(id,username,display_name,email,auth_source,active) VALUES($1,$2,$2,$3,'oidc',$4)`, id, username, username+"@example.test", active); err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(context.Background(), `INSERT INTO user_roles(user_id,role_code) VALUES($1,'REQUESTER')`, id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

// serviceAddress fills the mail tab's service address, which is where the
// resource identifier comes from when none is written explicitly.
func (h *harness) serviceAddress(base string) {
	h.t.Helper()
	if _, err := h.db.Pool.Exec(context.Background(), `UPDATE settings SET value_json = value_json || jsonb_build_object('base_url',$1::text) WHERE key='mail'`, base); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) apiKey(admin *client) string {
	h.t.Helper()
	created := admin.do(http.MethodPost, "/api/v1/me/api-keys", map[string]any{"name": "mcp", "scopes": []string{"read"}})
	if created.status != http.StatusCreated {
		h.t.Fatalf("issue key: %d %s", created.status, created.body)
	}
	token, _ := created.json()["token"].(string)
	if !strings.HasPrefix(token, "sck_") {
		h.t.Fatalf("the key %q does not carry the prefix the bearer split relies on", token)
	}
	return token
}

const publicAddress = "https://seccheck.example.test"

// guards: protectedResourceMetadata, mcpChallenge, Authenticate
func TestAFreshInstallationTakesNoTokensAndSaysNothingNew(t *testing.T) {
	h := newHarness(t)
	idp := newSigningIDP(t)
	admin := h.login(adminOf(h))

	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		if res := metadata(t, h, path); res.StatusCode != http.StatusNotFound {
			t.Errorf("%s is served with MCP SSO off: %d", path, res.StatusCode)
		}
	}
	noBearer := mcpWith(t, h, "")
	if noBearer.status != http.StatusUnauthorized || noBearer.raw.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("a refusal pointed at an authorization server that is not configured: %d %q", noBearer.status, noBearer.raw.Header.Get("WWW-Authenticate"))
	}
	// A token on an installation without SSO is refused exactly like a
	// wrong key: same status, same words.
	wrongKey := mcpWith(t, h, "sck_not-a-real-key")
	token := mcpWith(t, h, idp.accessToken(t, publicAddress+"/mcp", nil))
	if token.status != http.StatusUnauthorized || token.body != wrongKey.body {
		t.Errorf("a token was refused differently from a wrong key:\n%d %s\n%d %s", token.status, token.body, wrongKey.status, wrongKey.body)
	}
	// The client is told nothing, so the log is the only place the reason
	// lives: the entry under this response's request id says the feature is
	// off and why.
	if message, fields := refusalLogged(t, h, token); message != "sso token refused: feature off" || !strings.Contains(fmt.Sprint(fields["reason"]), "mcp.oauth.enabled") {
		t.Errorf("the feature-off refusal is logged as %q %v", message, fields)
	}
	// And the key itself works as it always has.
	if res := mcpWith(t, h, h.apiKey(admin)); res.status != http.StatusOK || !strings.Contains(res.body, "seccheck.dashboard") {
		t.Errorf("an API key no longer opens /mcp: %d %s", res.status, res.body)
	}
	info := admin.do(http.MethodGet, "/api/v1/integrations", nil).json()
	if oauth, _ := info["mcp_oauth"].(map[string]any); oauth["enabled"] != false || oauth["metadata_url"] != nil {
		t.Errorf("the console is told SSO is available: %v", info["mcp_oauth"])
	}
}

// guards: updateSetting, ValidateMCPSettings
func TestTheSwitchCannotBeTurnedOnWithoutWhatItNeeds(t *testing.T) {
	h := newHarness(t)
	idp := newSigningIDP(t)
	admin := h.login(adminOf(h))
	save := func(body map[string]any) response {
		return admin.do(http.MethodPut, "/api/v1/admin/settings/mcp", body)
	}
	on := map[string]any{"oauth_enabled": true, "oauth_resource": "", "oauth_audience": "claude-mcp", "oauth_scopes": "read"}

	if res := save(on); res.status != http.StatusUnprocessableEntity || !strings.Contains(res.body, "Keycloak OIDC") {
		t.Errorf("turned on without an issuer: %d %s", res.status, res.body)
	}
	h.configureSSO(idp.server.URL, false)
	if res := save(on); res.status != http.StatusUnprocessableEntity || !strings.Contains(res.body, "리소스 식별자") {
		t.Errorf("turned on without a resource identifier: %d %s", res.status, res.body)
	}
	for _, bad := range []map[string]any{
		{"oauth_enabled": false, "oauth_resource": "http://seccheck.example.test/mcp"},
		{"oauth_enabled": false, "oauth_resource": "https://seccheck.example.test/"},
		{"oauth_enabled": false, "oauth_resource": "https://user:pw@seccheck.example.test/mcp"},
		{"oauth_enabled": false, "oauth_scopes": "admin"},
		{"oauth_enabled": false, "oauth_audience": "claude\"mcp"},
	} {
		if res := save(bad); res.status != http.StatusUnprocessableEntity {
			t.Errorf("%v was accepted: %d %s", bad, res.status, res.body)
		}
	}
	explicit := map[string]any{"oauth_enabled": true, "oauth_resource": publicAddress + "/mcp", "oauth_audience": "", "oauth_scopes": ""}
	if res := save(explicit); res.status != http.StatusOK {
		t.Fatalf("an explicit resource identifier was refused: %d %s", res.status, res.body)
	}
	if res := metadata(t, h, "/.well-known/oauth-protected-resource/mcp"); res.StatusCode != http.StatusOK {
		t.Errorf("metadata after enabling: %d", res.StatusCode)
	}
	// The switch is written to the audit chain like every other setting.
	var n int
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE event_type='UPDATE_SETTING' AND target_id='mcp'`).Scan(&n); err != nil || n == 0 {
		t.Errorf("turning MCP SSO on left no audit event (%d, %v)", n, err)
	}
}

// guards: protectedResourceMetadata, mcpChallenge
func TestARefusedMCPClientIsToldWhereToSignIn(t *testing.T) {
	h := newHarness(t)
	idp := newSigningIDP(t)
	admin := h.login(adminOf(h))
	h.configureSSO(idp.server.URL, false)
	h.serviceAddress(publicAddress)
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/mcp", map[string]any{"oauth_enabled": true, "oauth_resource": "", "oauth_audience": "claude-mcp", "oauth_scopes": "read"}); res.status != http.StatusOK {
		t.Fatalf("enable: %d %s", res.status, res.body)
	}

	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		res := metadata(t, h, path)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", path, res.StatusCode)
		}
		if res.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s is not readable cross-origin: %q", path, res.Header.Get("Access-Control-Allow-Origin"))
		}
		var doc struct {
			Resource string   `json:"resource"`
			Servers  []string `json:"authorization_servers"`
			Methods  []string `json:"bearer_methods_supported"`
			Scopes   []string `json:"scopes_supported"`
			Error    any      `json:"error"`
		}
		if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if doc.Resource != publicAddress+"/mcp" {
			t.Errorf("%s resource %q, want the service address plus the MCP path", path, doc.Resource)
		}
		if len(doc.Servers) != 1 || doc.Servers[0] != idp.server.URL {
			t.Errorf("%s authorization servers %v, want the web sign-in's issuer", path, doc.Servers)
		}
		if len(doc.Methods) != 1 || doc.Methods[0] != "header" || len(doc.Scopes) != 1 || doc.Scopes[0] != "read" {
			t.Errorf("%s methods %v scopes %v", path, doc.Methods, doc.Scopes)
		}
		if doc.Error != nil {
			t.Errorf("%s is wrapped in the API envelope: %v", path, doc.Error)
		}
	}

	// The 401 now carries the pointer, and says the bearer was bad when
	// there was one.
	want := `resource_metadata="` + publicAddress + `/.well-known/oauth-protected-resource/mcp"`
	noBearer := mcpWith(t, h, "")
	if header := noBearer.raw.Header.Get("WWW-Authenticate"); noBearer.status != http.StatusUnauthorized || !strings.HasPrefix(header, "Bearer ") || !strings.Contains(header, want) || strings.Contains(header, "invalid_token") {
		t.Errorf("no bearer: %d %q", noBearer.status, header)
	}
	badBearer := mcpWith(t, h, "sck_wrong")
	if header := badBearer.raw.Header.Get("WWW-Authenticate"); !strings.Contains(header, want) || !strings.Contains(header, `error="invalid_token"`) {
		t.Errorf("bad bearer: %q", header)
	}
	// A REST 401 does not: browsers and other clients would go somewhere
	// they have no business.
	if header := restWith(t, h, "sck_wrong").raw.Header.Get("WWW-Authenticate"); header != "" {
		t.Errorf("a REST refusal carries the MCP challenge: %q", header)
	}
	info := admin.do(http.MethodGet, "/api/v1/integrations", nil).json()
	oauth, _ := info["mcp_oauth"].(map[string]any)
	if oauth["enabled"] != true || oauth["metadata_url"] != publicAddress+"/.well-known/oauth-protected-resource/mcp" || oauth["authorization_server"] != idp.server.URL {
		t.Errorf("the console is not told how to connect: %v", oauth)
	}
}

// guards: authenticateMCPToken, audienceAccepted
func TestAKeycloakTokenOpensMCPForAnAccountSecCheckKnows(t *testing.T) {
	h := newHarness(t)
	idp := newSigningIDP(t)
	admin := h.login(adminOf(h))
	h.configureSSO(idp.server.URL, false)
	h.serviceAddress(publicAddress)
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/mcp", map[string]any{"oauth_enabled": true, "oauth_resource": "", "oauth_audience": "claude-mcp", "oauth_scopes": "read"}); res.status != http.StatusOK {
		t.Fatalf("enable: %d %s", res.status, res.body)
	}
	memberID := h.ssoUser("ssomember", true)

	// The formal path: an Audience mapper put the resource in aud.
	opened := mcpWith(t, h, idp.accessToken(t, publicAddress+"/mcp", nil))
	if opened.status != http.StatusOK || !strings.Contains(opened.body, "seccheck.dashboard") {
		t.Fatalf("a token for this resource was refused: %d %s", opened.status, opened.body)
	}
	// The plain path: a real Keycloak 26 puts `account` in aud and the client
	// in azp, and the administrator listed that client.
	viaClient := mcpWith(t, h, idp.accessToken(t, "account", map[string]any{"azp": "claude-mcp"}))
	if viaClient.status != http.StatusOK {
		t.Errorf("a token issued to the listed client was refused: %d %s", viaClient.status, viaClient.body)
	}
	// aud as a bare string, and the listed client in aud rather than azp.
	if res := mcpWith(t, h, idp.accessToken(t, "claude-mcp", map[string]any{"azp": "claude-mcp"})); res.status != http.StatusOK {
		t.Errorf("a token with the listed client in aud was refused: %d %s", res.status, res.body)
	}
	// A token issued to some other application in the same realm is not ours,
	// however real its signature -- and the refusal says what it saw and what
	// to write where.
	other := mcpWith(t, h, idp.accessToken(t, "account", map[string]any{"azp": "some-other-app"}))
	if other.status != http.StatusUnauthorized {
		t.Fatalf("a token issued to another application opened MCP: %d %s", other.status, other.body)
	}
	message, _ := other.json()["error"].(map[string]any)["message"].(string)
	for _, want := range []string{"aud [account]", `azp "some-other-app"`, `허용 대상에 "some-other-app"`, "Audience 매퍼에 \"" + publicAddress + "/mcp\""} {
		if !strings.Contains(message, want) {
			t.Errorf("the audience refusal does not say %q: %s", want, message)
		}
	}
	if header := other.raw.Header.Get("WWW-Authenticate"); !strings.Contains(header, `error="invalid_token"`) {
		t.Errorf("a refused token got no challenge: %q", header)
	}

	// A tool call through the token is audited as that person.
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"seccheck.dashboard","arguments":{}}}`
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/mcp", strings.NewReader(call))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+idp.accessToken(t, publicAddress+"/mcp", nil))
	if res := (&client{h: h}).send(req); res.status != http.StatusOK || strings.Contains(res.body, `"isError"`) {
		t.Errorf("a tool call through the token failed: %d %s", res.status, res.body)
	}
	var calls int
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE event_type='MCP_TOOL_CALL' AND user_id=$1`, memberID).Scan(&calls); err != nil || calls != 1 {
		t.Errorf("the tool call is not on the chain as the SSO member: %d %v", calls, err)
	}

	// The token opens /mcp and nothing else.
	if res := restWith(t, h, idp.accessToken(t, publicAddress+"/mcp", nil)); res.status != http.StatusUnauthorized {
		t.Errorf("a valid token opened a REST path: %d %s", res.status, res.body)
	}
	// And the key still works beside it.
	if res := mcpWith(t, h, h.apiKey(admin)); res.status != http.StatusOK {
		t.Errorf("an API key no longer opens /mcp with SSO on: %d %s", res.status, res.body)
	}
}

// guards: authenticateMCPToken
func TestTokensThatAreNotThisServersAreRefused(t *testing.T) {
	h := newHarness(t)
	idp := newSigningIDP(t)
	stranger := newSigningIDP(t)
	admin := h.login(adminOf(h))
	h.configureSSO(idp.server.URL, false)
	h.serviceAddress(publicAddress)
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/mcp", map[string]any{"oauth_enabled": true, "oauth_resource": "", "oauth_audience": "", "oauth_scopes": "read"}); res.status != http.StatusOK {
		t.Fatalf("enable: %d %s", res.status, res.body)
	}
	h.ssoUser("ssomember", true)
	resource := publicAddress + "/mcp"
	unsigned := map[string]any{"iss": idp.server.URL, "aud": resource, "sub": "subject-mcp", "exp": time.Now().Add(time.Hour).Unix(), "typ": "Bearer", "preferred_username": "ssomember"}

	// Each refusal is a 401 to the client and one mcp_oauth entry under the
	// response's request id whose message or error field names the cause --
	// which of signature, issuer, expiry, nbf and so on it was -- so that an
	// administrator with the request id can tell them apart.
	cases := []struct{ name, token, cause string }{
		{"expired", idp.accessToken(t, resource, map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}), "expired"},
		{"not yet valid", idp.accessToken(t, resource, map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}), "nbf"},
		{"other issuer", idp.accessToken(t, resource, map[string]any{"iss": stranger.server.URL}), "different provider"},
		{"other key", stranger.accessToken(t, resource, map[string]any{"iss": idp.server.URL}), "signature"},
		{"ID token", idp.accessToken(t, resource, map[string]any{"typ": "ID"}), "id_token"},
		{"bound token", idp.accessToken(t, resource, map[string]any{"cnf": map[string]any{"jkt": "thumbprint"}}), "cnf"},
		{"no subject", idp.accessToken(t, resource, map[string]any{"sub": ""}), "no_sub"},
		{"no audience", idp.accessToken(t, "account", nil), "audience"},
		{"HS256", idp.sign(t, map[string]any{"alg": "HS256", "typ": "JWT"}, unsigned), `"HS256"`},
		{"alg none", idp.sign(t, map[string]any{"alg": "none", "typ": "JWT"}, unsigned), `"none"`},
		{"unknown person", idp.accessToken(t, resource, map[string]any{"preferred_username": "nobody", "sub": "subject-nobody"}), "no account"},
	}
	for _, c := range cases {
		res := mcpWith(t, h, c.token)
		if res.status != http.StatusUnauthorized {
			t.Errorf("%s token opened MCP: %d %s", c.name, res.status, res.body)
			continue
		}
		message, fields := refusalLogged(t, h, res)
		if !strings.HasPrefix(message, "sso token refused: ") {
			t.Errorf("%s token: the log entry is not a refusal: %q", c.name, message)
		}
		if detail, _ := fields["error"].(string); !strings.Contains(message, c.cause) && !strings.Contains(detail, c.cause) {
			t.Errorf("%s token: neither the message %q nor the error %q names the cause %q", c.name, message, detail, c.cause)
		}
		if strings.Contains(message, c.token) || strings.Contains(fmt.Sprint(fields), c.token) {
			t.Errorf("%s token: the log entry holds the token itself", c.name)
		}
	}
	// alg=none with the signature part left empty is not even the shape of a
	// token, so it never reaches the verifier: it is refused as a wrong key.
	unsignedEmpty := strings.TrimSuffix(idp.sign(t, map[string]any{"alg": "none", "typ": "JWT"}, unsigned), "."+base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))) + "."
	if res, wrongKey := mcpWith(t, h, unsignedEmpty), mcpWith(t, h, "sck_wrong"); res.status != http.StatusUnauthorized || res.body != wrongKey.body {
		t.Errorf("alg=none with an empty signature: %d %s", res.status, res.body)
	}
	// The sanity check on the harness: the same shape with nothing wrong opens.
	if res := mcpWith(t, h, idp.accessToken(t, resource, nil)); res.status != http.StatusOK {
		t.Fatalf("the reference token was refused, so the refusals above prove nothing: %d %s", res.status, res.body)
	}
}

// guards: authenticateMCPToken, usernameFromClaims
func TestATokenFindsTheAccountTheWebSignInMadeWhateverTheClaimSettingHolds(t *testing.T) {
	h := newHarness(t)
	idp := newSigningIDP(t)
	admin := h.login(adminOf(h))
	h.configureSSO(idp.server.URL, false)
	h.serviceAddress(publicAddress)
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/mcp", map[string]any{"oauth_enabled": true, "oauth_resource": "", "oauth_audience": "", "oauth_scopes": "read"}); res.status != http.StatusOK {
		t.Fatalf("enable: %d %s", res.status, res.body)
	}
	resource := publicAddress + "/mcp"
	// With username_claim left blank the web sign-in names the account after
	// sub. The token has to find that account, not one named after
	// preferred_username that the web sign-in never made.
	if _, err := h.db.Pool.Exec(context.Background(), `UPDATE settings SET value_json = value_json || '{"username_claim":""}'::jsonb WHERE key='oidc'`); err != nil {
		t.Fatal(err)
	}
	h.ssoUser("subject-mcp", true)
	if res := mcpWith(t, h, idp.accessToken(t, resource, nil)); res.status != http.StatusOK || !strings.Contains(res.body, "seccheck.dashboard") {
		t.Errorf("with username_claim blank the account named after sub was not opened: %d %s", res.status, res.body)
	}
	// And the account preferred_username would have named is not.
	h.ssoUser("ssomember", true)
	if res := mcpWith(t, h, idp.accessToken(t, resource, map[string]any{"sub": "subject-other"})); res.status != http.StatusUnauthorized {
		t.Errorf("with username_claim blank the token was matched by preferred_username: %d %s", res.status, res.body)
	}
	// A claim named in the setting but missing from the token also falls
	// back to sub, the way the web sign-in does.
	if _, err := h.db.Pool.Exec(context.Background(), `UPDATE settings SET value_json = value_json || '{"username_claim":"employee_id"}'::jsonb WHERE key='oidc'`); err != nil {
		t.Fatal(err)
	}
	if res := mcpWith(t, h, idp.accessToken(t, resource, nil)); res.status != http.StatusOK {
		t.Errorf("with a claim the token lacks, sub was not used: %d %s", res.status, res.body)
	}
}

// guards: authenticateMCPToken
func TestATokenNeverMakesAnAccountOrWakesOne(t *testing.T) {
	h := newHarness(t)
	idp := newSigningIDP(t)
	admin := h.login(adminOf(h))
	h.configureSSO(idp.server.URL, false)
	h.serviceAddress(publicAddress)
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/mcp", map[string]any{"oauth_enabled": true, "oauth_resource": "", "oauth_audience": "", "oauth_scopes": "read"}); res.status != http.StatusOK {
		t.Fatalf("enable: %d %s", res.status, res.body)
	}
	resource := publicAddress + "/mcp"
	ctx := context.Background()
	count := func() int {
		var n int
		if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()

	// Nobody by that name: refused, told to sign in on the web first, and
	// no row appears.
	unknown := mcpWith(t, h, idp.accessToken(t, resource, map[string]any{"preferred_username": "newcomer", "sub": "subject-new"}))
	if unknown.status != http.StatusUnauthorized || !strings.Contains(unknown.body, "웹으로") {
		t.Errorf("an unknown person: %d %s", unknown.status, unknown.body)
	}
	// A local account with the same username is not the same person.
	h.user("localsame", "REQUESTER")
	if res := mcpWith(t, h, idp.accessToken(t, resource, map[string]any{"preferred_username": "localsame"})); res.status != http.StatusUnauthorized {
		t.Errorf("a token bound to a local account by username: %d %s", res.status, res.body)
	}
	// A disabled SSO account stays disabled.
	h.ssoUser("leaver", false)
	if res := mcpWith(t, h, idp.accessToken(t, resource, map[string]any{"preferred_username": "leaver"})); res.status != http.StatusUnauthorized {
		t.Errorf("a disabled account was opened by a token: %d %s", res.status, res.body)
	}
	if got := count(); got != before+2 {
		t.Errorf("a token created an account: %d users, expected %d", got, before+2)
	}
	// The token's roles are not read: the member is a requester here whatever
	// the token claims, so a reviewer-only tool is refused.
	h.ssoUser("ssomember", true)
	call := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"seccheck.review_report","arguments":{}}}`
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/mcp", strings.NewReader(call))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+idp.accessToken(t, resource, map[string]any{"realm_access": map[string]any{"roles": []string{"SYSTEM_ADMIN", "SECURITY_REVIEWER"}}}))
	if res := (&client{h: h}).send(req); !strings.Contains(res.body, "권한이 없습니다") {
		t.Errorf("a role claim in the token was honoured: %d %s", res.status, res.body)
	}
}
