package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeProvider stands in for Keycloak far enough for the sign-in to start:
// discovery answers, and the authorization endpoint is where the browser is
// sent. What comes back is the test's to decide.
func fakeProvider(t *testing.T) *httptest.Server {
	t.Helper()
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": idp.URL, "authorization_endpoint": idp.URL + "/auth",
			"token_endpoint": idp.URL + "/token", "userinfo_endpoint": idp.URL + "/userinfo",
		})
	}))
	t.Cleanup(idp.Close)
	return idp
}

// configureSSO turns OIDC on against the fake provider, with or without
// silent sign-in.
func (h *harness) configureSSO(issuer string, autoLogin bool) {
	h.t.Helper()
	cfg := map[string]any{"enabled": true, "issuer": issuer, "client_id": "seccheck", "redirect_url": h.server.URL + "/api/v1/auth/oidc/callback",
		"scopes": []string{"openid"}, "username_claim": "preferred_username", "default_role": "REQUESTER", "auto_login": autoLogin}
	raw, _ := json.Marshal(cfg)
	if _, err := h.db.Pool.Exec(context.Background(), `UPDATE settings SET value_json=$1 WHERE key='oidc'`, raw); err != nil {
		h.t.Fatal(err)
	}
}

// browse follows nothing, so each redirect can be read.
func browse(t *testing.T, target string) *http.Response {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

// startSSO begins a sign-in and returns the provider address the browser was
// sent to.
func startSSO(t *testing.T, h *harness, query string) *url.URL {
	t.Helper()
	res := browse(t, h.server.URL+"/api/v1/auth/oidc/start?"+query)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("starting SSO returned %d", res.StatusCode)
	}
	target, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// prompt=none asks the provider to answer from a session it already holds
// and never draw a screen. Whether the browser may ask that way is the
// administrator's call, so a ?prompt=none somebody typed into the address
// bar is dropped unless auto_login is on.
func TestSilentSignInIsOnlyAskedForWhenTheAdministratorTurnedItOn(t *testing.T) {
	h := newHarness(t)
	idp := fakeProvider(t)

	h.configureSSO(idp.URL, false)
	public := browse(t, h.server.URL+"/api/v1/public/config")
	var config map[string]any
	_ = json.NewDecoder(public.Body).Decode(&config)
	if config["oidc_auto_login"] != false {
		t.Errorf("the public config advertises auto login as %v with the setting off", config["oidc_auto_login"])
	}
	target := startSSO(t, h, "prompt=none&return_to=%2Freviews%2Fabc")
	if !strings.HasPrefix(target.String(), idp.URL+"/auth?") {
		t.Fatalf("the browser was sent to %s, not the provider", target)
	}
	if target.Query().Has("prompt") {
		t.Errorf("auto_login is off and the request still asked for prompt=%s", target.Query().Get("prompt"))
	}

	h.configureSSO(idp.URL, true)
	public = browse(t, h.server.URL+"/api/v1/public/config")
	_ = json.NewDecoder(public.Body).Decode(&config)
	if config["oidc_auto_login"] != true {
		t.Errorf("the public config advertises auto login as %v with the setting on", config["oidc_auto_login"])
	}
	target = startSSO(t, h, "prompt=none&return_to=%2Freviews%2Fabc")
	if target.Query().Get("prompt") != "none" {
		t.Errorf("auto_login is on and the request did not ask for prompt=none: %s", target.RawQuery)
	}
	// The ordinary button still signs in with a screen.
	target = startSSO(t, h, "return_to=%2Freviews%2Fabc")
	if target.Query().Has("prompt") {
		t.Errorf("a plain sign-in asked for prompt=%s", target.Query().Get("prompt"))
	}

	// With SSO off altogether the public config must not advertise auto login
	// either, or the browser would go and ask a provider that is not there.
	if _, err := h.db.Pool.Exec(context.Background(), `UPDATE settings SET value_json=value_json||'{"enabled":false}' WHERE key='oidc'`); err != nil {
		t.Fatal(err)
	}
	public = browse(t, h.server.URL+"/api/v1/public/config")
	_ = json.NewDecoder(public.Body).Decode(&config)
	if config["oidc_auto_login"] != false {
		t.Errorf("SSO is off and the public config still advertises auto login as %v", config["oidc_auto_login"])
	}
}

// A provider with no session answers prompt=none with login_required. That is
// the ordinary answer for a signed-out person, and the browser must be told
// not to ask again: it lands on the login screen with a marker in the
// address, keeping the place it was going.
func TestARefusedSilentAttemptLandsOnTheLoginScreenMarked(t *testing.T) {
	h := newHarness(t)
	idp := fakeProvider(t)
	h.configureSSO(idp.URL, true)

	callback := func(query string) string {
		res := browse(t, h.server.URL+"/api/v1/auth/oidc/callback?"+query)
		if res.StatusCode != http.StatusFound {
			t.Fatalf("the callback answered %d", res.StatusCode)
		}
		return res.Header.Get("Location")
	}
	stateOf := func(target *url.URL) string { return target.Query().Get("state") }

	silent := startSSO(t, h, "prompt=none&return_to=%2Freviews%2Fabc%3Fitem%3D7")
	for _, refusal := range []string{"login_required", "interaction_required", "consent_required"} {
		attempt := silent
		if refusal != "login_required" {
			attempt = startSSO(t, h, "prompt=none&return_to=%2Freviews%2Fabc%3Fitem%3D7")
		}
		if got, want := callback("error="+refusal+"&state="+url.QueryEscape(stateOf(attempt))), "/login?sso=none&return_to=%2Freviews%2Fabc%3Fitem%3D7"; got != want {
			t.Errorf("after %s the browser was sent to %q, want %q", refusal, got, want)
		}
	}
	// The state is spent: a second callback with it is no longer silent.
	if got := callback("error=login_required&state=" + url.QueryEscape(stateOf(silent))); got != "/login?error=login_required" {
		t.Errorf("a spent state was still read as a silent attempt: %q", got)
	}
	var left int
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM oidc_states`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d sign-in states were left behind after the provider answered", left)
	}

	// Going home needs no return_to in the marker.
	home := startSSO(t, h, "prompt=none")
	if got := callback("error=login_required&state=" + url.QueryEscape(stateOf(home))); got != "/login?sso=none" {
		t.Errorf("a refused attempt from the home page was sent to %q", got)
	}

	// A refusal that is not about a missing session is a real error, and the
	// login screen shows it as one.
	denied := startSSO(t, h, "prompt=none")
	if got := callback("error=access_denied&state=" + url.QueryEscape(stateOf(denied))); got != "/login?error=access_denied" {
		t.Errorf("access_denied on a silent attempt was sent to %q", got)
	}

	// A sign-in that showed a screen and still came back refused is an error,
	// not a silent refusal, whatever the code.
	shown := startSSO(t, h, "return_to=%2Freviews%2Fabc")
	if got := callback("error=login_required&state=" + url.QueryEscape(stateOf(shown))); got != "/login?error=login_required" {
		t.Errorf("a refused ordinary sign-in was sent to %q", got)
	}
	// And a callback with no state at all is not one either.
	if got := callback("error=login_required"); got != "/login?error=login_required" {
		t.Errorf("an error with no state was sent to %q", got)
	}
}

// return_to is carried through the provider and back, which makes it a place
// this service could be made to send people. Only a path inside the service
// survives the trip.
func TestTheReturnAddressStaysInsideTheService(t *testing.T) {
	h := newHarness(t)
	idp := fakeProvider(t)
	h.configureSSO(idp.URL, true)

	for _, outside := range []string{"https://evil.example/", "//evil.example/x", "/\\evil.example", "reviews/abc", "/x\r\nSet-Cookie:a=b"} {
		attempt := startSSO(t, h, "prompt=none&return_to="+url.QueryEscape(outside))
		res := browse(t, h.server.URL+"/api/v1/auth/oidc/callback?error=login_required&state="+url.QueryEscape(attempt.Query().Get("state")))
		if got := res.Header.Get("Location"); got != "/login?sso=none" {
			t.Errorf("return_to=%q came back as %q", outside, got)
		}
	}
}
