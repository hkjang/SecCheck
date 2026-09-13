package analytics

import (
	"strings"
	"testing"
	"time"
)

func boolPtr(v bool) *bool { return &v }

func TestOffByDefaultAndNeverOnNonPages(t *testing.T) {
	var off Config
	if off.Active("/") || off.Snippet("n") != "" {
		t.Fatal("a zero configuration must inject nothing")
	}
	on := Config{Enabled: true, Provider: ProviderMomento, MomentoURL: "https://momento.internal", MomentoSiteID: "sc"}
	if !on.Active("/") || !on.Active("/reviews/1") {
		t.Fatal("an enabled configuration must be active on pages")
	}
	for _, path := range []string{"/api/v1/me", "/api", "/mcp", "/health", "/ready", "/metrics", "/momento/tracker.js", "/momento"} {
		if on.Active(path) {
			t.Errorf("%s is not a page and must not carry the snippet", path)
		}
	}
	if on.Active("/admin/settings") {
		t.Fatal("administrative screens are excluded unless include_admin is set")
	}
	on.IncludeAdmin = true
	if !on.Active("/admin/settings") {
		t.Fatal("include_admin must reach the administrative screens")
	}
}

func TestMomentoSnippetGoesThroughTheProxyByDefault(t *testing.T) {
	c := Config{Enabled: true, Provider: ProviderMomento, MomentoURL: "https://momento.internal/", MomentoSiteID: "sec-check"}
	snippet := c.Snippet("abc")
	for _, want := range []string{`src="/momento/tracker.js"`, `data-endpoint="/momento"`, `data-site-id="sec-check"`, `nonce="abc"`, `data-environment="prd"`, `data-contract-version="1"`} {
		if !strings.Contains(snippet, want) {
			t.Errorf("proxied momento snippet lacks %s: %s", want, snippet)
		}
	}
	if strings.Contains(snippet, "momento.internal") {
		t.Fatalf("the proxied snippet must not name the collector: %s", snippet)
	}
	scripts, connects, _ := c.PolicySources()
	if len(scripts) != 0 || len(connects) != 0 {
		t.Fatalf("the proxied setup must add no external origin to the policy, got %v %v", scripts, connects)
	}

	c.MomentoProxy = boolPtr(false)
	snippet = c.Snippet("abc")
	if !strings.Contains(snippet, `src="https://momento.internal/tracker.js"`) || strings.Contains(snippet, "data-endpoint") {
		t.Fatalf("the direct snippet must load from the collector: %s", snippet)
	}
	scripts, connects, images := c.PolicySources()
	for _, group := range [][]string{scripts, connects, images} {
		if len(group) != 1 || group[0] != "https://momento.internal" {
			t.Fatalf("the direct setup must allow exactly the collector, got %v", group)
		}
	}
}

func TestEveryScriptTagGetsTheNonceOnce(t *testing.T) {
	c := Config{Enabled: true, Provider: ProviderCustom, CustomSnippet: `<script src="https://t.example/a.js"></script>
<SCRIPT>track()</SCRIPT>
<script nonce="keep">x()</script>`}
	out := c.Snippet("n0nce")
	if got := strings.Count(out, `nonce="n0nce"`); got != 2 {
		t.Fatalf("want the nonce on the two tags that lack one, got %d in %s", got, out)
	}
	if !strings.Contains(out, `nonce="keep"`) {
		t.Fatal("a tag that carries its own nonce must be left alone")
	}
	if c.Snippet("") != strings.TrimSpace(c.CustomSnippet) {
		t.Fatal("no nonce means no change")
	}
}

func TestOriginsAreReadOutOfThePastedSnippet(t *testing.T) {
	snippet := `<script async src="https://cdn.tracker.example/lib.js"></script>
<script>t.init({endpoint:'https://collect.tracker.example:8443/v1'});new Image().src="http://pixel.example/p.gif?u="+u;</script>
<script>fetch("https://cdn.tracker.example/x")</script>`
	got := SnippetOrigins(snippet)
	want := []string{"https://cdn.tracker.example", "https://collect.tracker.example:8443", "http://pixel.example"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("origins = %v, want %v", got, want)
	}
	c := Config{Enabled: true, Provider: ProviderCustom, CustomSnippet: snippet, AllowedHosts: "https://extra.example, https://cdn.tracker.example"}
	scripts, _, _ := c.PolicySources()
	if strings.Join(scripts, " ") != strings.Join(append(want, "https://extra.example"), " ") {
		t.Fatalf("script sources = %v", scripts)
	}
}

func TestValidateRefusesWhatCannotWork(t *testing.T) {
	cases := []struct {
		name string
		c    Config
		want string
	}{
		{"off is fine", Config{}, ""},
		{"off with junk provider", Config{Provider: "pixel"}, "추적 도구는"},
		{"on without provider", Config{Enabled: true, Provider: ProviderNone}, "추적을 켜려면"},
		{"momento without site", Config{Enabled: true, Provider: ProviderMomento, MomentoURL: "https://m.internal"}, "Momento"},
		{"momento bad url", Config{Enabled: true, Provider: ProviderMomento, MomentoURL: "m.internal", MomentoSiteID: "1"}, "수집기 주소"},
		{"ga4 without id", Config{Enabled: true, Provider: ProviderGA4}, "측정 ID"},
		{"matomo without id", Config{Enabled: true, Provider: ProviderMatomo, MatomoURL: "https://m"}, "Matomo"},
		{"custom empty", Config{Enabled: true, Provider: ProviderCustom}, "비어 있습니다"},
		{"custom too long", Config{Enabled: true, Provider: ProviderCustom, CustomSnippet: strings.Repeat("x", MaxSnippetBytes+1)}, "8192바이트"},
		{"too long even when off", Config{Provider: ProviderCustom, CustomSnippet: strings.Repeat("x", MaxSnippetBytes+1)}, "8192바이트"},
		{"bad placement", Config{Placement: "footer"}, "삽입 위치"},
		{"bad allowed host", Config{AllowedHosts: "tracker.example"}, "허용 출처"},
		{"good", Config{Enabled: true, Provider: ProviderMomento, MomentoURL: "https://m.internal", MomentoSiteID: "1", AllowedHosts: "https://a.example https://b.example", Placement: "BODY"}, ""},
	}
	for _, tc := range cases {
		got := tc.c.Validate()
		if (tc.want == "" && got != "") || (tc.want != "" && !strings.Contains(got, tc.want)) {
			t.Errorf("%s: Validate() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestInjectFollowsThePlacement(t *testing.T) {
	page := []byte("<html><head><title>x</title></head><body><div id=root></div></body></html>")
	c := Config{Enabled: true, Provider: ProviderCustom, CustomSnippet: "<script>t()</script>"}
	head := string(c.Inject(page, "n"))
	if !strings.Contains(head, `<script nonce="n">t()</script>`+"\n</head>") {
		t.Fatalf("head placement: %s", head)
	}
	c.Placement = "body"
	body := string(c.Inject(page, "n"))
	if !strings.Contains(body, `<script nonce="n">t()</script>`+"\n</body>") {
		t.Fatalf("body placement: %s", body)
	}
	bare := string(c.Inject([]byte("shell"), "n"))
	if !strings.HasPrefix(bare, "shell\n<script") {
		t.Fatalf("a shell without the tag gets the snippet appended: %s", bare)
	}
	if string(Config{}.Inject(page, "n")) != string(page) {
		t.Fatal("nothing configured, nothing injected")
	}
}

func TestRecorderKeepsDistinctOriginsNotCounts(t *testing.T) {
	r := NewRecorder()
	clock := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { clock = clock.Add(time.Second); return clock }
	for i := 0; i < 5; i++ {
		r.Record("https://collect.example/v1/hit?x="+string(rune('a'+i)), "connect-src", "https://seccheck.internal/reviews/1?tab=items")
	}
	r.Record("https://collect.example/lib.js", "script-src-elem https://collect.example", "https://seccheck.internal/")
	r.Record("inline", "script-src", "/")
	r.Record("data", "img-src", "/")
	r.Record("chrome-extension://abc/x.js", "script-src", "/")
	items := r.List(Config{})
	if len(items) != 2 {
		t.Fatalf("want two distinct (directive, origin) pairs, got %+v", items)
	}
	if items[0].Directive != "script-src-elem" || items[1].Origin != "https://collect.example" || items[1].Count != 5 || items[1].Page != "/reviews/1" {
		t.Fatalf("unexpected list: %+v", items)
	}
	allowed := r.List(Config{Enabled: true, Provider: ProviderCustom, AllowedHosts: "https://collect.example"})
	if !allowed[0].Allowed || !allowed[1].Allowed {
		t.Fatalf("an origin the settings allow must be marked: %+v", allowed)
	}
	wild := r.List(Config{Enabled: true, Provider: ProviderGA4, MeasurementID: "G-1", AllowedHosts: "https://*.example"})
	if !wild[0].Allowed {
		t.Fatalf("a wildcard entry must match: %+v", wild)
	}
	r.Forget()
	if len(r.List(Config{})) != 0 {
		t.Fatal("Forget must empty the list")
	}
}

func TestRecorderIsBounded(t *testing.T) {
	r := NewRecorder()
	clock := time.Unix(0, 0)
	r.now = func() time.Time { clock = clock.Add(time.Second); return clock }
	for i := 0; i < MaxViolations+10; i++ {
		r.Record("https://h"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("y", i/26)+".example/", "connect-src", "/")
	}
	items := r.List(Config{})
	if len(items) != MaxViolations {
		t.Fatalf("want %d entries, got %d", MaxViolations, len(items))
	}
	if items[len(items)-1].LastSeen.Unix() != 11 {
		t.Fatalf("the oldest entries must be the ones evicted; oldest kept is %v", items[len(items)-1].LastSeen.Unix())
	}
}

func TestAddAllowedHost(t *testing.T) {
	if got := AddAllowedHost("", "https://a.example/"); got != "https://a.example" {
		t.Fatal(got)
	}
	if got := AddAllowedHost("https://a.example", "HTTPS://A.EXAMPLE"); got != "https://a.example" {
		t.Fatal(got)
	}
	if got := AddAllowedHost("https://a.example", "https://b.example"); got != "https://a.example, https://b.example" {
		t.Fatal(got)
	}
}
