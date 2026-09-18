// Package analytics puts a visitor tracking snippet into the served pages.
//
// The pages ship with a content security policy that allows scripts from the
// application origin only, so a snippet cannot simply be pasted into the
// shell: the browser drops it without a word and the administrator is left
// looking at an empty dashboard. This package produces both halves of the
// answer -- the markup to inject and the policy sources it needs -- with a
// per-request nonce so the inline part runs without loosening the policy for
// everything else.
package analytics

import (
	"fmt"
	"html"
	"net/url"
	"strings"
)

const (
	ProviderNone    = "none"
	ProviderMomento = "momento"
	ProviderGA4     = "ga4"
	ProviderGTM     = "gtm"
	ProviderMatomo  = "matomo"
	ProviderCustom  = "custom"

	// MaxSnippetBytes bounds a pasted snippet. A tracker loader is a few
	// hundred bytes; anything larger is a whole script that belongs on a
	// server, not in a settings row read on every page.
	MaxSnippetBytes = 8 * 1024

	// ProxyPath is the same-origin prefix the application forwards to the
	// Momento collector, so a page never has to reach an external origin.
	ProxyPath = "/momento"
)

// Providers lists the choices in the order the screen offers them. Momento is
// first because it is the in-house collector: the only option whose data does
// not leave the network.
var Providers = []string{ProviderNone, ProviderMomento, ProviderGA4, ProviderGTM, ProviderMatomo, ProviderCustom}

// Config is the `analytics` settings row. Off by default: a fresh install
// serves exactly the pages it served before this existed.
type Config struct {
	Enabled       bool   `json:"enabled"`
	Provider      string `json:"provider"`
	MomentoURL    string `json:"momento_url"`
	MomentoSiteID string `json:"momento_site_id"`
	// MomentoProxy sends the tracker through ProxyPath on this origin instead
	// of naming the collector in the policy. It is the default because it is
	// the one setup that works under a policy nobody can change.
	MomentoProxy  *bool  `json:"momento_proxy"`
	MeasurementID string `json:"measurement_id"`
	MatomoURL     string `json:"matomo_url"`
	MatomoSiteID  string `json:"matomo_site_id"`
	CustomSnippet string `json:"custom_snippet"`
	AllowedHosts  string `json:"allowed_hosts"`
	IncludeAdmin  bool   `json:"include_admin"`
	Placement     string `json:"placement"`
}

func (c Config) momentoProxy() bool { return c.MomentoProxy == nil || *c.MomentoProxy }

func (c Config) placement() string {
	if strings.EqualFold(strings.TrimSpace(c.Placement), "body") {
		return "body"
	}
	return "head"
}

// Active reports whether a page at path should carry the snippet. Non-page
// paths never do, and administrative screens only when asked for: console
// traffic is rarely the visitor data anybody wants to count.
func (c Config) Active(path string) bool {
	if !c.Enabled || c.Provider == ProviderNone || c.Provider == "" {
		return false
	}
	if IsNonPage(path) {
		return false
	}
	if !c.IncludeAdmin && strings.HasPrefix(path, "/admin") {
		return false
	}
	return strings.TrimSpace(c.Snippet("")) != ""
}

// IsNonPage lists the paths that never serve a page: the API, the machine
// interface, the health probes and the collector proxy. Their policy is
// narrower than the pages', not wider.
func IsNonPage(path string) bool {
	if path == "/api" || strings.HasPrefix(path, "/api/") || path == "/mcp" || path == "/health" || path == "/ready" || path == "/metrics" || strings.HasPrefix(path, "/.well-known/") {
		return true
	}
	return path == ProxyPath || strings.HasPrefix(path, ProxyPath+"/")
}

// Validate reports what is missing for the chosen provider, in the words the
// settings screen shows.
func (c Config) Validate() string {
	if c.Provider != "" && !contains(Providers, c.Provider) {
		return "추적 도구는 none, momento, ga4, gtm, matomo, custom 중 하나여야 합니다."
	}
	if len(c.CustomSnippet) > MaxSnippetBytes {
		return fmt.Sprintf("추적 코드는 %d바이트를 넘을 수 없습니다.", MaxSnippetBytes)
	}
	if p := strings.TrimSpace(c.Placement); p != "" && !strings.EqualFold(p, "head") && !strings.EqualFold(p, "body") {
		return "삽입 위치는 head 또는 body 여야 합니다."
	}
	for _, raw := range []string{c.MomentoURL, c.MatomoURL} {
		if raw = strings.TrimSpace(raw); raw != "" && originOf(raw) == "" {
			return "수집기 주소는 http(s)로 시작하는 완전한 URL이어야 합니다."
		}
	}
	for _, host := range splitHosts(c.AllowedHosts) {
		if originOf(host) == "" {
			return "허용 출처는 https://host 형식이어야 합니다: " + host
		}
	}
	if !c.Enabled {
		return ""
	}
	switch c.Provider {
	case ProviderNone, "":
		return "추적을 켜려면 추적 도구를 고르세요."
	case ProviderMomento:
		if strings.TrimSpace(c.MomentoURL) == "" || strings.TrimSpace(c.MomentoSiteID) == "" {
			return "Momento 수집기 주소와 사이트 ID가 필요합니다."
		}
	case ProviderGA4, ProviderGTM:
		if strings.TrimSpace(c.MeasurementID) == "" {
			return "GA4 측정 ID 또는 GTM 컨테이너 ID가 필요합니다."
		}
	case ProviderMatomo:
		if strings.TrimSpace(c.MatomoURL) == "" || strings.TrimSpace(c.MatomoSiteID) == "" {
			return "Matomo 주소와 사이트 ID가 필요합니다."
		}
	case ProviderCustom:
		if strings.TrimSpace(c.CustomSnippet) == "" {
			return "직접 입력 추적 코드가 비어 있습니다."
		}
	}
	return ""
}

// Snippet renders the markup to inject. The nonce goes onto every script tag
// so the policy can stay strict.
func (c Config) Snippet(nonce string) string {
	switch c.Provider {
	case ProviderMomento:
		base := strings.TrimRight(strings.TrimSpace(c.MomentoURL), "/")
		site := html.EscapeString(strings.TrimSpace(c.MomentoSiteID))
		if base == "" || site == "" {
			return ""
		}
		if c.momentoProxy() {
			return withNonce(fmt.Sprintf(`<script async src="%s/tracker.js" data-site-id="%s" data-environment="prd" data-contract-version="1" data-endpoint="%s"></script>`, ProxyPath, site, ProxyPath), nonce)
		}
		return withNonce(fmt.Sprintf(`<script async src="%s/tracker.js" data-site-id="%s" data-environment="prd" data-contract-version="1"></script>`, html.EscapeString(base), site), nonce)
	case ProviderGA4:
		id := html.EscapeString(strings.TrimSpace(c.MeasurementID))
		if id == "" {
			return ""
		}
		return withNonce(fmt.Sprintf(`<script async src="https://www.googletagmanager.com/gtag/js?id=%s"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','%s');</script>`, id, id), nonce)
	case ProviderGTM:
		id := html.EscapeString(strings.TrimSpace(c.MeasurementID))
		if id == "" {
			return ""
		}
		return withNonce(fmt.Sprintf(`<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src='https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);})(window,document,'script','dataLayer','%s');</script>`, id), nonce)
	case ProviderMatomo:
		base := strings.TrimRight(strings.TrimSpace(c.MatomoURL), "/")
		site := html.EscapeString(strings.TrimSpace(c.MatomoSiteID))
		if base == "" || site == "" {
			return ""
		}
		return withNonce(fmt.Sprintf(`<script>var _paq=window._paq=window._paq||[];_paq.push(['trackPageView']);_paq.push(['enableLinkTracking']);(function(){var u="%s/";_paq.push(['setTrackerUrl',u+'matomo.php']);_paq.push(['setSiteId','%s']);var d=document,g=d.createElement('script'),s=d.getElementsByTagName('script')[0];g.async=true;g.src=u+'matomo.js';s.parentNode.insertBefore(g,s);})();</script>`, html.EscapeString(base), site), nonce)
	case ProviderCustom:
		return withNonce(strings.TrimSpace(c.CustomSnippet), nonce)
	}
	return ""
}

// withNonce adds the nonce to every script tag that does not already carry
// one, which is what lets a pasted snippet run under a strict policy as it is.
func withNonce(snippet, nonce string) string {
	if nonce == "" || snippet == "" {
		return snippet
	}
	var b strings.Builder
	rest := snippet
	for {
		i := strings.Index(strings.ToLower(rest), "<script")
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		end := i + len("<script")
		b.WriteString(rest[:end])
		tag := rest[end:]
		if close := strings.Index(tag, ">"); close >= 0 {
			tag = tag[:close]
		}
		if !strings.Contains(strings.ToLower(tag), "nonce=") {
			b.WriteString(` nonce="` + html.EscapeString(nonce) + `"`)
		}
		rest = rest[end:]
	}
}

// Inject places the snippet just before the closing tag its placement names,
// or at the end of the document when that tag is missing.
func (c Config) Inject(page []byte, nonce string) []byte {
	snippet := c.Snippet(nonce)
	if snippet == "" {
		return page
	}
	marker := "</head>"
	if c.placement() == "body" {
		marker = "</body>"
	}
	text := string(page)
	i := strings.LastIndex(strings.ToLower(text), marker)
	if i < 0 {
		return []byte(text + "\n" + snippet + "\n")
	}
	return []byte(text[:i] + snippet + "\n" + text[i:])
}

// PolicySources lists the origins the snippet needs in script-src,
// connect-src and img-src. Known providers need no policy knowledge at all;
// a pasted snippet names the addresses it loads and reports to, so those are
// read out of it rather than copied from a console error by hand.
func (c Config) PolicySources() (scripts, connects, images []string) {
	add := func(origin string) {
		scripts = append(scripts, origin)
		connects = append(connects, origin)
		images = append(images, origin)
	}
	switch c.Provider {
	case ProviderMomento:
		if !c.momentoProxy() {
			if origin := originOf(c.MomentoURL); origin != "" {
				add(origin)
			}
		}
	case ProviderGA4, ProviderGTM:
		scripts = append(scripts, "https://www.googletagmanager.com")
		connects = append(connects, "https://www.google-analytics.com", "https://analytics.google.com", "https://*.google-analytics.com")
		images = append(images, "https://www.google-analytics.com", "https://www.googletagmanager.com")
	case ProviderMatomo:
		if origin := originOf(c.MatomoURL); origin != "" {
			add(origin)
		}
	case ProviderCustom:
		for _, origin := range SnippetOrigins(c.CustomSnippet) {
			add(origin)
		}
	}
	for _, host := range splitHosts(c.AllowedHosts) {
		add(host)
	}
	return dedupe(scripts), dedupe(connects), dedupe(images)
}

// SnippetOrigins lists every http(s) origin written into a snippet: the
// script it loads, the endpoint it posts to, the pixel it requests.
func SnippetOrigins(snippet string) []string {
	var origins []string
	for i := 0; i < len(snippet); {
		start := strings.Index(strings.ToLower(snippet[i:]), "http")
		if start < 0 {
			break
		}
		start += i
		end := start
		for end < len(snippet) && !isURLBoundary(snippet[end]) {
			end++
		}
		i = end
		if origin := originOf(snippet[start:end]); origin != "" {
			origins = append(origins, origin)
		}
	}
	return dedupe(origins)
}

// isURLBoundary reports the characters that cannot appear in a URL written
// inside HTML or JavaScript, which is where each address ends.
func isURLBoundary(letter byte) bool {
	switch letter {
	case '"', '\'', '`', '<', '>', ' ', '\t', '\n', '\r', ')', ',', ';', '\\', '+':
		return true
	}
	return false
}

// originOf reduces an address to scheme://host[:port], or "" when it is not
// an http(s) address. Only those can go into a policy.
func originOf(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return scheme + "://" + strings.ToLower(parsed.Host)
}

func splitHosts(raw string) []string {
	var hosts []string
	for _, host := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		if host = strings.TrimSpace(host); host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// AddAllowedHost appends one origin to the allow list, leaving the existing
// entries and their order alone.
func AddAllowedHost(existing, origin string) string {
	origin = strings.TrimSpace(strings.TrimSuffix(origin, "/"))
	if origin == "" {
		return existing
	}
	for _, host := range splitHosts(existing) {
		if strings.EqualFold(host, origin) {
			return existing
		}
	}
	if strings.TrimSpace(existing) == "" {
		return origin
	}
	return strings.TrimSpace(existing) + ", " + origin
}

func dedupe(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := items[:0]
	for _, item := range items {
		key := strings.ToLower(item)
		if !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	return out
}

func contains(items []string, v string) bool {
	for _, item := range items {
		if item == v {
			return true
		}
	}
	return false
}
