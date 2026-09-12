package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/analytics"
)

// cspReportPath is where browsers post the requests the page policy refused.
// It is unauthenticated because the browser sends the report without
// credentials, and it stores nothing but a bounded list of origins in memory.
// The route is registered by its literal in routes(), which the docs tests
// read; this constant is what goes into the policy header.
const cspReportPath = "/api/v1/analytics/csp-report"

// maxReportBytes keeps an unauthenticated endpoint from being fed large
// bodies.
const maxReportBytes = 8 * 1024

// analyticsConfig reads the tracking settings, cached the way the security
// settings are so a page view costs no query. Any failure -- including the
// row not existing yet -- means "no tracking", so a settings problem never
// takes a page down.
func (s *Server) analyticsConfig(ctx context.Context) analytics.Config {
	s.analyticsMu.Lock()
	defer s.analyticsMu.Unlock()
	if time.Since(s.analyticsAt) < 15*time.Second {
		return s.analyticsConf
	}
	var cfg analytics.Config
	if _, err := s.Store.Setting(ctx, "analytics", &cfg); err != nil {
		cfg = analytics.Config{}
	}
	s.analyticsConf = cfg
	s.analyticsAt = time.Now()
	return cfg
}

func (s *Server) invalidateAnalyticsConfig() {
	s.analyticsMu.Lock()
	s.analyticsAt = time.Time{}
	s.analyticsConf = analytics.Config{}
	s.analyticsMu.Unlock()
}

// pagePolicy is the strict policy every page has always had, plus only what
// the configured snippet needs: a nonce for its inline code and the origins
// it loads from and reports to. When tracking is off the policy is exactly
// what it was before tracking existed -- nothing is loosened in advance, and
// 'unsafe-inline' never appears.
func pagePolicy(config analytics.Config, path, nonce string) string {
	scripts := []string{"'self'"}
	connects := []string{"'self'"}
	images := []string{"'self'", "data:", "blob:"}
	active := config.Active(path)
	if active {
		extraScripts, extraConnects, extraImages := config.PolicySources()
		scripts = append(scripts, "'nonce-"+nonce+"'")
		scripts = append(scripts, extraScripts...)
		connects = append(connects, extraConnects...)
		images = append(images, extraImages...)
	}
	policy := "default-src 'self'; script-src " + strings.Join(scripts, " ") +
		"; style-src 'self'; img-src " + strings.Join(images, " ") +
		"; connect-src " + strings.Join(connects, " ") +
		"; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests"
	if active {
		// While tracking is on, ask the browser to say what it refused. That
		// report is what turns a silent console error into a one-click fix.
		policy += "; report-uri " + cspReportPath
	}
	return policy
}

// nonPagePolicy is what the API, the machine interface and the probes get.
// None of them render a document, so nothing at all is allowed to load.
const nonPagePolicy = "default-src 'none'; frame-ancestors 'none'"

// newNonce is 128 bits of randomness per request, which is what the policy
// needs to make the inline snippet the only inline code that runs.
func newNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

const nonceKey ctxKey = "csp_nonce"

func requestNonce(r *http.Request) string {
	nonce, _ := r.Context().Value(nonceKey).(string)
	return nonce
}

// inject is the SPA's hook: the snippet for this request's page, or nothing.
func (s *Server) inject(r *http.Request, page []byte) []byte {
	config := s.analyticsConfig(r.Context())
	if !config.Active(r.URL.Path) {
		return page
	}
	return config.Inject(page, requestNonce(r))
}

type cspReport struct {
	Report struct {
		BlockedURI         string `json:"blocked-uri"`
		ViolatedDirective  string `json:"violated-directive"`
		EffectiveDirective string `json:"effective-directive"`
		DocumentURI        string `json:"document-uri"`
	} `json:"csp-report"`
}

// receiveCSPReport records what a browser refused to load. It always answers
// 204 so a misbehaving page never sees an error from us, and it records
// nothing unless tracking is on -- the report-uri is only in the policy then,
// but a stale page could still post here.
func (s *Server) receiveCSPReport(w http.ResponseWriter, r *http.Request) {
	defer w.WriteHeader(http.StatusNoContent)
	if s.violations == nil || !s.analyticsConfig(r.Context()).Enabled {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReportBytes))
	if err != nil || len(body) == 0 {
		return
	}
	var report cspReport
	if json.Unmarshal(body, &report) != nil {
		return
	}
	directive := report.Report.EffectiveDirective
	if directive == "" {
		directive = report.Report.ViolatedDirective
	}
	s.violations.Record(report.Report.BlockedURI, directive, report.Report.DocumentURI)
}

// listAnalyticsViolations shows the administrator which addresses the policy
// is blocking, so a snippet can be fixed without reading a browser console.
func (s *Server) listAnalyticsViolations(w http.ResponseWriter, r *http.Request) {
	items := []analytics.Violation{}
	if s.violations != nil {
		items = s.violations.List(s.analyticsConfig(r.Context()))
	}
	jsonResponse(w, 200, items)
}

// clearAnalyticsViolations forgets the recorded reports, which is how an
// administrator checks whether a change actually fixed the snippet.
func (s *Server) clearAnalyticsViolations(w http.ResponseWriter, r *http.Request) {
	if s.violations != nil {
		s.violations.Forget()
	}
	w.WriteHeader(http.StatusNoContent)
}

// allowAnalyticsHost adds one blocked origin to the allow list: the one-click
// fix for the reports listed above.
func (s *Server) allowAnalyticsHost(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Origin string `json:"origin"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	origin := strings.TrimSpace(in.Origin)
	if u, err := url.Parse(origin); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		problem(w, 422, "VALIDATION_FAILED", "허용 출처는 https://host 형식이어야 합니다: "+origin, nil)
		return
	}
	var raw map[string]any
	if _, err := s.Store.Setting(r.Context(), "analytics", &raw); err != nil {
		s.fault(w, r, "QUERY_FAILED", "설정을 불러오지 못했습니다.", err)
		return
	}
	current, _ := raw["allowed_hosts"].(string)
	raw["allowed_hosts"] = analytics.AddAllowedHost(current, origin)
	b, _ := json.Marshal(raw)
	if _, err := s.Store.Pool.Exec(r.Context(), `UPDATE settings SET value_json=$2,updated_by=$3,updated_at=now() WHERE key=$1`, "analytics", b, session(r).User.ID); err != nil {
		s.fault(w, r, "UPDATE_FAILED", "설정을 저장하지 못했습니다.", err)
		return
	}
	s.invalidateAnalyticsConfig()
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_SETTING", "SETTING", "analytics", nil, map[string]any{"allowed_hosts": raw["allowed_hosts"]}))
	jsonResponse(w, 200, raw)
}

// momentoProxy forwards /momento/* to the collector so the page never has
// to reach an external origin and the policy never has to name one. It is
// live only while Momento is the configured provider and proxying is on;
// otherwise the path is simply not there.
func (s *Server) momentoProxy(w http.ResponseWriter, r *http.Request) {
	config := s.analyticsConfig(r.Context())
	target, err := url.Parse(strings.TrimRight(strings.TrimSpace(config.MomentoURL), "/"))
	if !config.Enabled || config.Provider != analytics.ProviderMomento || config.MomentoProxy != nil && !*config.MomentoProxy || err != nil || target.Host == "" {
		http.NotFound(w, r)
		return
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = strings.TrimSuffix(target.Path, "/") + strings.TrimPrefix(pr.In.URL.Path, analytics.ProxyPath)
			pr.Out.URL.RawPath = ""
			pr.Out.Host = target.Host
			// The browser sends this origin's cookies with a same-origin
			// request. The collector has no business seeing a session.
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("X-CSRF-Token")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.Store.Log(r.Context(), "WARN", requestID(r), "analytics", "momento proxy failed", map[string]any{"path": r.URL.Path, "error": err.Error()})
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	proxy.ServeHTTP(w, r)
}
