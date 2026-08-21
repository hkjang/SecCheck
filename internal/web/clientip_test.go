package web

import (
	"net/http"
	"net/netip"
	"testing"
)

func prefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, value := range values {
		prefix, err := parseProxyPrefix(value)
		if err != nil {
			t.Fatalf("parse %q: %v", value, err)
		}
		out = append(out, prefix)
	}
	return out
}

func request(remote, forwarded string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r.RemoteAddr = remote
	if forwarded != "" {
		r.Header.Set("X-Forwarded-For", forwarded)
	}
	return r
}

func TestResolveClientIPIgnoresForwardedHeaderWithoutTrustedProxy(t *testing.T) {
	if got := resolveClientIP(request("203.0.113.9:41234", "10.9.9.9"), nil); got != "203.0.113.9" {
		t.Fatalf("client IP = %q, want the peer address when no proxy is trusted", got)
	}
	if got := resolveClientIP(request("203.0.113.9:41234", "10.9.9.9"), prefixes(t, "10.1.0.0/16")); got != "203.0.113.9" {
		t.Fatalf("client IP = %q, want the peer address when the peer is not a trusted proxy", got)
	}
}

func TestResolveClientIPSkipsChainedTrustedProxies(t *testing.T) {
	trusted := prefixes(t, "10.1.0.0/16", "10.2.0.7")
	if got := resolveClientIP(request("10.1.0.5:9000", "198.51.100.4, 10.2.0.7"), trusted); got != "198.51.100.4" {
		t.Fatalf("client IP = %q, want the first untrusted hop", got)
	}
	if got := resolveClientIP(request("10.1.0.5:9000", "not-an-ip, 198.51.100.4"), trusted); got != "198.51.100.4" {
		t.Fatalf("client IP = %q, want the rightmost parsable hop", got)
	}
	if got := resolveClientIP(request("10.1.0.5:9000", "garbage"), trusted); got != "10.1.0.5" {
		t.Fatalf("client IP = %q, want the peer address for an unusable header", got)
	}
}
