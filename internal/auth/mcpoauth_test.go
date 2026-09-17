package auth

import (
	"reflect"
	"testing"
)

// The scopes an SSO principal gets are the administrator's ceiling, narrowed
// by the token only when the token speaks this service's vocabulary.
func TestSSOScopesAreTheAdministratorsCeilingNarrowedByTheToken(t *testing.T) {
	cases := []struct {
		admin []string
		token string
		want  []string
	}{
		{[]string{"read"}, "openid profile email", []string{"read"}},
		{[]string{"read", "read:write"}, "openid profile email", []string{"read", "read:write"}},
		{[]string{"read", "read:write"}, "openid read", []string{"read"}},
		{[]string{"read"}, "read:write", []string{}},
	}
	for _, c := range cases {
		if got := grantedScopes(c.admin, c.token); !reflect.DeepEqual(got, c.want) {
			t.Errorf("admin %v token %q: got %v want %v", c.admin, c.token, got, c.want)
		}
	}
}

func TestResourceIdentifierComesFromSettingsOnly(t *testing.T) {
	if got := MCPResource("", "https://seccheck.example.test/"); got != "https://seccheck.example.test/mcp" {
		t.Errorf("service address: %q", got)
	}
	if got := MCPResource(" https://mcp.example.test/mcp ", "https://other/"); got != "https://mcp.example.test/mcp" {
		t.Errorf("explicit wins: %q", got)
	}
	if got := MCPResource("", ""); got != "" {
		t.Errorf("nothing configured must yield nothing, not a Host-derived value: %q", got)
	}
	for value, ok := range map[string]bool{
		"https://seccheck.example.test/mcp":         true,
		"http://localhost:8080/mcp":                 true,
		"http://seccheck.example.test/mcp":          false,
		"https://seccheck.example.test/":            false,
		"https://seccheck.example.test/mcp?x=1":     false,
		"https://user:pw@seccheck.example.test/mcp": false,
	} {
		if ValidMCPResource(value) != ok {
			t.Errorf("ValidMCPResource(%q) = %v", value, !ok)
		}
	}
	cfg := MCPOAuthConfig{Resource: "https://seccheck.example.test/mcp"}
	if got := cfg.MetadataURL(); got != "https://seccheck.example.test/.well-known/oauth-protected-resource/mcp" {
		t.Errorf("metadata url: %q", got)
	}
	if !LooksLikeJWT("a.b.c") || LooksLikeJWT("sck_abc") || LooksLikeJWT("a..c") {
		t.Error("the JWT shape test is wrong")
	}
}
