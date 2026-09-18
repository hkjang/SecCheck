package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hkjang/SecCheck/internal/auth"
)

// The resource-server half of MCP authorization: the document a refused
// client reads to find Keycloak, and the 401 that points at it. Token
// verification itself is in internal/auth, next to the web sign-in whose
// issuer it reuses.

// protectedResourceMetadataPath is RFC 9728's well-known location. Both the
// bare path and the path-suffixed one are served, because clients built
// against different drafts of the MCP specification ask at either.
const protectedResourceMetadataPath = "/.well-known/oauth-protected-resource"

// protectedResourceMetadata is the document that tells an MCP client where to
// sign in. Public by design -- it says where the authorization server is,
// not who is signed in -- and a bare JSON document rather than this API's
// envelope, because the reader is an OAuth client library that knows nothing
// about {data: ...}. Off means 404: a document that is served while tokens
// are refused sends every client into a sign-in loop.
func (s *Server) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	cfg := s.Auth.MCPOAuthConfig(r.Context())
	if !cfg.Enabled {
		problem(w, http.StatusNotFound, "MCP_OAUTH_DISABLED", "이 서버의 MCP 는 SSO 토큰을 받지 않습니다. 개인 API 키(sck_)를 사용하세요.", nil)
		return
	}
	// A client running inside a browser reads this cross-origin; only this
	// document is opened that way, never the API.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":                 cfg.Resource,
		"authorization_servers":    []string{cfg.Issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         cfg.Scopes,
		"resource_name":            "SecCheck MCP",
	})
}

// mcpChallenge turns a 401 from /mcp into an invitation: the client reads
// resource_metadata and starts the OAuth flow from there. Without it a
// refusal is a dead end. Only /mcp carries it -- on a REST 401 the header
// would send browsers and other clients somewhere they have no business --
// and only while tokens are actually accepted, or the invitation is a lie.
func (s *Server) mcpChallenge(w http.ResponseWriter, r *http.Request, presented bool) {
	if r.URL.Path != auth.MCPPath {
		return
	}
	cfg := s.Auth.MCPOAuthConfig(r.Context())
	if !cfg.Enabled {
		return
	}
	header := fmt.Sprintf(`Bearer realm="SecCheck", resource_metadata=%q`, cfg.MetadataURL())
	if presented {
		header += `, error="invalid_token"`
	}
	w.Header().Set("WWW-Authenticate", header)
}

// mcpOAuthInfo is what the console and the API guide show a person who wants
// to connect without a key: the addresses to hand a client, nothing secret.
func (s *Server) mcpOAuthInfo(r *http.Request) map[string]any {
	info := map[string]any{"enabled": false}
	if s.Auth == nil {
		return info
	}
	cfg := s.Auth.MCPOAuthConfig(r.Context())
	info["enabled"] = cfg.Enabled
	if cfg.Enabled {
		info["resource"] = cfg.Resource
		info["metadata_url"] = cfg.MetadataURL()
		info["authorization_server"] = cfg.Issuer
		info["scopes"] = cfg.Scopes
	}
	return info
}
