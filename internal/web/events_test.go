package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every audit event the code records must be named, or an auditor reads raw
// identifiers like UPDATE_SUBMISSION in a Korean report and the filter
// dropdown silently omits it.
func TestEveryAuditEventIsNamed(t *testing.T) {
	for _, code := range emittedCodes(t, `auditFrom\(r, "([A-Z_]{3,})"`, `EventType: "([A-Z_]{3,})"`) {
		if auditEventLabels[code] == "" {
			t.Errorf("audit event %s is recorded but has no label in auditEventLabels", code)
		}
	}
}

// Every notification the code sends must be in the preference catalogue, or
// the recipient cannot turn it off and the list shows a bare code.
func TestEveryNotificationEventIsInThePreferenceCatalogue(t *testing.T) {
	known := map[string]bool{}
	for _, event := range notificationEvents {
		known[event["code"]] = true
	}
	for _, code := range emittedNotificationCodes(t) {
		if !known[code] {
			t.Errorf("notification %s is sent but is not in notificationEvents, so nobody can mute it", code)
		}
	}
	// And nothing in the catalogue should be an event that is never sent.
	sent := map[string]bool{}
	for _, code := range emittedNotificationCodes(t) {
		sent[code] = true
	}
	for _, event := range notificationEvents {
		if !sent[event["code"]] {
			t.Errorf("notificationEvents offers %s but nothing ever sends it", event["code"])
		}
	}
}

func emittedNotificationCodes(t *testing.T) []string {
	t.Helper()
	// The argument lists contain nested calls such as r.Context(), so the
	// scan is bounded by distance rather than by the next closing bracket.
	codes := emittedCodes(t,
		`(?s)addTargetedNotification\(.{0,160}?"([A-Z_]{3,})"`,
		`(?s)addNotification\(.{0,160}?"([A-Z_]{3,})"`,
		`(?s)notifyReviewer\(.{0,160}?"([A-Z_]{3,})"`,
		`(?s)INSERT INTO notifications\(.{0,200}?'([A-Z_]{3,})'`,
		// The event is the third argument, so the scan stops there rather
		// than wandering into the error handling that follows the call. The
		// context argument is spelled ctx in the workers and r.Context() in the
		// handlers, and a call the scan does not recognise reads here as an
		// event nobody sends.
		`\.Notify\([A-Za-z0-9_.()]+, [A-Za-z0-9_.()]+, "([A-Z_]{3,})"`,
		`\.NotifyTx\([A-Za-z0-9_.()]+, [A-Za-z0-9_.()]+, [A-Za-z0-9_.()]+, "([A-Z_]{3,})"`,
	)
	// Approve and reject pass the decision through as the event type.
	return append(codes, "APPROVED", "REJECTED")
}

// emittedCodes scans the non-test sources of the whole module for the given
// patterns. Reading the source is cruder than a type-checked registry, but it
// cannot be bypassed by adding a call site somewhere new.
func emittedCodes(t *testing.T, patterns ...string) []string {
	t.Helper()
	var source strings.Builder
	for _, dir := range []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")} {
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr == nil {
				source.Write(body)
				source.WriteString("\n")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, pattern := range patterns {
		for _, m := range regexp.MustCompile(pattern).FindAllStringSubmatch(source.String(), -1) {
			// REVIEW_REQUEST is the notification target type, not an event.
			if m[1] == "REVIEW_REQUEST" || seen[m[1]] {
				continue
			}
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// The README sells REST/OpenAPI integration, so the document has to describe
// the whole API. It used to be a hand-maintained subset covering a third of
// the endpoints, which misleads an integrator more than having none.
func TestOpenAPIDescribesEveryAPIRoute(t *testing.T) {
	s := &Server{mux: http.NewServeMux()}
	s.routes()

	var api int
	seen := map[string]bool{}
	for _, route := range s.api {
		if !strings.HasPrefix(route.Path, "/api/") && route.Path != "/mcp" {
			continue
		}
		api++
		if route.Summary == "" {
			t.Errorf("%s %s has no summary", route.Method, route.Path)
		}
		if route.Tag == "" {
			t.Errorf("%s %s has no tag", route.Method, route.Path)
		}
		id := operationID(route)
		if seen[id] {
			t.Errorf("operationId %s is not unique", id)
		}
		seen[id] = true
	}
	if api < 90 {
		t.Fatalf("only %d API routes were registered; the table looks incomplete", api)
	}
}

// The console's tool list is served from the same definitions the protocol
// serves, because the hand-written copy had drifted to five entries while
// seven were being offered.
func TestIntegrationInfoMatchesTheServedTools(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/integrations", nil)
	(&Server{}).integrationInfo(rec, req)

	var info struct {
		MCPVersion string `json:"mcp_version"`
		Tools      []struct {
			Name        string `json:"name"`
			Title       string `json:"title"`
			Description string `json:"description"`
			ReadOnly    bool   `json:"read_only"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(info.Tools) != len(mcpTools()) {
		t.Fatalf("the console is told about %d tools while %d are served", len(info.Tools), len(mcpTools()))
	}
	if info.MCPVersion != mcpVersion {
		t.Errorf("advertised protocol version %q, serving %q", info.MCPVersion, mcpVersion)
	}
	served := map[string]bool{}
	for _, tool := range mcpTools() {
		served[fmt.Sprint(tool["name"])] = true
	}
	for _, tool := range info.Tools {
		if !served[tool.Name] {
			t.Errorf("the console advertises %s, which is not served", tool.Name)
		}
		if tool.Title == "" || tool.Description == "" {
			t.Errorf("%s is advertised without a description", tool.Name)
		}
		if !tool.ReadOnly {
			t.Errorf("%s is advertised as writing, but the page promises read-only tools", tool.Name)
		}
	}
}

// The write-scope check in the middleware waves /mcp through, because a
// JSON-RPC read is still a POST. That is safe only while every tool in the
// catalogue is a read -- and the dispatcher now enforces it per tool, so this
// checks the two halves agree.
func TestEveryMCPToolIsDeclaredReadOnly(t *testing.T) {
	for _, tool := range mcpTools() {
		name, _ := tool["name"].(string)
		annotations, ok := tool["annotations"].(map[string]any)
		if !ok {
			t.Errorf("%s carries no annotations, so its scope cannot be judged", name)
			continue
		}
		if readOnly, _ := annotations["readOnlyHint"].(bool); !readOnly {
			t.Errorf("%s is not declared read-only; a read-scoped API key can still reach /mcp", name)
		}
		if destructive, _ := annotations["destructiveHint"].(bool); destructive {
			t.Errorf("%s is declared destructive", name)
		}
		if !mcpToolIsReadOnly(name) {
			t.Errorf("mcpToolIsReadOnly(%q) disagrees with the catalogue", name)
		}
	}
	if mcpToolIsReadOnly("seccheck.not_a_tool") {
		t.Error("an unknown tool name was treated as read-only")
	}
}

// Every name the dispatcher answers has to be in the catalogue: one that is
// not has no declaration, and the per-tool scope check would refuse it.
func TestTheMCPDispatcherAnswersOnlyCataloguedTools(t *testing.T) {
	body, err := os.ReadFile("mcp.go")
	if err != nil {
		t.Fatal(err)
	}
	dispatch := regexp.MustCompile(`case "(seccheck\.[a-z_]+)":`).FindAllStringSubmatch(string(body), -1)
	if len(dispatch) == 0 {
		t.Fatal("no tool cases found; callMCPTool must have changed shape")
	}
	catalogue := map[string]bool{}
	for _, tool := range mcpTools() {
		name, _ := tool["name"].(string)
		catalogue[name] = true
	}
	for _, m := range dispatch {
		if !catalogue[m[1]] {
			t.Errorf("callMCPTool answers %s but tools/list never advertises it", m[1])
		}
	}
	if len(dispatch) != len(catalogue) {
		t.Errorf("%d tools dispatched, %d advertised", len(dispatch), len(catalogue))
	}
}

// A client generated from the document has to be able to call the API. The
// specification used to name no request bodies at all.
func TestTheOpenAPIDocumentDescribesRequestBodies(t *testing.T) {
	s := &Server{mux: http.NewServeMux()}
	s.routes()
	rec := httptest.NewRecorder()
	s.openAPI(rec, httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil))
	// A path item holds method keys alongside a shared "parameters" array, so
	// the operations are decoded one at a time.
	type operationDoc struct {
		RequestBody struct {
			Required bool `json:"required"`
			Content  map[string]struct {
				Schema struct {
					AdditionalProperties bool           `json:"additionalProperties"`
					Properties           map[string]any `json:"properties"`
				} `json:"schema"`
			} `json:"content"`
		} `json:"requestBody"`
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the document is not valid JSON: %v", err)
	}
	described := 0
	for path, methods := range doc.Paths {
		for method, raw := range methods {
			if method == "parameters" {
				continue
			}
			var op operationDoc
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			key := strings.ToUpper(method) + " " + path
			want, expected := requestPayloads[key]
			body := op.RequestBody
			if !expected {
				if len(body.Content) > 0 {
					t.Errorf("%s describes a body but decodes none", key)
				}
				continue
			}
			schema := body.Content["application/json"].Schema
			if len(schema.Properties) != len(want) {
				t.Errorf("%s describes %d properties, the server accepts %d", key, len(schema.Properties), len(want))
			}
			if schema.AdditionalProperties {
				t.Errorf("%s allows extra properties, but the server rejects them", key)
			}
			described++
		}
	}
	if described != len(requestPayloads) {
		t.Errorf("%d bodies reached the document, %d are in the table", described, len(requestPayloads))
	}
}
