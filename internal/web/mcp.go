package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hkjang/SecCheck/internal/auth"
)

const mcpVersion = "2026-07-28"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r) && !contains(s.runtimeSecurity(r.Context()).CORSOrigins, origin) {
		writeRPCError(w, nil, http.StatusForbidden, -32000, "Invalid Origin", nil)
		return
	}
	var req rpcRequest
	if !decodeMCP(w, r, &req) {
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		writeRPCError(w, req.ID, 400, -32600, "Invalid Request", nil)
		return
	}
	protocol := r.Header.Get("MCP-Protocol-Version")
	modern := protocol == mcpVersion
	if modern {
		if err := validateMCPHeaders(r, req); err != "" {
			writeRPCError(w, req.ID, 400, -32020, "Header mismatch: "+err, nil)
			return
		}
	}
	if protocol != "" && !modern && !strings.HasPrefix(protocol, "2025-") {
		writeRPCError(w, req.ID, 400, -32021, "Unsupported protocol version", map[string]any{"supported": []string{mcpVersion, "2025-11-25"}})
		return
	}
	var result any
	var err *rpcError
	switch req.Method {
	case "initialize":
		if modern {
			err = &rpcError{Code: -32601, Message: "initialize was removed in protocol 2026-07-28; use server/discover"}
		} else {
			result = map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "serverInfo": map[string]any{"name": "SecCheck", "title": "SecCheck Security Review", "version": s.Version}, "instructions": "SecCheck 심의와 Security Control을 권한 범위 안에서 조회합니다."}
		}
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
		return
	case "server/discover":
		result = map[string]any{"resultType": "complete", "protocolVersion": mcpVersion, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "serverInfo": map[string]any{"name": "SecCheck", "title": "SecCheck Security Review", "version": s.Version}}
	case "ping":
		result = map[string]any{"resultType": "complete"}
	case "tools/list":
		result = map[string]any{"resultType": "complete", "tools": mcpTools(), "ttlMs": 300000, "cacheScope": "private"}
	case "tools/call":
		result, err = s.callMCPTool(r, req.Params)
	default:
		err = &rpcError{Code: -32601, Message: "Method not found"}
	}
	status := 200
	if err != nil && err.Code == -32601 {
		status = 404
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result, Error: err})
}

func decodeMCP(w http.ResponseWriter, r *http.Request, out *rpcRequest) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		writeRPCError(w, nil, 400, -32700, "Parse error", nil)
		return false
	}
	return true
}
func writeRPCError(w http.ResponseWriter, id any, status, code int, message string, data any) {
	jsonResponse(w, status, rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message, Data: data}})
}
func sameOrigin(origin string, r *http.Request) bool {
	return origin == "https://"+r.Host || origin == "http://"+r.Host
}
func validateMCPHeaders(r *http.Request, req rpcRequest) string {
	if r.Header.Get("Mcp-Method") != req.Method {
		return "Mcp-Method does not match request method"
	}
	var params struct {
		Name string         `json:"name"`
		Meta map[string]any `json:"_meta"`
	}
	_ = json.Unmarshal(req.Params, &params)
	if fmt.Sprint(params.Meta["io.modelcontextprotocol/protocolVersion"]) != mcpVersion {
		return "protocol version body metadata is missing or does not match"
	}
	if req.Method == "tools/call" {
		header, ok := decodeMCPHeader(r.Header.Get("Mcp-Name"))
		if !ok || header != params.Name {
			return "Mcp-Name does not match tool name"
		}
	}
	return ""
}
func decodeMCPHeader(v string) (string, bool) {
	if strings.HasPrefix(v, "=?base64?") && strings.HasSuffix(v, "?=") {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(v, "=?base64?"), "?="))
		return string(b), err == nil
	}
	if strings.TrimSpace(v) != v || v == "" {
		return v, false
	}
	for _, r := range v {
		if r < 0x20 || r > 0x7e {
			return v, false
		}
	}
	return v, true
}

// integrationInfo describes the machine interfaces for the console. The page
// used to hard-code the tool list and had drifted to five entries while seven
// were served, so an integrator reading it did not know two of them existed.
// Serving the real list means it cannot drift again.
func (s *Server) integrationInfo(w http.ResponseWriter, r *http.Request) {
	tools := make([]map[string]any, 0, len(mcpTools()))
	for _, tool := range mcpTools() {
		annotations, _ := tool["annotations"].(map[string]any)
		readOnly, _ := annotations["readOnlyHint"].(bool)
		tools = append(tools, map[string]any{
			"name": tool["name"], "title": tool["title"], "description": tool["description"], "read_only": readOnly,
		})
	}
	jsonResponse(w, 200, map[string]any{
		"api_version":       "v1",
		"openapi":           "/api/openapi.json",
		"mcp_endpoint":      "/mcp",
		"mcp_version":       mcpVersion,
		"mcp_compatibility": []string{"2025-11-25"},
		"tools":             tools,
	})
}

// mcpToolIsReadOnly answers for the tool as it is actually advertised. An
// unknown name is not read-only: a tool that reaches the dispatcher without
// being in the catalogue has no declaration to trust.
func mcpToolIsReadOnly(name string) bool {
	for _, tool := range mcpTools() {
		if tool["name"] != name {
			continue
		}
		annotations, _ := tool["annotations"].(map[string]any)
		readOnly, _ := annotations["readOnlyHint"].(bool)
		return readOnly
	}
	return false
}

func mcpTools() []map[string]any {
	return []map[string]any{
		{"name": "seccheck.dashboard", "title": "SecCheck dashboard", "description": "권한 범위의 심의 상태별 건수와 처리할 보완 요청을 조회합니다.", "inputSchema": map[string]any{"type": "object", "additionalProperties": false}, "annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false}},
		{"name": "seccheck.get_review", "title": "Get security review", "description": "심의 ID로 기본정보, 진행률, 상태와 담당자를 조회합니다.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"review_id": map[string]any{"type": "string", "description": "SecCheck review UUID"}}, "required": []string{"review_id"}, "additionalProperties": false}, "annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false}},
		{"name": "seccheck.list_reviews", "title": "List security reviews", "description": "권한 범위의 보안성 심의를 상태 또는 검색어로 조회합니다.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"status": map[string]any{"type": "string"}, "query": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}}, "additionalProperties": false}, "annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false}},
		{"name": "seccheck.search_controls", "title": "Search security controls", "description": "게시된 체크리스트의 항목 코드, 보안요건, 질문과 가이드를 검색합니다.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string", "minLength": 2}, "category": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}}, "required": []string{"query"}, "additionalProperties": false}, "annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false}},
		{"name": "seccheck.review_report", "title": "Review report", "description": "기간별 심의 처리 현황, 처리 소요 기간, 부서별 집계와 반복 미흡 항목을 조회합니다.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"from": map[string]any{"type": "string", "description": "YYYY-MM-DD"}, "to": map[string]any{"type": "string", "description": "YYYY-MM-DD"}, "department": map[string]any{"type": "string"}}, "additionalProperties": false}, "annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false}},
		{"name": "seccheck.my_queue", "title": "My review queue", "description": "지금 본인이 처리해야 하는 심의와 기한이 임박한 보완 요청을 조회합니다.", "inputSchema": map[string]any{"type": "object", "additionalProperties": false}, "annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false}},
		{"name": "seccheck.validate_submission", "title": "Validate submission", "description": "제출 전 서버 검증을 실행하고 누락된 적용여부, N/A 사유, 증적 또는 검사 상태를 반환합니다.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"review_id": map[string]any{"type": "string"}}, "required": []string{"review_id"}, "additionalProperties": false}, "annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false}},
	}
}

func (s *Server) callMCPTool(r *http.Request, raw json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if json.Unmarshal(raw, &p) != nil || p.Name == "" {
		return nil, &rpcError{Code: -32602, Message: "Invalid tool parameters"}
	}
	sess := session(r)
	// The middleware lets any API key POST to /mcp because the transport is a
	// POST even for a read. That exemption is only sound while the tool being
	// called is itself read-only, so the write scope is enforced per tool
	// here rather than left as an assumption about the catalogue.
	if sess.APIKey && !contains(sess.Scopes, "read:write") && !mcpToolIsReadOnly(p.Name) {
		return nil, &rpcError{Code: -32003, Message: "이 API 키에는 쓰기 범위가 없습니다."}
	}
	var data any
	var err error
	switch p.Name {
	case "seccheck.dashboard":
		data, err = s.mcpDashboard(r, sess)
	case "seccheck.my_queue":
		data = map[string]any{"my_queue": s.myQueue(r), "due_soon": s.dueChangeRequests(r)}
	case "seccheck.review_report":
		if !hasAnyRole(sess.User, "SYSTEM_ADMIN", "SECURITY_REVIEWER", "AUDITOR", "APPROVER") {
			return nil, &rpcError{Code: -32001, Message: "이 도구를 사용할 권한이 없습니다."}
		}
		data, err = s.mcpReviewReport(r, p.Arguments)
	case "seccheck.get_review":
		data, err = s.mcpGetReview(r, sess, stringValue(p.Arguments["review_id"]))
	case "seccheck.list_reviews":
		data, err = s.mcpListReviews(r, sess, stringValue(p.Arguments["status"]), stringValue(p.Arguments["query"]), numberValue(p.Arguments["limit"], 50))
	case "seccheck.search_controls":
		data, err = s.mcpSearchControls(r, stringValue(p.Arguments["query"]), stringValue(p.Arguments["category"]), numberValue(p.Arguments["limit"], 50))
	case "seccheck.validate_submission":
		id := stringValue(p.Arguments["review_id"])
		if !s.canAccessReview(r.Context(), sess, id) {
			err = errForbidden
		} else {
			data, err = s.validateSubmission(r.Context(), id)
		}
	default:
		return nil, &rpcError{Code: -32602, Message: "Unknown tool: " + p.Name}
	}
	if err != nil {
		if err == errForbidden {
			return mcpToolError("권한 범위에서 대상을 찾을 수 없습니다."), nil
		}
		return mcpToolError("도구 실행에 실패했습니다."), nil
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "MCP_TOOL_CALL", "MCP_TOOL", p.Name, nil, map[string]any{"arguments": p.Arguments}))
	b, _ := json.Marshal(data)
	return map[string]any{"resultType": "complete", "content": []map[string]any{{"type": "text", "text": string(b)}}, "structuredContent": data}, nil
}
func mcpToolError(message string) map[string]any {
	return map[string]any{"resultType": "complete", "isError": true, "content": []map[string]any{{"type": "text", "text": message}}}
}

// mcpReviewReport reuses the HTTP report so an agent and the console can never
// disagree about the numbers.
func (s *Server) mcpReviewReport(r *http.Request, args map[string]any) (any, error) {
	query := r.URL.Query()
	for _, key := range []string{"from", "to", "department"} {
		if value := strings.TrimSpace(stringValue(args[key])); value != "" {
			query.Set(key, value)
		}
	}
	scoped := r.Clone(r.Context())
	scoped.URL.RawQuery = query.Encode()
	return s.buildReport(scoped, reportFilter(scoped))
}

func (s *Server) mcpDashboard(r *http.Request, sess auth.Session) (any, error) {
	where, args := accessFilter(sess, 1)
	if hasAnyRole(sess.User, "SECURITY_REVIEWER", "AUDITOR") {
		where = "TRUE"
		args = nil
	}
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT status,count(*) FROM review_requests WHERE `+where+` GROUP BY status`, args...)
	if err != nil {
		return nil, err
	}
	return scanDynamicAny(rows, []string{"status", "count"})
}
func (s *Server) mcpGetReview(r *http.Request, sess auth.Session, id string) (any, error) {
	if !s.canAccessReview(r.Context(), sess, id) {
		return nil, errForbidden
	}
	var raw []byte
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT to_jsonb(r)-'description'||jsonb_build_object('description',r.description) FROM review_requests r WHERE id=$1`, id).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var out any
	_ = json.Unmarshal(raw, &out)
	return out, nil
}
func (s *Server) mcpListReviews(r *http.Request, sess auth.Session, status, q string, limit int) (any, error) {
	where, args := accessFilter(sess, 1)
	if hasAnyRole(sess.User, "SECURITY_REVIEWER", "AUDITOR") {
		where = "TRUE"
		args = nil
	}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND status=$%d", len(args))
	}
	if q != "" {
		args = append(args, "%"+q+"%")
		where += fmt.Sprintf(" AND (review_number ILIKE $%d OR service_name ILIKE $%d)", len(args), len(args))
	}
	args = append(args, limit)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,review_number,service_name,status,department,planned_open_date,updated_at FROM review_requests WHERE `+where+` ORDER BY updated_at DESC LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	return scanDynamicAny(rows, []string{"id", "review_number", "service_name", "status", "department", "planned_open_date", "updated_at"})
}
func (s *Server) mcpSearchControls(r *http.Request, q, category string, limit int) (any, error) {
	if len(strings.TrimSpace(q)) < 2 {
		return nil, fmt.Errorf("query too short")
	}
	args := []any{"%" + q + "%"}
	where := `v.status='PUBLISHED' AND (i.item_code ILIKE $1 OR i.title ILIKE $1 OR i.question ILIKE $1 OR i.guide ILIKE $1)`
	if category != "" {
		args = append(args, strings.ToUpper(category))
		where += ` AND i.category=$2`
	}
	args = append(args, limit)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT i.item_code,i.category,i.title,i.question,i.guide,i.legal_basis,i.severity,t.name AS template,v.version FROM checklist_items i JOIN checklist_versions v ON v.id=i.version_id JOIN checklist_templates t ON t.id=v.template_id WHERE `+where+` ORDER BY i.category,i.item_code LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	return scanDynamicAny(rows, []string{"item_code", "category", "title", "question", "guide", "legal_basis", "severity", "template", "version"})
}

// scanDynamicAny adapts the reader for the MCP helpers, which answer with an
// interface value and the error beside it.
func scanDynamicAny(rows interface {
	Next() bool
	Values() ([]any, error)
	Close()
	Err() error
}, names []string) (any, error) {
	return scanDynamic(rows, names)
}

func numberValue(v any, fallback int) int {
	if n, ok := v.(float64); ok && n >= 1 && n <= 100 {
		return int(n)
	}
	return fallback
}
