package web

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// The specification is generated from the route table rather than maintained
// by hand, so every endpoint is described and the roles it needs are part of
// the document. The previous hand-written version covered 31 of 91 paths.
func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	paths := map[string]any{}
	tags := map[string]bool{}
	for _, route := range s.api {
		if !strings.HasPrefix(route.Path, "/api/") && route.Path != "/mcp" {
			continue
		}
		item, _ := paths[route.Path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			if params := pathParameters(route.Path); len(params) > 0 {
				item["parameters"] = params
			}
			paths[route.Path] = item
		}
		item[strings.ToLower(route.Method)] = s.operation(route)
		tags[route.Tag] = true
	}
	jsonResponse(w, 200, map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "SecCheck API",
			"version":     s.Version,
			"description": "보안성 심의 체크리스트, 증적, 검토, 승인 및 감사 API. 브라우저는 세션+CSRF를, 시스템 연계는 범위 제한 개인 API 키 Bearer 인증을 사용합니다. read 키는 조회/MCP만, read:write 키는 기존 RBAC 범위 안의 변경도 허용합니다. 각 operation의 x-required-roles는 해당 엔드포인트에 필요한 역할입니다. 비어 있으면 역할 제한이 없다는 뜻이며, x-object-scoped가 true인 operation은 역할 대신 대상 심의의 참여 여부로 접근을 판단합니다(권한이 없으면 404).",
		},
		"servers":    []map[string]string{{"url": "/"}},
		"tags":       tagList(tags),
		"components": map[string]any{"securitySchemes": map[string]any{"bearerAuth": map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "SecCheck API key"}, "cookieAuth": map[string]any{"type": "apiKey", "in": "cookie", "name": "seccheck_session"}}},
		"security":   []map[string]any{{"bearerAuth": []string{}}, {"cookieAuth": []string{}}},
		"paths":      paths,
	})
}

func (s *Server) operation(route APIRoute) map[string]any {
	responses := map[string]any{"200": map[string]any{"description": "Success"}}
	switch route.Method {
	case http.MethodPost:
		responses["201"] = map[string]any{"description": "Created"}
	case http.MethodDelete:
		responses["204"] = map[string]any{"description": "No Content"}
	}
	operation := map[string]any{
		"summary":     route.Summary,
		"tags":        []string{route.Tag},
		"operationId": operationID(route),
		"responses":   responses,
	}
	if body := requestBodySchema(route); body != nil {
		operation["requestBody"] = body
		responses["400"] = map[string]any{"description": "Invalid request body"}
	}
	if route.Public {
		// Health, readiness and the sign-in endpoints are reachable without a
		// session, which the document has to say.
		operation["security"] = []map[string]any{}
		return operation
	}
	responses["401"] = map[string]any{"description": "Authentication required"}
	responses["403"] = map[string]any{"description": "Forbidden"}
	roles := route.Roles
	if roles == nil {
		roles = []string{}
	}
	operation["x-required-roles"] = roles
	notes := []string{}
	if len(roles) > 0 {
		notes = append(notes, "필요 역할: "+strings.Join(roles, ", "))
	}
	if objectScopedRoutes[route.Method+" "+route.Path] {
		operation["x-object-scoped"] = true
		notes = append(notes, "해당 심의의 참여자(요청자, 공동 작성자, 지정된 검토자·승인자)만 호출할 수 있습니다. 권한이 없으면 404를 반환합니다.")
	}
	if len(notes) > 0 {
		operation["description"] = strings.Join(notes, " · ")
	}
	return operation
}

// requestBodySchema describes what a route decodes. The server rejects
// unknown properties, so additionalProperties is false here too: a client
// generated from this document sends exactly what will be accepted.
func requestBodySchema(route APIRoute) map[string]any {
	fields := requestPayloads[route.Method+" "+route.Path]
	if len(fields) == 0 {
		return nil
	}
	properties := map[string]any{}
	for _, f := range fields {
		properties[f.Name] = jsonSchemaType(f.Type)
	}
	return map[string]any{
		"required": true,
		"content": map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"type": "object", "additionalProperties": false, "properties": properties},
		}},
	}
}

func jsonSchemaType(goType string) map[string]any {
	switch goType {
	case "bool":
		return map[string]any{"type": "boolean"}
	case "int", "int64":
		return map[string]any{"type": "integer"}
	case "float64":
		return map[string]any{"type": "number"}
	case "time.Time":
		return map[string]any{"type": "string", "format": "date-time"}
	case "[]string":
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	case "any":
		return map[string]any{}
	case "map":
		return map[string]any{"type": "object"}
	}
	return map[string]any{"type": "string"}
}

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

func pathParameters(path string) []map[string]any {
	var out []map[string]any
	for _, m := range pathParam.FindAllStringSubmatch(path, -1) {
		out = append(out, map[string]any{
			"name": m[1], "in": "path", "required": true,
			"schema": map[string]any{"type": "string"},
		})
	}
	return out
}

// operationID is derived from the method and path so it is stable across
// releases and usable by generated clients.
func operationID(route APIRoute) string {
	parts := []string{strings.ToLower(route.Method)}
	for _, segment := range strings.Split(strings.TrimPrefix(route.Path, "/"), "/") {
		if segment == "" {
			continue
		}
		if strings.HasPrefix(segment, "{") {
			parts = append(parts, "by"+strings.Title(strings.Trim(segment, "{}"))) //nolint:staticcheck // ASCII identifiers only
			continue
		}
		parts = append(parts, strings.ReplaceAll(segment, "-", "_"))
	}
	return strings.Join(parts, "_")
}

func tagList(tags map[string]bool) []map[string]string {
	out := make([]map[string]string, 0, len(tags))
	for tag := range tags {
		out = append(out, map[string]string{"name": tag})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"] < out[j]["name"] })
	return out
}
