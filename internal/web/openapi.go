package web

import "net/http"

func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]any{
		"openapi":    "3.1.0",
		"info":       map[string]any{"title": "SecCheck API", "version": s.Version, "description": "보안성 심의 체크리스트, 증적, 검토, 승인 및 감사 API. 브라우저는 세션+CSRF를, 시스템 연계는 범위 제한 개인 API 키 Bearer 인증을 사용합니다. read 키는 조회/MCP만, read:write 키는 기존 RBAC 범위 안의 변경도 허용합니다."},
		"servers":    []map[string]string{{"url": "/"}},
		"components": map[string]any{"securitySchemes": map[string]any{"bearerAuth": map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "SecCheck API key"}, "cookieAuth": map[string]any{"type": "apiKey", "in": "cookie", "name": "seccheck_session"}}},
		"security":   []map[string]any{{"bearerAuth": []string{}}, {"cookieAuth": []string{}}},
		"paths": map[string]any{
			"/api/v1/templates":                            map[string]any{"get": operation("템플릿 목록", "templates"), "post": operation("템플릿 생성", "templates")},
			"/api/v1/templates/{id}":                       map[string]any{"get": operation("템플릿 상세", "templates"), "patch": operation("템플릿 수정", "templates"), "delete": operation("미사용 템플릿 삭제", "templates")},
			"/api/v1/templates/import/preview":             map[string]any{"post": operation("Excel 가져오기 드라이런", "templates")},
			"/api/v1/review-requests":                      map[string]any{"get": operation("권한 범위의 심의 목록", "reviews"), "post": operation("심의 생성 및 체크리스트 스냅샷 배정", "reviews")},
			"/api/v1/review-requests/{id}":                 map[string]any{"get": operation("심의 상세", "reviews"), "patch": operation("심의 기본정보 수정", "reviews")},
			"/api/v1/review-requests/{id}/items":           map[string]any{"get": operation("응답, 검토결과, 증적을 포함한 스냅샷 항목", "reviews")},
			"/api/v1/review-requests/{id}/submit":          map[string]any{"post": operation("서버 검증 후 제출/재제출", "workflow")},
			"/api/v1/review-requests/{id}/export/{format}": map[string]any{"get": operation("xlsx, pdf, json, zip 결과 내보내기", "export")},
			"/api/v1/admin/audit":                          map[string]any{"get": operation("위변조 탐지 해시 체인 감사로그", "admin")},
			"/api/v1/admin/settings":                       map[string]any{"get": operation("관리 설정 목록", "admin")},
			"/api/v1/admin/users/{id}/unlock":              map[string]any{"post": operation("로그인 실패로 잠긴 계정 잠금 해제", "admin")},
			"/api/v1/admin/users/{id}/password":            map[string]any{"post": operation("로컬 계정 임시 비밀번호 재설정", "admin")},
			"/api/v1/me/password":                          map[string]any{"put": operation("본인 비밀번호 변경", "profile")},
			"/api/v1/notifications":                        map[string]any{"get": operation("인앱 알림 목록", "notifications")},
			"/api/v1/notifications/unread-count":           map[string]any{"get": operation("읽지 않은 알림 수", "notifications")},
			"/api/v1/notifications/read-all":               map[string]any{"post": operation("모든 알림 읽음 처리", "notifications")},
			"/api/v1/me/security":                          map[string]any{"get": operation("계정 보안 상태", "profile")},
			"/api/v1/me/sessions":                          map[string]any{"get": operation("본인 로그인 세션 목록", "profile")},
			"/api/v1/me/totp/setup":                        map[string]any{"post": operation("일회용 코드 등록 시작", "profile")},
			"/api/v1/me/totp/enable":                       map[string]any{"post": operation("일회용 코드 활성화", "profile")},
			"/api/v1/review-requests/{id}/responses/bulk":  map[string]any{"post": operation("체크리스트 항목 일괄 작성", "reviews")},
			"/api/v1/admin/users/{id}/totp/reset":          map[string]any{"post": operation("일회용 코드 초기화", "admin")},
			"/api/v1/admin/jobs":                           map[string]any{"get": operation("백그라운드 작업 큐 상태", "admin")},
			"/api/v1/admin/jobs/{id}/retry":                map[string]any{"post": operation("실패한 작업 재시도", "admin")},
			"/api/v1/admin/audit/verify":                   map[string]any{"get": operation("해시 체인 검증. full=1이면 전체 재검증", "admin")},
			"/api/v1/admin/settings/notification/test":     map[string]any{"post": operation("SMTP 설정 테스트 메일 발송", "admin")},
			"/api/v1/me/notification-preferences":          map[string]any{"get": operation("알림 수신 설정 조회", "notifications"), "put": operation("알림 수신 설정 저장", "notifications")},
			"/api/v1/security-controls":                    map[string]any{"get": operation("통합 Security Control과 영향 건수", "controls"), "post": operation("Security Control 생성", "controls")},
			"/mcp":                                         map[string]any{"post": operation("MCP 2026-07-28 Streamable HTTP endpoint", "mcp")},
		},
	})
}
func operation(summary, tag string) map[string]any {
	return map[string]any{"summary": summary, "tags": []string{tag}, "responses": map[string]any{"200": map[string]any{"description": "Success"}, "401": map[string]any{"description": "Authentication required"}, "403": map[string]any{"description": "Forbidden"}}}
}
