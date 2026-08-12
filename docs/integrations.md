# API 및 MCP 연계

개인화 > 개인 키 관리에서 API 키를 발급합니다. 원문 키는 발급/회전 직후 한 번만 표시되며 DB에는 SHA-256만 저장됩니다.

- `read`: GET/HEAD와 읽기 전용 MCP 도구만 허용
- `read:write`: 보유한 RBAC·객체 권한 범위 안에서 변경 API도 허용

API 키 범위는 RBAC를 확장하지 않습니다. 예를 들어 `read:write` 키라도 사용자가 보안 담당자 역할과 해당 심의 권한을 갖지 않으면 검토 결과를 쓸 수 없습니다.

## REST

```bash
curl -H "Authorization: Bearer $SECCHECK_API_KEY" \
  https://seccheck.example/api/v1/review-requests
```

OpenAPI 3.1 문서는 인증 후 `/api/openapi.json`에서 조회합니다. 일반 사용자는 자신, 구축/개발 담당자 또는 공동 작성자로 지정된 심의만 조회할 수 있습니다.

## MCP

- Endpoint: `https://seccheck.example/mcp`
- Transport: Stateless Streamable HTTP
- Protocol: `2026-07-28`
- Auth: `Authorization: Bearer sck_...`

제공 도구는 대시보드, 심의 목록/상세, Security Control 검색, 제출 검증입니다. 현재 MCP 도구는 의도적으로 읽기 전용이며 상태 변경은 사람이 SecCheck UI에서 확인합니다. 모든 호출은 감사로그에 남습니다.

최신 요청은 `MCP-Protocol-Version`, `Mcp-Method`, 그리고 tool call의 `Mcp-Name` 헤더와 본문 `_meta`를 함께 보내야 합니다. 서버는 header/body 불일치를 거절하고 Origin을 검증합니다.
