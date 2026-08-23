# SecCheck API & MCP 연계 가이드 (API & MCP Guide)

`SecCheck`는 시스템 연계 및 CI/CD 자동화를 위한 **REST API**와 AI 에이전트(Claude Desktop, Cursor 등) 연동을 위한 **Model Context Protocol (MCP)** 인터페이스를 제공합니다.

---

## 1. 인증 체계 (Authentication)

모든 API 및 MCP 호출은 개인 키 관리(`/profile/keys`)에서 발급받은 **Bearer API Key** 또는 세션 쿠키를 사용합니다:

```http
Authorization: Bearer sck_a1b2c3d4_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 1-1. OpenAPI 명세

전체 API 명세는 로그인 상태에서 `GET /api/openapi.json`으로 받습니다. 명세는 서버의 라우트 등록 테이블에서 생성되므로 **문서화되지 않은 엔드포인트가 존재할 수 없습니다.** 각 operation에는 다음이 포함됩니다.

- `summary` · `tags` — 한글 설명과 기능 분류
- `operationId` — 메서드와 경로에서 파생된 안정적인 식별자 (클라이언트 자동 생성용)
- `parameters` — 경로 파라미터 선언
- `requestBody` — 본문을 받는 operation의 JSON 속성과 타입. 서버가 알 수 없는 속성을 거부하므로 스키마도 `additionalProperties: false`입니다. 즉 명세대로 보내면 그대로 통과합니다
- `x-object-scoped` — `true`이면 역할이 아니라 **대상 심의에 대한 접근 권한**으로 판단합니다. 요청자·공동 작성자·지정된 검토자·승인자가 해당하며, 조회는 `SECURITY_REVIEWER`와 `AUDITOR`도 모든 심의에 접근합니다. `SYSTEM_ADMIN`은 포함되지 않습니다 — 서비스 운영 권한이 남의 심의 열람 권한은 아닙니다. 권한이 없으면 404이므로, 역할만 보고 호출 가능 여부를 판단하면 안 됩니다
- `x-required-roles` — 호출에 필요한 RBAC 역할. 빈 배열이면 로그인한 모든 사용자가 호출 가능
- `security: []` — 인증 없이 호출 가능한 엔드포인트 (`/api/v1/auth/login`, `/api/v1/public/config` 등)

아래 표는 자주 쓰는 엔드포인트만 추린 것이며, 전체 목록은 명세를 참조하십시오.

## 2. REST API 주요 엔드포인트 (`/api/v1`)

### 📋 심의 요청 및 관리 (Review Requests)
| 메서드 | 경로 | 설명 | 권한 |
| :--- | :--- | :--- | :--- |
| `GET` | `/review-requests` | 심의 목록 조회 (필터: `q`, `status`) | 전체 (권한 범위의 심의만 반환) |
| `POST` | `/review-requests` | 신규 심의 생성 및 Rule Engine 자동 배정 | `REQUESTER` |
| `GET` | `/review-requests/{id}` | 심의 상세 정보 및 진행 통계 조회 | 담당자, 검토자, 승인자 |
| `GET` | `/review-requests/{id}/items` | 심의에 배정된 체크리스트 항목 및 답변 목록 | 담당자, 검토자, 승인자 |
| `PUT` | `/review-requests/{id}/responses/{itemID}` | 체크리스트 항목 작성 및 자동 저장 | 해당 심의 참여자 |
| `POST` | `/review-requests/{id}/submit` | 심의 제출 (서버 검증 실행) | 해당 심의 참여자 |
| `POST` | `/review-requests/{id}/begin-review` | 보안 검토 시작 (`REVIEWING` 전환) | `SECURITY_REVIEWER` |
| `PUT` | `/review-requests/{id}/review-results/{itemID}` | 항목별 검토 결과 및 의견 저장 | `SECURITY_REVIEWER` |
| `POST` | `/review-requests/{id}/approve` | 심의 최종 승인 | `APPROVER` |
| `POST` | `/review-requests/{id}/reject` | 심의 반려 | `APPROVER` |

### 📎 증적 파일 (Evidences)
| 메서드 | 경로 | 설명 | 권한 |
| :--- | :--- | :--- | :--- |
| `POST` | `/review-requests/{id}/items/{itemID}/evidences` | 증적 파일 암호화 업로드 (`multipart/form-data`) | 해당 심의 참여자 |
| `GET` | `/evidences/{id}/download` | 증적 파일 복호화 다운로드 | 권한자 |
| `POST` | `/evidences/{id}/versions` | 증적 파일 신규 버전 교체 등록 | 해당 심의 참여자 |

### 🛡️ 통합 Security Controls & 템플릿
| 메서드 | 경로 | 설명 | 권한 |
| :--- | :--- | :--- | :--- |
| `GET` | `/security-controls` | 통합 Security Control 목록 및 영향 통계 | 전체 |
| `GET` | `/security-controls/{id}/impact` | 특정 Control 변경 시 영향 받는 템플릿/심의 조회 | 전체 |
| `GET` | `/templates` | 체크리스트 템플릿 목록 및 게시 버전 조회 | 전체 |

---

## 3. Model Context Protocol (MCP) 엔드포인트

- **엔드포인트**: `POST /mcp`
- **프로토콜 버전**: MCP `2026-07-28` Stateless Streamable HTTP (구형 `2025-11-25` 호환)
- **인증**: `Authorization: Bearer <API_KEY>`

### 🛠️ 제공 도구 목록 (Tools)
1. `seccheck.dashboard`: 대시보드 통계 및 긴급 처리 건수 조회
2. `seccheck.list_reviews`: 상태 및 키워드 기반 심의 목록 검색
3. `seccheck.get_review`: 특정 심의의 상세 정보, 진행률, 체크리스트 항목 조회
4. `seccheck.search_controls`: Security Control 및 체크리스트 가이드 검색
5. `seccheck.validate_submission`: 제출 전 누락 항목 및 결함 사전 검증
6. `seccheck.my_queue`: 지금 본인이 처리해야 하는 심의와 기한이 임박한 보완 요청 조회
7. `seccheck.review_report`: 기간별 처리 현황·소요 기간·부서별 집계·반복 미흡 항목 조회 (`SYSTEM_ADMIN`, `SECURITY_REVIEWER`, `AUDITOR`, `APPROVER`)

도구는 모두 호출자의 권한 범위 안에서만 답합니다. 읽기 전용이 아닌 도구를 API 키로 호출하려면 키에 쓰기 범위가 있어야 하며, 전체 목록과 입력 스키마는 `tools/list`로 확인합니다.

### 💬 MCP 호출 예시 (JSON-RPC 2.0)

#### 요청: 심의 제출 전 결함 사전 검증
```json
{
  "jsonrpc": "2.0",
  "id": "req-201",
  "method": "tools/call",
  "params": {
    "name": "seccheck.validate_submission",
    "arguments": {
      "review_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
    }
  }
}
```

#### 응답
```json
{
  "jsonrpc": "2.0",
  "id": "req-201",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "검증 결과: 제출 가능한 상태입니다. (작성 완료: 45/45, 필수 증적 첨부: 12건)"
      }
    ]
  }
}
```
