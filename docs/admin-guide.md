# SecCheck 관리자 운영 가이드 (Admin Guide)

`SecCheck`는 오프라인 폐쇄망 및 엔터프라이즈 환경에서 외부 의존성 없이 안정적으로 동작하도록 설계된 보안 검토 플랫폼입니다.

---

## 1. 런타임 환경변수 4종

서비스 구동 시 필요한 환경변수는 정확히 다음 4개뿐이며, 그 외 모든 정책은 관리자 웹 콘솔에서 런타임으로 관리됩니다:

| 환경변수명 | 필수 여부 | 설명 | 예시 |
| :--- | :---: | :--- | :--- |
| `POSTGRES_DSN` | **필수** | PostgreSQL 연결 DSN (`sslmode=verify-full` 권장) | `postgres://seccheck:pass@postgres:5432/seccheck?sslmode=disable` |
| `BOOTSTRAP_ADMIN` | **필수** | 초기 로컬 관리자 아이디 | `admin` |
| `BOOTSTRAP_ADMIN_PASSWORD` | **필수** | 초기 관리자 비밀번호 (최소 12자 이상) | `ComplexPassword123!` |
| `ENCRYPTION_KEY` | **필수** | 비밀값 및 데이터 키 암호화용 32바이트 Master Key | `01234567890123456789012345678901` |

---

## 2. Keycloak OIDC SSO 엔터프라이즈 연동

`SecCheck`는 표준 OpenID Connect Discovery를 통해 사내 Keycloak과 원클릭으로 연동됩니다.

1. **Keycloak Client 설정**:
   - Client Type: `OpenID Connect`
   - Client Authentication: `ON` (Confidential)
   - Standard Flow: `ON`
   - Valid Redirect URIs: `https://<seccheck-host>/api/v1/auth/oidc/callback`
2. **관리자 콘솔 설정 (`/admin/settings` → `Keycloak OIDC`)**:
   - `Keycloak / OIDC SSO 활성화` ON
   - **Issuer URL**: `https://keycloak.company.internal/realms/enterprise`
   - **Client ID** & **Client Secret**: Keycloak 발급 자격증명 입력 (AES-256-GCM 암호화 보관)
   - **Callback URL**: `https://seccheck.company.internal/api/v1/auth/oidc/callback`
   - **사용자명 Claim**: `preferred_username`
   - **기본 역할**: `REQUESTER`
3. **연결 테스트**:
   - `Discovery 연결 테스트` 버튼을 클릭하여 엔드포인트 도달 가능 여부를 실시간 검증합니다.

---

## 3. RBAC 7대 역할 체계

| 역할 코드 | 한글 명칭 | 권한 범위 |
| :--- | :--- | :--- |
| `SYSTEM_ADMIN` | **시스템 관리자** | 서비스 설정, 사용자 및 역할 관리, 감사로그 열람 및 체인 검증 |
| `TEMPLATE_ADMIN` | **체크리스트 관리자** | 템플릿 생성/편집/게시, Security Control 등록, Excel 가져오기 |
| `SECURITY_REVIEWER` | **보안 담당자** | 보안 검토 Queue 조회, 검토 시작, 판정, 보완 요청 및 검증 완료 |
| `APPROVER` | **승인자** | 최종 승인 및 반려 의사결정 권한 |
| `REQUESTER` | **심의 요청자** | 신규 심의 생성, 체크리스트 작성, 증적 업로드, 제출 및 재제출 |
| `CONTRIBUTOR` | **공동 작성자** | 배정된 심의의 체크리스트 공동 작성 및 증적 첨부 |
| `AUDITOR` | **감사자** | 모든 심의 및 감사로그 읽기 전용 열람 권한 |

---

## 4. 파일 업로드 보안 & ClamAV 안티바이러스

- **Magic/MIME & 확장자 교차 검증**: 파일 확장자 위변조(예: `.exe`를 `.pdf`로 변경)를 서버 레벨에서 차단합니다.
- **AES-256-GCM 암호화 보관**: 모든 증적은 서버 디스크에 UUID 파일명으로 암호화되어 저장됩니다.
- **ClamAV 악성코드 검사**:
  - 관리자 설정에서 `ClamAV 악성코드 검사` 활성화 및 `clamav:3310` 데몬 주소 입력
  - ClamAV 검사 실패 또는 악성코드 탐지 시 파일 업로드는 즉시 차단(Fail-Closed)됩니다.

---

## 5. 암호학적 해시 체인 감사로그 무결성 검증

- **해시 체인 구조**:
  - 모든 행위(로그인, 심의 생성, 수정, 제출, 판정, 승인, 설정 변경, 키 회전)는 이전 이벤트의 해시(`prev_hash`)와 결합되어 SHA-256 해시 체인을 형성합니다.
  - 데이터베이스 직접 조작이나 위변조가 발생할 경우 체인이 즉시 깨집니다.
- **체인 검증 실행 (`/admin/audit`)**:
  - `체인 검증` 버튼을 누르면 서버가 전체 이벤트의 암호학적 링크를 전수 검사하여 `"N개 감사 이벤트의 해시 체인이 유효합니다."` 결과를 반환합니다.

---

## 6. 관측성 및 Prometheus 모니터링

| 엔드포인트 | 메서드 | 용도 | 설명 |
| :--- | :--- | :--- | :--- |
| `/health` | GET | Liveness Probe | 프로세스 생존 여부 확인 |
| `/ready` | GET | Readiness Probe | DB 풀 및 테이블 쿼리 가능 상태 확인 |
| `/metrics` | GET | Prometheus Metrics | API 요청수, 지연시간, 심의 상태별 통계, 증적 저장량, 실패 작업 수 수집 |
| `/mcp` | POST | Model Context Protocol | AI 에이전트 연계 인터페이스 (`2026-07-28`) |

---

## 7. 로그인 보호와 계정 잠금 (`/admin/settings` → `접근 보안`)

| 설정 | 기본값 | 설명 |
| :--- | :---: | :--- |
| `login_rate_limit_per_minute` | `30` | IP별 분당 로그인 **실패** 허용 횟수. 성공한 로그인은 계산하지 않습니다 |
| `max_login_failures` | `5` | 계정 잠금까지 허용할 연속 실패 횟수. `0`이면 잠금 미사용 |
| `lockout_minutes` | `15` | 자동 잠금 유지 시간 |
| `idle_timeout_minutes` | `0` | 유휴 세션 만료. `0`이면 세션 시간까지 유지 |
| `trusted_proxies` | (비어 있음) | X-Forwarded-For를 신뢰할 Reverse Proxy IP 또는 CIDR |

- 잠금은 `LOGIN_LOCKED` 감사 이벤트로 남고 `seccheck_accounts_locked` 지표로 관측합니다.
- 잠긴 계정은 `/admin/users` 화면의 `잠금 해제` 버튼으로 즉시 복구하며, 해제 역시 감사로그에 기록됩니다.
- 비밀번호를 잊은 로컬 계정은 같은 화면의 `비밀번호` 버튼으로 임시 비밀번호를 발급합니다. `임의 생성` 버튼으로 안전한 값을 만들고, 재설정하면 해당 사용자의 모든 세션이 종료되며 잠금도 함께 풀립니다. SSO 계정에는 사용할 수 없습니다.
- 사용자 목록은 이름·아이디·이메일·부서·역할로 검색하고 `로그인 잠김`, `비활성`, `로컬/SSO`로 좁혀 볼 수 있습니다.
- 잠금은 신규 로그인만 차단하고 이미 열려 있는 세션은 종료하지 않으므로, 제3자가 잠금을 이용해 사용자를 강제 로그아웃시킬 수 없습니다.
- **Reverse Proxy 뒤에 배치하는 구성에서는 `trusted_proxies` 설정이 필수입니다.** 비워 두면 모든 요청이 Proxy 한 IP로 집계되어 요청 제한과 감사로그의 접속 IP가 조직 전체 단위로 묶입니다.

---

## 8. 데이터 보존 자동 정리

서비스 시작 1분 뒤부터 매시간 다음을 5,000행 단위로 정리하므로 별도 cron이 필요하지 않습니다.

- 만료된 세션과 OIDC state
- `COMPLETED` 7일, `FAILED` 90일이 지난 알림 Job
- 일반 설정 `retention_days`(기본 1825일)가 지난 서버 로그와 인앱 알림
- 잠금 시간이 지난 계정의 로그인 실패 카운터

감사로그는 해시 체인 검증을 위해 자동 삭제하지 않습니다. 정리 결과는 `maintenance` component 서버 로그에서 확인합니다.

---

## 9. 감사로그 조회와 반출

- **필터**: 이벤트 유형(앞부분만 입력해도 하위 이벤트까지 매칭), 사용자명 또는 접속 IP, 기간(시작일·종료일), 표시 건수.
- **상세 보기**: 이벤트 뱃지를 클릭하면 변경 전후 값, 요청 ID, 이전 해시와 이벤트 해시를 전체 확인할 수 있습니다.
- **CSV 내보내기**: 현재 필터 그대로 최대 50,000행을 UTF-8 BOM CSV로 내려받습니다. Excel에서 바로 열리며, 내보내기 행위 자체도 `EXPORT_AUDIT` 이벤트로 감사로그에 남습니다.

## 10. 서버 로그 조회

- 메시지, 구성요소, 요청 ID, 구조화 필드(경로·상태코드 등)를 한 번에 검색합니다.
- `10초 자동 새로고침`을 켜면 장애 대응 중 화면을 유지한 채 최신 로그를 추적할 수 있습니다.
- 감사로그의 요청 ID를 서버 로그 검색창에 붙여 넣으면 동일 요청의 처리 결과를 바로 연결해 볼 수 있습니다.
