# SecCheck

SecCheck는 Excel 기반 보안성 심의를 템플릿·버전·제출 스냅샷·항목별 검토로 분리한 오프라인 운영형 보안 검토 플랫폼입니다. 원본 체크리스트에서 정규화한 개발보안, 개인(신용)정보, 클라우드, Docker, Kubernetes 기본 데이터를 첫 구동 시 게시 템플릿으로 자동 등록합니다. 원본 XLSX는 소스 저장소나 컨테이너 이미지에 포함하지 않습니다.

## 핵심 기능

- 게시 후 불변인 체크리스트 버전과 제출 시점 Snapshot
- 서비스 특성 기반 Rule Engine과 수동 변경 사유
- 통합 Security Control과 템플릿·기존 심의 영향 범위 추적
- 임시/자동 저장, N/A 사유, 증적 누락을 포함한 서버 제출 검증
- 항목별 검토, 무제한 보완·재제출, 설정형 최종 승인
- UUID 파일명, Magic/MIME 검증, SHA-256, AES-256-GCM, 파일 버전과 선택형 ClamAV
- Keycloak 등 표준 OIDC SSO, 로컬 bootstrap 관리자, Backend RBAC/객체 권한
- 사용자별 API 키 및 증적 암호화 키 버전·회전
- 해시 체인 감사로그, 구조화 서버 로그, `/health`, `/ready`, `/metrics`
- PostgreSQL `SKIP LOCKED` 작업 큐 기반 SMTP 알림·재시도와 인앱 알림
- Excel/PDF/JSON/ZIP 결과 내보내기, Excel Import Wizard
- REST/OpenAPI 및 MCP `2026-07-28` Stateless Streamable HTTP (구형 `2025-11-25` 초기화 호환)

## 배포

서비스 컨테이너에는 런타임 인터넷 연결이 필요하지 않습니다. PostgreSQL과 TLS 종료 Reverse Proxy는 운영망에 별도로 준비합니다.

```bash
docker load < seccheck-v0.1.0.tar.gz
cp .env.example .env
# .env의 네 값 설정
docker compose up -d
```

SecCheck 서비스가 받는 환경변수는 다음 네 개뿐입니다.

| 변수 | 설명 |
|---|---|
| `POSTGRES_DSN` | PostgreSQL DSN. 운영에서는 `sslmode=verify-full` 권장 |
| `BOOTSTRAP_ADMIN` | 최초 로컬 관리자 사용자명 |
| `BOOTSTRAP_ADMIN_PASSWORD` | 최초 관리자 비밀번호. 최소 12자 이상의 임의값 권장 |
| `ENCRYPTION_KEY` | 32 raw byte 또는 32 byte를 Base64로 인코딩한 Master Key |

그 밖의 OIDC client ID/secret, 승인 절차, 업로드/ClamAV, 세션, SMTP 알림, CORS와 보안 설정은 서비스 관리자 화면에서 관리합니다. OIDC Client Secret과 SMTP 비밀번호는 Master Key로 암호화됩니다.

새 키 생성 예시:

```bash
openssl rand -base64 32
```

`ENCRYPTION_KEY`를 분실하면 암호화된 설정과 사용자 증적 키를 복구할 수 없습니다. 데이터와 분리된 비밀 관리 시스템 및 암호화 백업에 보관하십시오.

## 로컬 개발

```bash
npm ci --prefix web
npm --prefix web run build
go test ./...
go run -ldflags '-X main.version=0.1.0' ./cmd/seccheck
```

개발 실행도 동일한 네 환경변수와 접근 가능한 PostgreSQL이 필요합니다.

## 운영 보안

- TLS는 Reverse Proxy에서 종료하고 관리자 설정의 Secure Cookie를 켭니다.
- 증적 볼륨 `/app/data`는 실행 불가(noexec) 정책, 최소권한 UID 10001, 별도 암호화 백업을 적용합니다.
- PostgreSQL은 정기 Full/PITR 백업을 구성하고, 증적 볼륨과 설정 DB를 같은 복구 시점으로 보존합니다.
- 분기별 복구 훈련에서 별도 격리 환경에 DB/증적/Master Key를 복구하고 증적 SHA-256 다운로드 검증 결과를 변경관리 시스템에 기록합니다.
- ClamAV를 사용할 때 관리자 설정에 `host:port`를 입력합니다. 검사 장애 시 파일 업로드는 fail-closed 됩니다.
- `/metrics`는 내부 Monitoring allowlist에서만 접근하도록 Reverse Proxy에서 제한합니다.
- Bootstrap 관리자는 SSO 관리자가 준비된 뒤 비활성화할 수 있습니다. 비활성화 시 기존 세션도 삭제됩니다.

자세한 구성과 운영 절차는 [운영 가이드](docs/operations.md), API/MCP는 [연계 가이드](docs/integrations.md)를 참고하세요.

## 릴리스

`v0.1.0`과 같은 tag를 push하면 GitHub Actions가 테스트·의존성/비밀/컨테이너/DAST Gate, SBOM 생성·검사, provenance attestation을 수행합니다. GitHub Release에는 요청한 형식의 단일 자산 `seccheck-v0.1.0.tar.gz`만 첨부되며 내부 Docker image 이름은 `seccheck:v0.1.0`입니다.
