<div align="center">

# SecCheck (Enterprise Security Review Platform)

<p>
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.26" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React 19" />
  <img src="https://img.shields.io/badge/PostgreSQL-17-4169E1?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/MCP-2026--07--28-8A2BE2?style=flat-square" alt="MCP" />
  <img src="https://img.shields.io/badge/Release-v1.0.58-success?style=flat-square" alt="v1.0.58" />
</p>

<h3>Excel 보안 심의를 넘어 추적 가능한 Security Control로.</h3>

<p align="center">
  <b>SecCheck</b>는 Excel 기반 보안성 심의를 템플릿·버전·제출 스냅샷·항목별 검토로 분리하고,<br>
  Rule Engine 자동 배정과 암호학적 해시 체인 감사로그를 지원하는 엔터프라이즈 오프라인 운영형 보안 검토 플랫폼입니다.
</p>

[**🎬 3분 서비스 시연 영상 (MP4)**](docs/seccheck_overview.mp4) · [**📕 종합 기술 매뉴얼 완본 (PDF)**](docs/seccheck_complete_manual.pdf) · [**🌐 인터랙티브 웹 쇼케이스**](docs/index.html) · [**📚 문서 허브**](docs/README.md)

</div>

---

## 📸 주요 화면 둘러보기

<div align="center">

### 📊 보안 심의 현황 대시보드
![대시보드](docs/screenshots/02_dashboard.png)

### 📋 체크리스트 & 실시간 진행 집계
![체크리스트 상세](docs/screenshots/05_review_detail_checklist.png)

<details>
<summary><b>👉 더 많은 기능 화면 스크린샷 접기/펼치기</b></summary>
<br/>

| 화면명 | 캡처 이미지 | 설명 |
| :--- | :--- | :--- |
| **로그인 & SSO** | ![로그인](docs/screenshots/01_login.png) | 부트스트랩 관리자 및 Keycloak OIDC 통합 로그인 |
| **심의 목록** | ![심의 목록](docs/screenshots/03_reviews_list.png) | 다차원 상태 필터링 및 심의 현황 테이블 |
| **신규 심의 요청** | ![신규 심의](docs/screenshots/04_new_review_form.png) | 서비스 정보 및 Rule Engine 9대 적용 조건 |
| **항목 편집 & 증적** | ![항목 편집](docs/screenshots/06_review_item_editor.png) | 자체 판단, N/A 사유, AES-256 증적 첨부 |
| **배정 조정 모달** | ![배정 조정](docs/screenshots/09_review_rule_override_modal.png) | Rule Engine 결과 수동 제외/포함 조정 |
| **보안 검토 Queue** | ![보안 검토](docs/screenshots/10_security_reviews.png) | 보안 담당자 전용 제출/재제출 심의 대기열 |
| **Security Controls** | ![통합 Controls](docs/screenshots/11_controls_catalog.png) | 통제 코드 관리 및 템플릿/심의 영향 범위 추적 |
| **템플릿 관리** | ![템플릿](docs/screenshots/12_templates_list.png) | 개발보안, 개인정보, 클라우드, K8s 기본 탑재 |
| **템플릿 상세/규칙** | ![템플릿 상세](docs/screenshots/13_template_detail.png) | 카테고리, 항목, 중요도 및 자동 배정 조건 |
| **Excel 가져오기** | ![Excel 마법사](docs/screenshots/14_excel_import_wizard.png) | 기존 엑셀 체크리스트 업로드 및 컬럼 매핑 |
| **개인 키 & 암호화** | ![키 관리](docs/screenshots/16_api_keys_and_encryption.png) | Bearer API 키 발급 및 증적 암호화 키 회전 |
| **API · MCP 연계** | ![MCP 연계](docs/screenshots/18_integrations_mcp.png) | REST API 명세 및 MCP `2026-07-28` 도구 규격 |
| **사용자 및 역할** | ![사용자 관리](docs/screenshots/19_admin_users.png) | RBAC 7대 역할 체계 및 활성 제어 |
| **해시 체인 감사로그** | ![감사로그](docs/screenshots/25_admin_audit_hashchain.png) | SHA-256 해시 체인 무결성 전수 검증 |
| **구조화 서버 로그** | ![서버 로그](docs/screenshots/26_admin_logs.png) | 민감정보 마스킹 요청 ID 기반 서버 로그 |

</details>

</div>

---

## 🏗️ 시스템 아키텍처

```
      ┌─────────────────────────────────────────────────────────────┐
      │           Web Browser / Keycloak OIDC Client                │
      │        - React + TypeScript + Lucide UI                     │
      │        - Checklist Editor with Auto-Save & Evidence Upload  │
      │        - Hash Chain Verification & Multi-format Export      │
      └──────────────┬──────────────────────────────▲───────────────┘
                     │ REST API (/api/v1)           │ Static Assets &
                     │ JSON-RPC 2.0 (/mcp)          │ OpenAPI Spec
      ┌──────────────▼──────────────────────────────┴───────────────┐
      │                  SecCheck Daemon (Go 1.26)                  │
      │  - HTTP Server & Static Bundle Embed                        │
      │  - Rule Engine (Service Characteristic Evaluation)          │
      │  - Evidence Encryption Engine (AES-256-GCM Envelope)        │
      │  - Hash-Chaining Audit Engine (SHA-256 Immutability)        │
      │  - Background SMTP Worker (SKIP LOCKED Queue)               │
      └──────────────┬──────────────────────────────┬───────────────┘
                     │                              │
                     ▼                              ▼
      ┌─────────────────────────────┐┌──────────────────────────────┐
      │     PostgreSQL Database     ││   Encrypted Evidence Store   │
      │ - review_requests / items   ││ - UUID Filename Storage      │
      │ - templates / controls      ││ - Magic/MIME Validated       │
      │ - audit_logs (hash chained) ││ - AES-256-GCM Encrypted      │
      │ - notify_jobs (SKIP LOCKED) ││ - Multi-versioned            │
      └─────────────────────────────┘└──────────────────────────────┘
```

---

## 📖 공식 기술 문서 (PDF)

| 문서명 | 설명 | PDF 다운로드 / 바로보기 |
| :--- | :--- | :--- |
| **🎬 3분 서비스 시연 영상** | 플랫폼 핵심 업무 흐름 및 실시간 CRU 시연 (1080p FHD, 3분 06초) | [**docs/seccheck_overview.mp4**](docs/seccheck_overview.mp4) |
| **📕 종합 기술 매뉴얼 완본** | 모든 아키텍처·기능·실무·운영·API 통합 기술 완본 (A4 인쇄용) | [**docs/seccheck_complete_manual.pdf**](docs/seccheck_complete_manual.pdf) |
| **📸 기능 및 화면 가이드** | 전체 메뉴별 화면 가이드와 캡처 스크린샷, CRU 동작 설명 | [**PDF 바로보기**](docs/seccheck_features_guide.pdf) · [MD](docs/features.md) |
| **👤 사용자 실무 가이드** | 심의 생성, Rule Engine, 체크리스트 작성, N/A, 증적 첨부, 승인 | [**PDF 바로보기**](docs/seccheck_user_guide.pdf) · [MD](docs/user-guide.md) |
| **🛠️ 관리자 운영 가이드** | 4대 환경변수, Keycloak SSO, ClamAV, RBAC 역할, 체인 검증 | [**PDF 바로보기**](docs/seccheck_admin_guide.pdf) · [MD](docs/admin-guide.md) |
| **🔌 API & MCP 가이드** | REST API 명세, Model Context Protocol(MCP) `2026-07-28` 스펙 | [**PDF 바로보기**](docs/seccheck_api_guide.pdf) · [MD](docs/api-guide.md) |
| **🏗️ 시스템 아키텍처** | 3계층 불변 모델, AES-256-GCM 증적 암호화, 해시 체인 감사로그 | [**PDF 바로보기**](docs/seccheck_architecture.pdf) · [MD](docs/architecture.md) |
| **🌐 웹 쇼케이스** | 인터랙티브 깃허브 홍보 및 기능 둘러보기 웹페이지 | [**쇼케이스 열기**](docs/index.html) |
| **📚 문서 허브** | 전체 공식 기술 문서 목차 및 시작 가이드 | [**문서 허브 열기**](docs/README.md) |

---

## 🚀 빠른 시작 (Quick Start)

`SecCheck`가 런타임으로 요구하는 환경변수는 정확히 4개뿐입니다:

```bash
docker run -d --name seccheck --restart unless-stopped \
  -p 8080:8080 \
  -e POSTGRES_DSN='postgres://seccheck:password@postgres.internal:5432/seccheck?sslmode=require' \
  -e BOOTSTRAP_ADMIN='admin' \
  -e BOOTSTRAP_ADMIN_PASSWORD='your-strong-password' \
  -e ENCRYPTION_KEY='your-32-char-random-encryption-key' \
  seccheck:v1.0.58
```

- **접속 주소**: `http://localhost:8080` (초기 관리자 계정: `admin`)

---

## 🔐 접근 보안 기본값

| 항목 | 기본값 | 관리자 설정 |
| :--- | :--- | :--- |
| 계정 잠금 | 연속 로그인 실패 5회 → 15분 잠금 | `max_login_failures`, `lockout_minutes` |
| 로그인 실패 제한 | IP별 분당 30회 (성공은 미계산) | `login_rate_limit_per_minute` |
| 유휴 세션 만료 | 사용 안 함 | `idle_timeout_minutes` |
| 실제 클라이언트 IP 판별 | 사용 안 함 | `trusted_proxies` (Reverse Proxy IP/CIDR) |
| 관리자 2단계 인증 | 사용 안 함 | `require_totp_for_admins` (TOTP, RFC 6238) |
| `/metrics` 공개 | 인증 없이 공개 | `metrics_public` (끄면 읽기 범위 API 키 필요) |

잠긴 계정은 관리자 > 사용자 및 역할 화면에서 즉시 해제하거나 임시 비밀번호를 재발급하며, 잠금과 해제 모두 해시 체인 감사로그에 남습니다. 로컬 계정 사용자는 개인 프로필에서 직접 비밀번호를 변경할 수 있고, 변경 시 다른 기기의 세션이 모두 종료됩니다. 만료 세션, 완료된 알림 Job, 보존 기간이 지난 서버 로그와 인앱 알림은 매시간 자동 정리되고 감사로그는 체인 검증을 위해 보존됩니다. Reverse Proxy 뒤에 배치할 때는 `trusted_proxies`를 반드시 설정해야 요청 제한과 감사로그가 사용자 단위로 동작합니다. 업그레이드 시 확인할 스키마·설정 변경은 [CHANGELOG](CHANGELOG.md)에, 운영 절차는 [운영 가이드](docs/operations.md)에 있습니다.

증적 무결성은 복구 훈련에서 직접 증명할 수 있습니다. 업그레이드한 image가 실제로 동작하는지는 `selftest`가 종료 코드로 답합니다.

```bash
docker compose exec seccheck /app/seccheck verify-evidence
docker compose exec seccheck /app/seccheck selftest --username admin --password '****'          # 읽기 전용
docker compose exec seccheck /app/seccheck selftest --username admin --password '****' --full   # 검증 환경: 심의 생성과 Excel·PDF·ZIP 내보내기까지
docker compose exec seccheck /app/seccheck admin-recover --username admin --password '****' --unlock   # 마지막 관리자가 막혔을 때
```
