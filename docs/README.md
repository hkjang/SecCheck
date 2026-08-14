# SecCheck 공식 문서 허브 (Documentation Hub)

`SecCheck`는 Excel 기반 보안성 심의 업무를 템플릿·버전·제출 스냅샷·항목별 검토로 분리한 **오프라인 운영형 보안 검토 플랫폼**입니다.

---

## 📚 공식 기술 문서 (PDF 다운로드 & 바로보기)

> [!TIP]
> 모든 문서는 인쇄 및 가독성에 최적화된 **고품질 A4 PDF 문서**로 제공됩니다.

### 🌟 종합 완본
- 📕 **[SecCheck 종합 기술 매뉴얼 완본 (Complete Manual PDF)](seccheck_complete_manual.pdf)**: 아키텍처, 전체 기능, 사용자 실무, 관리자 운영, API & MCP 가이드가 통합된 종합 기술 완본 (A4 인쇄용)

### 1. 사용자 및 기능 가이드
- 📄 **[기능 및 화면 가이드 (PDF)](seccheck_features_guide.pdf)** (`docs/seccheck_features_guide.pdf`) · [MD](features.md)
  - 25개 전체 메뉴별 실제 구동 화면 캡처 및 세부 CRU 기능 명세
- 📄 **[사용자 실무 가이드 (PDF)](seccheck_user_guide.pdf)** (`docs/seccheck_user_guide.pdf`) · [MD](user-guide.md)
  - 심의 생성, Rule Engine, 체크리스트 작성, N/A 사유, 증적 업로드, 검토/승인 및 내보내기

### 2. 아키텍처 및 시스템 설계
- 📄 **[시스템 아키텍처 및 보안 설계 (PDF)](seccheck_architecture.pdf)** (`docs/seccheck_architecture.pdf`) · [MD](architecture.md)
  - 3계층 스냅샷 불변 모델, AES-256-GCM 증적 암호화, 해시 체인 감사로그
- 📄 **[운영 및 배포 가이드 (Markdown)](operations.md)**
  - 단일 Docker 이미지 반입 및 패키지 릴리스 가이드

### 3. 관리자 및 운영 가이드
- 📄 **[관리자 운영 가이드 (PDF)](seccheck_admin_guide.pdf)** (`docs/seccheck_admin_guide.pdf`) · [MD](admin-guide.md)
  - 4대 환경변수 부트스트랩, Keycloak OIDC SSO 연동, ClamAV 안티바이러스, RBAC 역할 관리, 체인 검증

### 4. API & AI / MCP 연동
- 📄 **[API & MCP 연계 가이드 (PDF)](seccheck_api_guide.pdf)** (`docs/seccheck_api_guide.pdf`) · [MD](api-guide.md)
  - REST API 명세, Model Context Protocol(MCP) `2026-07-28` Stateless Streamable HTTP 명세
- 📄 **[OpenAPI 3.1 명세 (Markdown)](integrations.md)**
  - REST API & MCP 연계 계약 스키마

---

## 🚀 빠른 시작 (Quick Start)

```bash
# 1. 패키지 이미지 로드
gzip -dc seccheck-v0.1.0.tar.gz | docker load

# 2. 필수 환경변수 4개로 컨테이너 실행
docker run -d --name seccheck --restart unless-stopped \
  -p 8080:8080 \
  -e POSTGRES_DSN='postgres://seccheck:password@postgres.internal:5432/seccheck?sslmode=require' \
  -e BOOTSTRAP_ADMIN='admin' \
  -e BOOTSTRAP_ADMIN_PASSWORD='your-strong-admin-password' \
  -e ENCRYPTION_KEY='your-32-char-random-encryption-key' \
  seccheck:v0.1.0
```

- **접속 주소**: `http://localhost:8080` (초기 관리자 계정: `admin`)
