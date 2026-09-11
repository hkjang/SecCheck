# SecCheck 공식 문서 허브 (Documentation Hub)

`SecCheck`는 Excel 기반 보안성 심의 업무를 템플릿·버전·제출 스냅샷·항목별 검토로 분리한 **오프라인 운영형 보안 검토 플랫폼**입니다.

---

## 📚 공식 기술 문서 (PDF 다운로드 & 바로보기)

> [!TIP]
> 모든 문서는 인쇄 및 가독성에 최적화된 **고품질 A4 PDF 문서**로 제공됩니다.

### 🌟 종합 완본 및 시연 영상
- 🎬 **[SecCheck 3분 서비스 시연 영상 (MP4)](seccheck_overview.mp4)**: 플랫폼 핵심 업무 흐름 및 CRU 시연 (1080p FHD, 3분 06초)
- 📕 **[SecCheck 종합 기술 매뉴얼 완본 (Complete Manual PDF)](seccheck_complete_manual.pdf)**: 기능 및 화면 가이드, API & MCP 연계 가이드, 시스템 아키텍처를 한 권으로 묶은 것 (A4 인쇄용). 사용자·관리자 가이드는 아래에 따로 있습니다

### 1. 사용자 및 기능 가이드
- 📄 **[기능 및 화면 가이드 (PDF)](seccheck_features_guide.pdf)** (`docs/seccheck_features_guide.pdf`) · [MD](features.md)
  - 25개 전체 메뉴별 실제 구동 화면 캡처 및 세부 CRU 기능 명세
- 📄 **[사용자 가이드 (PDF)](USER_GUIDE.pdf)** (`docs/USER_GUIDE.pdf`) · [MD](USER_GUIDE.md)
  - 처음 5분, 화면별 사용법(실제 화면 캡처), 자주 하는 작업, 막혔을 때, 용어

### 2. 아키텍처 및 시스템 설계
- 📄 **[시스템 아키텍처 및 보안 설계 (PDF)](seccheck_architecture.pdf)** (`docs/seccheck_architecture.pdf`) · [MD](architecture.md)
  - 3계층 스냅샷 불변 모델, AES-256-GCM 증적 암호화, 해시 체인 감사로그
- 📄 **[운영 및 배포 가이드 (Markdown)](operations.md)**
  - 단일 Docker 이미지 반입 및 패키지 릴리스 가이드

### 3. 관리자 및 운영 가이드
- 📄 **[관리자 가이드 (PDF)](ADMIN_GUIDE.pdf)** (`docs/ADMIN_GUIDE.pdf`) · [MD](ADMIN_GUIDE.md)
  - 구성 요소, 설치(docker load → compose → 최초 관리자), 환경 변수·설정 전수 표, 역할, 운영(백업·복구·업그레이드), 장애 대응, 보안

### 4. API & AI / MCP 연동
- 📄 **[API & MCP 연계 가이드 (PDF)](seccheck_api_guide.pdf)** (`docs/seccheck_api_guide.pdf`) · [MD](api-guide.md)
  - REST API 명세, Model Context Protocol(MCP) `2026-07-28` Stateless Streamable HTTP 명세
- 📄 **[OpenAPI 3.1 명세 (Markdown)](integrations.md)**
  - REST API & MCP 연계 계약 스키마

---

## 🔁 문서 다시 만들기

Markdown 이 정본이고 PDF 는 거기서 굽습니다. 문서를 고쳤으면 PDF 도 같은 커밋에서 다시 만듭니다.

```bash
scripts/build_docs_pdf.sh                # 전부
scripts/build_docs_pdf.sh user admin     # 사용자·관리자 가이드만
```

변환기는 공용 도구(`md2pdf.mjs`)를 쓰며 경로는 `MD2PDF` 환경 변수로 바꿀 수 있습니다. 화면 캡처는
`scripts/capture_all.js` 로 실제 서버에서 찍습니다 (스크립트 머리말의 필수 환경 변수 참고). 화면 하나를
더하거나 다시 찍을 때는 `SECCHECK_CAPTURE_ONLY=<파일명,…>` 으로 그 파일만 쓰게 하면 나머지 그림은 그대로 남습니다.

`scripts/precheck.sh` 는 원고(Markdown 과 거기 실린 그림)가 PDF 를 마지막으로 구운 뒤에 바뀌었는지
git 으로 확인해, PDF 를 다시 굽지 않은 채로 푸시하는 것을 막습니다. 어느 문서가 어느 PDF 가 되는지는
`scripts/build_docs_pdf.sh --list` 로 볼 수 있습니다.

---

## 🚀 빠른 시작 (Quick Start)

```bash
# 0. 받은 아카이브가 릴리즈 노트의 SHA-256과 같은지 먼저 확인
sha256sum seccheck-v0.1.0.tar.gz

# 1. 패키지 이미지 로드 (로드 후 image id도 릴리즈 노트와 대조할 수 있습니다)
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
