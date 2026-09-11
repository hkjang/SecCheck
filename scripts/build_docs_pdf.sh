#!/usr/bin/env bash
# Bake the Markdown under docs/ into the PDFs that sit next to it.
#
# The PDFs are committed, so they drift: features.md was re-pointed at the
# new captures while seccheck_features_guide.pdf kept showing the old ones.
# This script is the one place that knows which Markdown becomes which PDF,
# so regenerating after a doc change is a single command. The rendering
# itself is the shared md2pdf tool -- one converter for every project, not
# one per repository -- which also refuses to build when a picture is missing.
#
# Usage:  scripts/build_docs_pdf.sh            (all documents)
#         scripts/build_docs_pdf.sh user admin (only those)
#         MD2PDF=/path/to/md2pdf.mjs scripts/build_docs_pdf.sh
#
# Names: user admin features api architecture manual
set -euo pipefail
cd "$(dirname "$0")/.."

MD2PDF="${MD2PDF:-/mnt/c/Users/USER/projects/aidev/tools/guide/md2pdf.mjs}"
if [ ! -f "$MD2PDF" ]; then
  printf 'md2pdf 를 찾지 못했습니다: %s\nMD2PDF=<경로> 로 지정하세요.\n' "$MD2PDF" >&2
  exit 2
fi
tool_dir="$(dirname "$MD2PDF")"
if [ ! -d "$tool_dir/node_modules" ]; then
  (cd "$tool_dir" && npm install --no-audit --no-fund)
fi

VERSION="${DOCS_VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || echo dev)}"

build() { # <input.md> <output.pdf> <title> <subtitle>
  printf '\n=== %s -> %s\n' "$1" "$2"
  node "$MD2PDF" "$1" "$2" --title "$3" --subtitle "$4" --project "SecCheck" --version "$VERSION"
}

# The complete manual is the three technical documents back to back. They
# are concatenated inside docs/ so their ./screenshots/ paths still resolve.
manual() {
  local tmp=docs/.complete_manual.md
  trap 'rm -f "$tmp"' RETURN
  cat docs/features.md docs/api-guide.md docs/architecture.md >"$tmp"
  build "$tmp" docs/seccheck_complete_manual.pdf "종합 기술 매뉴얼" "기능·화면, API·MCP, 아키텍처를 한 권으로"
}

targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(user admin features api architecture manual)

for t in "${targets[@]}"; do
  case "$t" in
    user)         build docs/USER_GUIDE.md docs/USER_GUIDE.pdf "사용자 가이드" "보안성 심의를 요청하고, 검토하고, 승인하는 사람을 위해" ;;
    admin)        build docs/ADMIN_GUIDE.md docs/ADMIN_GUIDE.pdf "관리자 가이드" "SecCheck 를 설치하고 운영하는 사람을 위해" ;;
    features)     build docs/features.md docs/seccheck_features_guide.pdf "기능 및 화면 가이드" "전체 메뉴별 실제 화면과 기능 명세" ;;
    api)          build docs/api-guide.md docs/seccheck_api_guide.pdf "API & MCP 연계 가이드" "REST API 와 Model Context Protocol 로 SecCheck 에 연결하기" ;;
    architecture) build docs/architecture.md docs/seccheck_architecture.pdf "시스템 아키텍처 및 보안 설계" "스냅샷 불변 모델, 증적 암호화, 해시 체인 감사로그" ;;
    manual)       manual ;;
    *) printf '알 수 없는 문서 이름: %s (user admin features api architecture manual)\n' "$t" >&2; exit 2 ;;
  esac
done
