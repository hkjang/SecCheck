#!/usr/bin/env bash
# What CI will say, said here first.
#
# The secret scan has now failed twice on a push that looked harmless -- test
# password literals once, a list of passwords the service must refuse the
# other time -- and each time the answer came twenty minutes after the commit
# was already public. Everything here is a check the pipeline runs; the point
# is to run the cheap ones before pushing rather than after.
#
# Usage:  scripts/precheck.sh            (skips what it cannot run)
#         TEST_POSTGRES_DSN=... scripts/precheck.sh
set -uo pipefail
cd "$(dirname "$0")/.."

failed=0
step() { printf '\n=== %s\n' "$1"; }
fail() { printf '!!! %s\n' "$1"; failed=1; }

step "gofmt"
unformatted="$(gofmt -l . | grep -v '^web/' || true)"
if [ -n "$unformatted" ]; then
  fail "gofmt은 다음 파일을 다시 쓰고 싶어 합니다:"; printf '%s\n' "$unformatted"
fi

step "go vet"
go vet ./... || fail "go vet 실패"

step "go test"
if [ -n "${TEST_POSTGRES_DSN:-}" ]; then
  go test ./... || fail "테스트 실패"
else
  printf '건너뜀: TEST_POSTGRES_DSN이 없어 데이터베이스 테스트가 모두 skip됩니다.\n'
  printf '        CI는 PostgreSQL과 함께 돌리므로, 여기서 통과해도 CI가 통과한다는 뜻은 아닙니다.\n'
  go test ./... || fail "테스트 실패"
fi

step "프런트엔드"
if [ -d web/node_modules ]; then
  # The vitest suite reads the request bodies the screens write out and holds
  # them against internal/web/payloads.go -- a Go change that renames a field
  # is caught here, not by the person whose dialog starts answering 400.
  (cd web && npx tsc --noEmit && npm test --silent && npm run build >/dev/null) || fail "프런트엔드 타입체크·테스트 또는 빌드 실패"
else
  printf '건너뜀: web/node_modules가 없습니다 (cd web && npm ci).\n'
fi

step "가이드 그림"
# The guides are only as honest as their pictures. A reference to a capture
# that is not there makes the PDF build fail, but only once someone runs it;
# a capture nothing references is a screen the guide silently stopped
# showing after a rename. Both directions are checked, by file name only.
referenced="$(grep -rhoE 'screenshots/[A-Za-z0-9_./-]+\.png' README.md docs/*.md docs/index.html 2>/dev/null \
  | sed 's#.*screenshots/##' | sort -u)"
captured="$(ls docs/screenshots 2>/dev/null | sort)"
missing="$(comm -23 <(printf '%s\n' "$referenced") <(printf '%s\n' "$captured"))"
unused="$(comm -13 <(printf '%s\n' "$referenced") <(printf '%s\n' "$captured"))"
if [ -n "$missing" ]; then
  fail "문서가 참조하지만 docs/screenshots에 없는 그림입니다 (PDF 생성이 실패합니다):"; printf '%s\n' "$missing"
fi
if [ -n "$unused" ]; then
  fail "찍어 두었지만 어느 문서도 싣지 않는 그림입니다 (문서를 고치거나 파일을 지우세요):"; printf '%s\n' "$unused"
fi
# The guides are shot at a 1440-wide desktop window (scripts/capture_all.js),
# and a picture pasted in by hand at some other size stands out on the page
# next to the rest. The width is the four big-endian bytes at offset 16 of a
# PNG (the IHDR chunk), which od can read without any image tooling. Only
# the width: a full-page capture is legitimately taller than 900.
narrow="$(for f in docs/screenshots/*.png; do
  [ -f "$f" ] || continue
  width="$(od -An -tu1 -j16 -N4 "$f" | awk '{print $1*16777216 + $2*65536 + $3*256 + $4}')"
  [ "$width" = "1440" ] || printf '%s (%s px)\n' "${f#docs/screenshots/}" "$width"
done)"
if [ -n "$narrow" ]; then
  fail "너비가 1440px 이 아닌 그림입니다 (scripts/capture_all.js 로 다시 찍으세요):"; printf '%s\n' "$narrow"
fi

step "가이드 PDF"
# The PDFs are committed next to the Markdown they are baked from, and
# nothing rebuilds them on its own: features.md was re-pointed at new
# captures while its PDF kept the old ones until someone opened it. md2pdf is
# not available everywhere, so this does not rebuild anything -- it only asks
# git whether a document (or a picture it embeds) changed after its PDF was
# last baked, in the working tree or in history. The mapping comes from the
# build script so the two cannot disagree.
while read -r name pdf sources; do
  # shellcheck disable=SC2086  # sources is a space-separated list of paths
  inputs="$sources $(grep -hoE 'screenshots/[A-Za-z0-9_./-]+\.png' $sources 2>/dev/null | sed 's#^#docs/#' | sort -u | tr '\n' ' ')"
  if [ ! -f "$pdf" ]; then
    fail "$name: $pdf 가 없습니다. scripts/build_docs_pdf.sh $name 으로 만드세요."
    continue
  fi
  # A PDF that is itself modified was just rebuilt; nothing to say.
  [ -n "$(git status --porcelain -- "$pdf")" ] && continue
  # shellcheck disable=SC2086
  if [ -n "$(git status --porcelain --untracked-files=all -- $inputs)" ]; then
    fail "$name: 원고를 고쳤지만 $pdf 는 그대로입니다. scripts/build_docs_pdf.sh $name 으로 다시 구우세요."
    continue
  fi
  # shellcheck disable=SC2086
  src_commit="$(git log -1 --format=%H -- $inputs)"
  pdf_commit="$(git log -1 --format=%H -- "$pdf")"
  if [ -n "$src_commit" ] && [ -n "$pdf_commit" ] && ! git merge-base --is-ancestor "$src_commit" "$pdf_commit"; then
    fail "$name: $pdf 를 마지막으로 구운 커밋($(git rev-parse --short "$pdf_commit")) 뒤에 원고가 바뀌었습니다($(git rev-parse --short "$src_commit")). scripts/build_docs_pdf.sh $name 으로 다시 구우세요."
  fi
done < <(bash scripts/build_docs_pdf.sh --list)

step "비밀정보 스캔"
# The scanner and its digest are read from the workflow: a second copy of the
# pin here would drift, and then this script would be checking something the
# pipeline no longer runs.
scanner="$(grep -o 'ghcr.io/gitleaks/gitleaks@sha256:[0-9a-f]\{64\}' .github/workflows/ci.yml | head -1)"
if [ -z "$scanner" ]; then
  fail "ci.yml에서 gitleaks image를 찾지 못했습니다. 워크플로가 바뀌었는지 확인하세요."
elif command -v docker >/dev/null 2>&1; then
  # --no-git, like the pipeline: what matters is the tree about to be pushed.
  # Scanning history here would report the same handful of old test literals
  # every time, which is how a check teaches people to ignore it.
  docker run --rm -v "$PWD:/repo" "$scanner" detect --source=/repo --no-git --redact --no-banner --exit-code 1 \
    || fail "비밀정보 스캔에서 걸린 항목이 있습니다. CI도 같은 이유로 멈춥니다."
else
  printf '건너뜀: docker가 없어 비밀정보 스캔을 돌릴 수 없습니다. CI에서는 반드시 돌아갑니다.\n'
fi

printf '\n'
if [ "$failed" -eq 0 ]; then
  printf '통과: 여기서 확인할 수 있는 것은 모두 통과했습니다.\n'
else
  printf '실패: 위 항목을 고친 뒤 다시 실행하세요.\n'
fi
exit "$failed"
