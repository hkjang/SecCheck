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
  (cd web && npx tsc --noEmit && npm run build >/dev/null) || fail "프런트엔드 타입체크 또는 빌드 실패"
else
  printf '건너뜀: web/node_modules가 없습니다 (cd web && npm ci).\n'
fi

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
