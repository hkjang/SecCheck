#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <version without v prefix>" >&2
  exit 2
fi

version="$1"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid semantic version: $version" >&2
  exit 2
fi

image="seccheck:v${version}"
archive="seccheck-v${version}.tar.gz"
temporary="${archive}.tmp.$$"
trap 'rm -f "$temporary"' EXIT
docker image inspect "$image" >/dev/null
docker save "$image" | gzip -9 > "$temporary"
gzip -t "$temporary"
mv "$temporary" "$archive"
trap - EXIT
echo "$archive"
