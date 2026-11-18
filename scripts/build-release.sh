#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

version="$(tr -d '\r\n' < VERSION)"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid VERSION: $version (expected vMAJOR.MINOR.PATCH)" >&2
  exit 1
fi

output="$root/dist"
rm -rf "$output"
mkdir -p "$output"

targets=(
  windows/amd64
  windows/arm64
  windows/386
  linux/amd64
  linux/arm64
  linux/386
  linux/arm
  darwin/amd64
  darwin/arm64
  freebsd/amd64
  freebsd/arm64
)

for target in "${targets[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  filename="us-proxy-auditor.${os}-${arch}"
  if [[ "$os" == "windows" ]]; then
    filename+=".exe"
  fi
  echo "Building $filename ($version)"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" -o "$output/$filename" .
done

(
  cd "$output"
  sha256sum us-proxy-auditor.* > SHA256SUMS.txt
)

echo "Built ${#targets[@]} binaries and SHA256SUMS.txt in dist/."
