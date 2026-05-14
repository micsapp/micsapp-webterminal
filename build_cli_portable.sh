#!/usr/bin/env bash
# build_cli_portable.sh — Build portable mics_cli Linux binaries that run on
# any glibc ≥ 2.17 host (RHEL 7, Ubuntu 16.04+, Debian 8+, Amazon Linux 2,
# all current LTS distros).
#
# The trick is purely in the pkg invocation, not in the build host:
#
#   * pkg-fetch's prebuilt Node-runtime binaries for the `node16-linux-*`
#     targets were built on CentOS 7 (glibc 2.17). The pkg binary's glibc
#     symbol-version requirements come from that prebuilt runtime, not from
#     whoever runs pkg — so this script works on any modern Linux host.
#   * Upstream `pkg@5.8.1` is the last release whose prelude handles Node 16
#     cleanly; the `@yao-pkg/pkg` fork that build_cli.sh uses crashes at
#     startup on Node 16 targets ("promisify of undefined").
#   * Node 18 was the first LTS to drop CentOS 7 support (its prebuilt Linux
#     binary requires glibc 2.28), which is why build_cli.sh's default
#     binaries fail on Ubuntu 16.04.
#
# Output: cli/dist/mics_cli-linux-x64-portable and -arm64-portable.
#
# Usage:
#   ./build_cli_portable.sh

set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="${PROJECT_DIR}/cli"

PKG_VERSION="${PKG_VERSION:-pkg@5.8.1}"
PKG_TARGET="${PKG_TARGET:-node16}"

command -v npm >/dev/null 2>&1 || { echo "npm is required." >&2; exit 1; }
command -v objdump >/dev/null 2>&1 || echo "WARN: objdump not installed; glibc check will be skipped." >&2

cd "${CLI_DIR}"

# Regenerate build-info so the binary carries the right SHA.
node scripts/build-info.js

mkdir -p dist
# Clear stale portable binaries so pkg won't accidentally bundle them.
rm -f dist/mics_cli-linux-x64-portable dist/mics_cli-linux-arm64-portable

run_pkg() {
  npm exec --yes --package="$PKG_VERSION" -- pkg "$@"
}

echo "==> Building dist/mics_cli-linux-x64-portable (${PKG_TARGET}-linux-x64) with $PKG_VERSION"
run_pkg . --targets "${PKG_TARGET}-linux-x64" --output dist/mics_cli-linux-x64-portable

echo "==> Building dist/mics_cli-linux-arm64-portable (${PKG_TARGET}-linux-arm64) with $PKG_VERSION"
run_pkg . --targets "${PKG_TARGET}-linux-arm64" --output dist/mics_cli-linux-arm64-portable

chmod 0755 dist/mics_cli-linux-x64-portable dist/mics_cli-linux-arm64-portable

echo ""
echo "==> Verifying glibc compatibility:"
for f in dist/mics_cli-linux-x64-portable dist/mics_cli-linux-arm64-portable; do
  if command -v objdump >/dev/null 2>&1; then
    highest=$(objdump -T "$f" 2>/dev/null | grep -oE "GLIBC_2\.[0-9]+" | sort -V | tail -1)
    case "$highest" in
      GLIBC_2.1[0-7]|GLIBC_2.[0-9]) status="OK — glibc ≥ 2.17 hosts will run this" ;;
      "") status="(no GLIBC_* refs found — double-check with file/readelf)" ;;
      *) status="WARN: requires $highest; portable target is 2.17" ;;
    esac
    printf "  %-44s  highest=%-12s  %s\n" "$f" "${highest:-<none>}" "$status"
  fi
done

echo ""
echo "==> Local smoke test (x64 binary; arm64 must be tested on an arm host):"
./dist/mics_cli-linux-x64-portable version 2>&1 || true

echo ""
echo "==> Built:"
ls -lh dist/mics_cli-linux-*-portable 2>/dev/null
