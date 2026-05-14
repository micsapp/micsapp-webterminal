#!/usr/bin/env bash
set -euo pipefail

# Build the mics_cli binary into cli/dist/.
# Default target is the current OS/arch; pass an explicit target as the first
# argument to cross-compile (or 'all' for every supported target).
#
# Usage:
#   ./build_cli.sh                   # current host (fast)
#   ./build_cli.sh linux             # Linux x64 + arm64 (node20, glibc 2.28+)
#   ./build_cli.sh linux-portable    # Linux x64 + arm64 (node16, glibc 2.17 / Ubuntu 16.04+)
#   ./build_cli.sh mac               # macOS x64 + arm64
#   ./build_cli.sh win               # Windows x64
#   ./build_cli.sh all               # everything (modern + portable Linux + mac + win)
#   ./build_cli.sh clean             # rm cli/dist/

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="${PROJECT_DIR}/cli"
TARGET="${1:-host}"

say() { printf '%s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }

if [ ! -d "${CLI_DIR}" ]; then
  err "cli directory not found at ${CLI_DIR}"
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  err "node is not installed (need Node 18+)"
  exit 1
fi

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "${NODE_MAJOR}" -lt 18 ]; then
  err "Node ${NODE_MAJOR} is too old; need Node 18+"
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  err "npm is not installed"
  exit 1
fi

cd "${CLI_DIR}"

# Install pkg (devDependency) the first time. Subsequent runs reuse node_modules.
if [ ! -d node_modules/@yao-pkg/pkg ]; then
  say "==> installing build dependencies (one-time)"
  npm install
fi

case "${TARGET}" in
  host|"")
    say "==> building for the current host"
    npm run build
    ;;
  linux)
    say "==> building Linux x64 + arm64 (modern, glibc 2.28+)"
    npm run build:linux
    ;;
  linux-portable|portable)
    say "==> building Linux x64 + arm64 (portable, glibc 2.17 / Ubuntu 16.04+)"
    npm run build:linux-portable
    ;;
  mac|macos|darwin)
    say "==> building macOS x64 + arm64"
    npm run build:mac
    ;;
  win|windows)
    say "==> building Windows x64"
    npm run build:win
    ;;
  all)
    say "==> building all targets"
    npm run build:all
    ;;
  clean)
    say "==> removing cli/dist/"
    npm run clean
    exit 0
    ;;
  *)
    err "unknown target: ${TARGET}"
    err "use one of: host | linux | linux-portable | mac | win | all | clean"
    exit 1
    ;;
esac

say
say "==> output:"
ls -la "${CLI_DIR}/dist" 2>/dev/null || say "(no dist/ — build may have failed)"
