#!/usr/bin/env bash
# install.sh — Download the right mics_cli binary for this machine and
# install it as `mics_cli` on $PATH. Detects OS, arch, and (on Linux) glibc
# version to choose between the modern and the portable build.
#
# Usage:
#   bash install.sh                       # install to a sensible default
#   bash install.sh --prefix DIR          # force install dir
#   bash install.sh --user                # always install to ~/.local/bin
#   bash install.sh --force-portable      # pick the glibc 2.17 Linux build
#   bash install.sh --force-modern        # pick the glibc 2.28+ Linux build
#   bash install.sh --uninstall           # remove the installed binary
#
# One-liner:
#   curl -fsSL https://term.example.com/s/mics_cli/install.sh | bash

set -Eeuo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
BASE_URL="${MICS_CLI_BASE_URL:-https://tnas_d.micsapp.com/s/mics_cli}"
BIN_NAME="${MICS_CLI_BIN_NAME:-mics_cli}"
PREFIX=""
FORCE_USER=0
UNINSTALL=0
FORCE_PORTABLE=0
FORCE_MODERN=0

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  BOLD="\033[1m"; DIM="\033[2m"; RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; RESET="\033[0m"
else
  BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi
info() { printf "${BOLD}==>${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}WARN:${RESET} %s\n" "$*" >&2; }
die()  { printf "${RED}ERROR:${RESET} %s\n" "$*" >&2; exit 1; }
ok()   { printf "${GREEN}OK${RESET} %s\n" "$*"; }

usage() {
  awk 'NR==1{next} /^[^#]/{exit} {sub(/^# ?/,""); print}' "$0"
  exit 0
}

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)          PREFIX="$2"; shift 2 ;;
    --user)            FORCE_USER=1; shift ;;
    --uninstall)       UNINSTALL=1; shift ;;
    --force-portable)  FORCE_PORTABLE=1; shift ;;
    --force-modern)    FORCE_MODERN=1; shift ;;
    -h|--help)         usage ;;
    *)                 die "Unknown argument: $1 (try --help)" ;;
  esac
done

[[ $FORCE_PORTABLE -eq 1 && $FORCE_MODERN -eq 1 ]] && die "--force-portable and --force-modern are mutually exclusive."

# ---------------------------------------------------------------------------
# OS / arch detection
# ---------------------------------------------------------------------------
detect_target() {
  local kernel arch
  kernel=$(uname -s 2>/dev/null || echo unknown)
  arch=$(uname -m 2>/dev/null || echo unknown)

  case "$kernel" in
    Linux)  OS=linux  ;;
    Darwin) OS=macos  ;;
    CYGWIN*|MINGW*|MSYS*) die "Windows isn't supported by this installer. Download mics_cli-win-x64.exe from ${BASE_URL} directly and place it on your PATH." ;;
    *) die "Unsupported OS: $kernel" ;;
  esac

  case "$arch" in
    x86_64|amd64)        ARCH=x64   ;;
    aarch64|arm64)       ARCH=arm64 ;;
    *) die "Unsupported architecture: $arch" ;;
  esac

  if [[ "$OS" == linux ]]; then
    if [[ $FORCE_PORTABLE -eq 1 ]]; then
      VARIANT=portable
    elif [[ $FORCE_MODERN -eq 1 ]]; then
      VARIANT=modern
    else
      VARIANT=$(detect_linux_variant)
    fi
    if [[ "$VARIANT" == portable ]]; then
      ASSET="mics_cli-linux-${ARCH}-portable"
    else
      ASSET="mics_cli-linux-${ARCH}"
    fi
  else
    VARIANT=modern
    ASSET="mics_cli-${OS}-${ARCH}"
  fi
}

# Pick portable when glibc < 2.28 (Node 18's minimum). Falls back to portable
# if we can't parse a version — better safe than a runtime crash.
detect_linux_variant() {
  local raw major minor
  if ! command -v ldd >/dev/null 2>&1; then
    warn "ldd not found — defaulting to portable build."
    echo portable
    return
  fi
  raw=$(ldd --version 2>/dev/null | head -n1 || true)
  # Examples we want to match:
  #   "ldd (GNU libc) 2.31"
  #   "ldd (Ubuntu GLIBC 2.35-0ubuntu3.6) 2.35"
  #   "ldd (Debian GLIBC 2.17-105) 2.17"
  if [[ "$raw" =~ ([0-9]+)\.([0-9]+) ]]; then
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
  else
    warn "Couldn't parse glibc version from: $raw"
    warn "Defaulting to portable build."
    echo portable
    return
  fi
  GLIBC_VER="${major}.${minor}"
  # Compare: portable if < 2.28
  if [[ "$major" -lt 2 ]] || { [[ "$major" -eq 2 ]] && [[ "$minor" -lt 28 ]]; }; then
    echo portable
  else
    echo modern
  fi
}

# ---------------------------------------------------------------------------
# Pick an install prefix on $PATH
# ---------------------------------------------------------------------------
choose_prefix() {
  if [[ -n "$PREFIX" ]]; then return; fi
  if [[ $FORCE_USER -eq 1 ]]; then
    PREFIX="$HOME/.local/bin"
    return
  fi

  local system_candidates=()
  if [[ "$OS" == macos && -d /opt/homebrew/bin ]]; then
    system_candidates+=("/opt/homebrew/bin")
  fi
  system_candidates+=("/usr/local/bin")

  local have_sudo=0
  command -v sudo >/dev/null 2>&1 && have_sudo=1

  for dir in "${system_candidates[@]}"; do
    if [[ -d "$dir" && -w "$dir" ]]; then
      PREFIX="$dir"
      return
    fi
    if [[ $have_sudo -eq 1 ]]; then
      if [[ -d "$dir" ]]; then
        PREFIX="$dir"
        NEED_SUDO=1
        return
      fi
    fi
  done

  PREFIX="$HOME/.local/bin"
}

ensure_prefix_exists() {
  if [[ -d "$PREFIX" ]]; then return; fi
  info "Creating $PREFIX"
  if [[ -w "$(dirname "$PREFIX")" ]]; then
    mkdir -p "$PREFIX"
  elif command -v sudo >/dev/null 2>&1; then
    sudo mkdir -p "$PREFIX"
    NEED_SUDO=1
  else
    die "$PREFIX doesn't exist and we can't create it (no sudo). Try --user to install to ~/.local/bin."
  fi
}

writable_check() {
  if [[ -w "$PREFIX" ]]; then return; fi
  if command -v sudo >/dev/null 2>&1; then
    NEED_SUDO=1
    return
  fi
  die "$PREFIX isn't writable and sudo isn't available. Try --user."
}

runp() {
  if [[ "${NEED_SUDO:-0}" -eq 1 ]]; then
    sudo "$@"
  else
    "$@"
  fi
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
do_uninstall() {
  detect_target
  choose_prefix
  local target="$PREFIX/$BIN_NAME"
  if [[ ! -e "$target" ]]; then
    local hit=""
    for dir in /usr/local/bin /opt/homebrew/bin "$HOME/.local/bin"; do
      if [[ -e "$dir/$BIN_NAME" ]]; then hit="$dir/$BIN_NAME"; break; fi
    done
    [[ -z "$hit" ]] && { info "$BIN_NAME not found in common locations — nothing to do."; exit 0; }
    target="$hit"
    PREFIX="$(dirname "$target")"
  fi
  writable_check
  info "Removing $target"
  runp rm -f "$target"
  ok "Removed."
  exit 0
}

# ---------------------------------------------------------------------------
# Download + install
# ---------------------------------------------------------------------------
download() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fSL --connect-timeout 15 --progress-bar "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget --connect-timeout=15 --show-progress -qO "$out" "$url"
  else
    die "Need curl or wget."
  fi
}

main_install() {
  detect_target

  local detail="${OS}-${ARCH}"
  if [[ "$OS" == linux ]]; then
    detail="${detail} (${VARIANT}"
    [[ -n "${GLIBC_VER:-}" ]] && detail="${detail}, host glibc ${GLIBC_VER}"
    detail="${detail})"
  fi
  info "Detected: ${detail}  →  asset: ${ASSET}"

  choose_prefix
  ensure_prefix_exists
  writable_check

  local url="${BASE_URL}/${ASSET}"
  local target="${PREFIX}/${BIN_NAME}"
  local tmp
  tmp=$(mktemp -t "${BIN_NAME}.XXXXXX")
  trap 'rm -f "$tmp"' EXIT

  info "Downloading ${url}"
  download "$url" "$tmp"

  # Sanity check: at least a few MB and not an HTML error body
  local size
  size=$(stat -c '%s' "$tmp" 2>/dev/null || stat -f '%z' "$tmp" 2>/dev/null || echo 0)
  if [[ "${size:-0}" -lt 1000000 ]]; then
    head -c 200 "$tmp" | grep -qi "<html\|<!doctype" \
      && die "Download returned an HTML page (likely a 404 or auth wall). URL: $url" \
      || die "Downloaded file is suspiciously small (${size} bytes)."
  fi

  info "Installing to ${target}"
  # Note: not using `install -m 0755` because some NAS distros (e.g. TNAS)
  # ship a custom `install` binary that shadows GNU coreutils. cp + chmod is
  # POSIX and never shadowed.
  runp cp -f "$tmp" "$target"
  runp chmod 0755 "$target"

  rm -f "$tmp"; trap - EXIT

  ok "Installed $BIN_NAME → $target"
  if command -v "$BIN_NAME" >/dev/null 2>&1; then
    local resolved
    resolved=$(command -v "$BIN_NAME")
    if [[ "$resolved" != "$target" ]]; then
      warn "Another '$BIN_NAME' is earlier on \$PATH: $resolved"
      warn "Run '$target' explicitly, or re-order \$PATH to prefer $PREFIX."
    fi
    printf '\n%b\n' "${DIM}Quick check:${RESET}"
    "$BIN_NAME" version 2>/dev/null || "$BIN_NAME" --version 2>/dev/null || true
  else
    warn "$PREFIX is not on \$PATH."
    case "$PREFIX" in
      "$HOME/.local/bin")
        warn "Add to your shell rc:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
      *)
        warn "Add to your shell rc:  export PATH=\"$PREFIX:\$PATH\"" ;;
    esac
    warn "Or run it with its full path: $target"
  fi

  cat <<MSG

Next steps:
  $BIN_NAME login --url https://term.example.com
  $BIN_NAME exec 'uname -a'
  $BIN_NAME shell
MSG
}

if [[ $UNINSTALL -eq 1 ]]; then
  do_uninstall
fi
main_install
