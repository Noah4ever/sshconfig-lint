#!/usr/bin/env bash
set -euo pipefail

REPO="Noah4ever/sshconfig-lint"
BINARY="sshconfig-lint"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# ----- helpers -----

die() { echo "error: $*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found"
}

# ----- detect platform -----

detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "macos" ;;
    *)       die "unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "x86_64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)             die "unsupported architecture: $(uname -m)" ;;
  esac
}

# ----- resolve version -----

get_latest_version() {
  need curl
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"tag_name": *"//;s/".*//'
}

# ----- main -----

main() {
  need curl
  need tar

  local version="${VERSION:-}"
  if [ -z "$version" ]; then
    echo "fetching latest release..."
    version="$(get_latest_version)"
  fi

  [ -z "$version" ] && die "could not determine latest version"

  local os arch asset url
  os="$(detect_os)"
  arch="$(detect_arch)"
  asset="${BINARY}-${os}-${arch}.tar.gz"
  url="https://github.com/${REPO}/releases/download/${version}/${asset}"

  echo "downloading ${BINARY} ${version} (${os}/${arch})..."
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  curl -fsSL "$url" -o "${tmp}/${asset}" \
    || die "download failed — check that ${version} has a release for ${os}-${arch}"

  tar -xzf "${tmp}/${asset}" -C "$tmp"

  echo "installing to ${INSTALL_DIR}/${BINARY}..."
  if [ -w "$INSTALL_DIR" ]; then
    mv "${tmp}/${BINARY}-${os}-${arch}" "${INSTALL_DIR}/${BINARY}"
  else
    sudo mv "${tmp}/${BINARY}-${os}-${arch}" "${INSTALL_DIR}/${BINARY}"
  fi
  chmod +x "${INSTALL_DIR}/${BINARY}"

  echo "done: $(${BINARY} --version)"
}

main "$@"
