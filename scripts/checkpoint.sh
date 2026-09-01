#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"
CONFIRM="${CONFIRM:-0}"

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

usage() {
  echo "Usage: scripts/checkpoint.sh <name>" >&2
  echo "Example: scripts/checkpoint.sh 01-value-foundation" >&2
  exit 2
}

name="${1:-}"
[[ "$name" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || usage
[[ $# -eq 1 ]] || usage
tag="checkpoint/$name"

need cargo
need git
need npm

cd "$ROOT_DIR"
[[ -d .git ]] || die "ROOT_DIR is not a git repo: $ROOT_DIR"
[[ -z "$(git status --porcelain)" ]] || die "git working tree is not clean"
git rev-parse "$tag" >/dev/null 2>&1 && die "tag already exists: $tag"

echo "== checkpoint validation =="
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all --locked

if [[ ! -d editors/vscode/node_modules ]]; then
  npm --prefix editors/vscode ci
fi
npm --prefix editors/vscode run check
npm --prefix editors/vscode test
npm --prefix editors/vscode run package

if [[ "$CONFIRM" != "1" ]]; then
  echo
  echo "Create and push $tag from $(git rev-parse --short HEAD)?"
  read -r -p "Type 'yes' to continue: " answer
  [[ "$answer" == "yes" ]] || die "aborted"
fi

git push origin HEAD
git tag -a "$tag" -m "Checkpoint $name"
git push origin "$tag"

echo "checkpoint published: $tag"
