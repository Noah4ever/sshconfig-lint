#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"
WORKSPACE_DIR="$(dirname -- "$ROOT_DIR")"
AUR_DIR="${AUR_DIR:-$WORKSPACE_DIR/aur/sshconfig-lint}"
TAP_DIR="${TAP_DIR:-$WORKSPACE_DIR/taps/homebrew-tap}"
TAP_FORMULA="${TAP_FORMULA:-Formula/sshconfig-lint.rb}"
GH_REPO="${GH_REPO:-Noah4ever/sshconfig-lint}"
ASSET_PREFIX="${ASSET_PREFIX:-sshconfig-lint}"
CONFIRM="${CONFIRM:-0}"
FORCE_TAG="${FORCE_TAG:-0}"
ALLOW_PRERELEASE_PUBLISH="${ALLOW_PRERELEASE_PUBLISH:-0}"

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

confirm() {
  local message="$1"
  if [[ "$CONFIRM" == "1" ]]; then
    return 0
  fi
  echo
  echo "$message"
  read -r -p "Type 'yes' to continue: " answer
  [[ "$answer" == "yes" ]] || die "aborted"
}

require_clean_tree() {
  [[ -z "$(git status --porcelain)" ]] || die "git working tree is not clean"
}

require_clean_repo() {
  local directory="$1"
  [[ -d "$directory/.git" ]] || die "not a git repo: $directory"
  [[ -z "$(git -C "$directory" status --porcelain)" ]] || die "git working tree is not clean: $directory"
}

hash_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

sha256_of_url() {
  local url="$1"
  local temporary
  temporary="$(mktemp)"
  curl -fsSL "$url" -o "$temporary"
  hash_file "$temporary"
  rm -f "$temporary"
}

sed_in_place() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    sed -i '' "$@"
  else
    sed -i "$@"
  fi
}

wait_for_release() {
  local release_tag="$1"
  local expected_assets="${2:-10}"
  local max_seconds="${3:-1800}"
  local interval="${4:-10}"
  local waited=0

  echo "waiting for $release_tag with at least $expected_assets assets..."
  while (( waited < max_seconds )); do
    local count
    count="$(gh release view "$release_tag" --repo "$GH_REPO" --json assets --jq '.assets | length' 2>/dev/null || echo 0)"
    if (( count >= expected_assets )); then
      echo "ok: $count assets found"
      return 0
    fi
    printf '\r  %ds elapsed, %d/%d assets...' "$waited" "$count" "$expected_assets"
    sleep "$interval"
    waited=$((waited + interval))
  done
  echo
  return 1
}

bump_versions() {
  local new_version="$1"
  local extension_version="${new_version%%-*}"

  perl -0777 -i -pe "s/(\\[package\\].*?\\nversion\\s*=\\s*)\"[^\"]+\"/\\1\"$new_version\"/s" Cargo.toml
  cargo check --quiet

  pushd editors/vscode >/dev/null
  npm version "$extension_version" --no-git-tag-version --allow-same-version >/dev/null
  CLI_VERSION="$new_version" perl -0777 -i -pe 's/("cliVersion"\s*:\s*")[^"]+/$1$ENV{CLI_VERSION}/' package.json
  popd >/dev/null

  grep -q "^version = \"$new_version\"$" Cargo.toml || die "failed to update Cargo.toml"
  grep -q "\"cliVersion\": \"$new_version\"" editors/vscode/package.json || die "failed to update VS Code CLI version"
}

usage() {
  cat <<'EOF'
Usage: scripts/release.sh <version> [--only <stage>,...]

Stages:
  preflight   Rust, CLI package and VS Code extension checks
  bump        synchronize versions and create the release commit
  tag         create and push the annotated release tag
  wait        wait for all GitHub release assets
  crates      publish a stable release to crates.io
  aur         update and push the AUR package
  homebrew    update and push the Homebrew tap
  vscode      publish the VS Code extension

Pre-release versions such as 0.5.0-rc.1 run preflight, bump, tag and wait,
but skip package registries unless ALLOW_PRERELEASE_PUBLISH=1 is set.

Environment overrides:
  ROOT_DIR, AUR_DIR, TAP_DIR, TAP_FORMULA, GH_REPO, ASSET_PREFIX
  CONFIRM=1, FORCE_TAG=1, ALLOW_PRERELEASE_PUBLISH=1
EOF
  exit 2
}

version="${1:-}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || usage
tag="v$version"
shift

only=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only)
      [[ $# -ge 2 ]] || usage
      only="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done

should_run() {
  [[ -z "$only" ]] && return 0
  [[ ",$only," == *",$1,"* ]]
}

is_prerelease() {
  [[ "$version" == *-* ]]
}

allow_registry_stage() {
  ! is_prerelease || [[ "$ALLOW_PRERELEASE_PUBLISH" == "1" ]]
}

need git
need cargo
need curl
need gh
need npm
need perl
need sed

cd "$ROOT_DIR"
[[ -d .git ]] || die "ROOT_DIR is not a git repo: $ROOT_DIR"

if should_run preflight; then
  require_clean_tree
  echo "== preflight =="
  cargo fmt --check
  cargo clippy --all-targets --locked -- -D warnings
  cargo test --all --locked
  cargo package --locked --allow-dirty
  npm --prefix editors/vscode ci
  npm --prefix editors/vscode run check
  npm --prefix editors/vscode test
  npm --prefix editors/vscode run package
fi

if should_run bump; then
  require_clean_tree
  echo "== bump version to $version =="
  bump_versions "$version"
  git add Cargo.toml Cargo.lock editors/vscode/package.json editors/vscode/package-lock.json
  if git diff --cached --quiet; then
    echo "versions already match $version"
  else
    git commit -m "chore: release $tag"
  fi
fi

if should_run tag; then
  require_clean_tree
  if git rev-parse "$tag" >/dev/null 2>&1; then
    [[ "$FORCE_TAG" == "1" ]] || die "tag already exists: $tag"
    git tag -d "$tag"
    git push origin ":refs/tags/$tag" || true
  fi

  confirm "Create and push $tag from $(git rev-parse --short HEAD)?"
  git tag -a "$tag" -m "Release $tag"
  git push origin HEAD
  git push origin "$tag"
fi

base_url="https://github.com/$GH_REPO/releases/download/$tag"
linux_x64="$base_url/${ASSET_PREFIX}-linux-x86_64.tar.gz"
linux_arm="$base_url/${ASSET_PREFIX}-linux-arm64.tar.gz"
mac_x64="$base_url/${ASSET_PREFIX}-macos-x86_64.tar.gz"
mac_arm="$base_url/${ASSET_PREFIX}-macos-arm64.tar.gz"

if should_run wait; then
  echo "== wait for GitHub release =="
  wait_for_release "$tag" 10 || die "release assets did not appear"
fi

if should_run crates; then
  if allow_registry_stage; then
    echo "== publish crates.io =="
    cargo publish --locked
  else
    echo "skip crates.io for pre-release $tag"
  fi
fi

if should_run aur; then
  if allow_registry_stage; then
    echo "== update AUR =="
    need updpkgsums
    need makepkg
    require_clean_repo "$AUR_DIR"
    git -C "$AUR_DIR" pull --ff-only

    pushd "$AUR_DIR" >/dev/null
    sed_in_place -E "s/^pkgver=.*/pkgver=$version/" PKGBUILD
    sed_in_place -E 's/^pkgrel=.*/pkgrel=1/' PKGBUILD
    updpkgsums
    makepkg --printsrcinfo > .SRCINFO
    git add PKGBUILD .SRCINFO
    git diff --cached --quiet || git commit -m "Release $tag"
    git push
    popd >/dev/null
  else
    echo "skip AUR for pre-release $tag"
  fi
fi

if should_run homebrew; then
  if allow_registry_stage; then
    echo "== update Homebrew tap =="
    require_clean_repo "$TAP_DIR"
    [[ -f "$TAP_DIR/$TAP_FORMULA" ]] || die "formula not found: $TAP_DIR/$TAP_FORMULA"
    git -C "$TAP_DIR" pull --ff-only

    sha_linux_x64="$(sha256_of_url "$linux_x64")"
    sha_linux_arm="$(sha256_of_url "$linux_arm")"
    sha_mac_x64="$(sha256_of_url "$mac_x64")"
    sha_mac_arm="$(sha256_of_url "$mac_arm")"

    pushd "$TAP_DIR" >/dev/null
    sed_in_place -E "s/^  version \".*\"/  version \"$version\"/" "$TAP_FORMULA"

    update_sha() {
      local platform="$1"
      local checksum="$2"
      sed_in_place "/${ASSET_PREFIX}-${platform}\.tar\.gz/{n;s/sha256 \"[^\"]*\"/sha256 \"${checksum}\"/;}" "$TAP_FORMULA"
    }

    update_sha macos-arm64 "$sha_mac_arm"
    update_sha macos-x86_64 "$sha_mac_x64"
    update_sha linux-arm64 "$sha_linux_arm"
    update_sha linux-x86_64 "$sha_linux_x64"

    git add "$TAP_FORMULA"
    git diff --cached --quiet || git commit -m "sshconfig-lint $tag"
    git push
    popd >/dev/null
  else
    echo "skip Homebrew for pre-release $tag"
  fi
fi

if should_run vscode; then
  if allow_registry_stage; then
    [[ -n "${VSCE_PAT:-}" ]] || die "VSCE_PAT is required to publish the VS Code extension"
    echo "== publish VS Code extension =="
    npm --prefix editors/vscode run package
    vsix="$(find editors/vscode -maxdepth 1 -name "sshconfig-lint-${version%%-*}.vsix" -print -quit)"
    [[ -n "$vsix" ]] || die "VSIX package not found"
    npx --prefix editors/vscode @vscode/vsce publish --packagePath "$vsix"
  else
    echo "skip VS Code Marketplace for pre-release $tag"
  fi
fi

echo
echo "release stages completed for $tag"
