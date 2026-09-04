#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"
WORKSPACE_DIR="$(dirname -- "$ROOT_DIR")"
AUR_DIR="${AUR_DIR:-$WORKSPACE_DIR/aur/sshconfig-lint}"
AUR_REPO="${AUR_REPO:-https://aur.archlinux.org/sshconfig-lint-bin.git}"
AUR_PUSH_REPO="${AUR_PUSH_REPO:-ssh://aur@aur.archlinux.org/sshconfig-lint-bin.git}"
TAP_DIR="${TAP_DIR:-$WORKSPACE_DIR/taps/homebrew-tap}"
TAP_REPO="${TAP_REPO:-https://github.com/Noah4ever/homebrew-tap.git}"
TAP_FORMULA="${TAP_FORMULA:-Formula/sshconfig-lint.rb}"
GH_REPO="${GH_REPO:-Noah4ever/sshconfig-lint}"
ASSET_PREFIX="${ASSET_PREFIX:-sshconfig-lint}"
RELEASE_DOWNLOAD_DIR="${RELEASE_DOWNLOAD_DIR:-$ROOT_DIR/release-artifacts}"
CONFIRM="${CONFIRM:-0}"
FORCE_TAG="${FORCE_TAG:-0}"
ALLOW_PRERELEASE_PUBLISH="${ALLOW_PRERELEASE_PUBLISH:-0}"
DRY_RUN="${DRY_RUN:-0}"
TEMP_REPO_DIRS=()

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

cleanup() {
  local directory
  for directory in "${TEMP_REPO_DIRS[@]-}"; do
    case "$directory" in
      */sshconfig-lint-release.*) rm -rf -- "$directory" ;;
    esac
  done
}

trap cleanup EXIT

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

ensure_aur_repo() {
  if [[ -d "$AUR_DIR/.git" ]]; then
    return
  fi

  local temporary
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/sshconfig-lint-release.XXXXXX")"
  TEMP_REPO_DIRS+=("$temporary")
  AUR_DIR="$temporary/sshconfig-lint-bin"
  echo "cloning AUR package into a temporary directory..."
  git clone "$AUR_REPO" "$AUR_DIR"
  git -C "$AUR_DIR" remote set-url --push origin "$AUR_PUSH_REPO"
}

ensure_tap_repo() {
  if [[ -d "$TAP_DIR/.git" ]]; then
    return
  fi

  local temporary
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/sshconfig-lint-release.XXXXXX")"
  TEMP_REPO_DIRS+=("$temporary")
  TAP_DIR="$temporary/homebrew-tap"
  echo "cloning Homebrew tap into a temporary directory..."
  git clone "$TAP_REPO" "$TAP_DIR"
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
  local release_tag="v$new_version"

  perl -0777 -i -pe "s/(\\[package\\].*?\\nversion\\s*=\\s*)\"[^\"]+\"/\\1\"$new_version\"/s" Cargo.toml
  cargo check --quiet

  RELEASE_TAG="$release_tag" perl -pi -e '
    s#(uses: Noah4ever/sshconfig-lint@)v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?#$1$ENV{RELEASE_TAG}#g;
    s#(rev: )v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?#$1$ENV{RELEASE_TAG}#g;
  ' README.md
  RELEASE_TAG="$release_tag" perl -pi -e \
    's#\x27v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\x27#\x27$ENV{RELEASE_TAG}\x27#g' \
    action.yml

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
  vscode      publish the VS Code extension or prepare a manual VSIX upload

Pre-release versions such as 0.5.0-rc.1 run preflight, bump, tag and wait,
but skip package registries unless ALLOW_PRERELEASE_PUBLISH=1 is set.

Environment overrides:
  ROOT_DIR, AUR_DIR, AUR_REPO, AUR_PUSH_REPO, TAP_DIR, TAP_REPO, TAP_FORMULA
  GH_REPO, ASSET_PREFIX, RELEASE_DOWNLOAD_DIR, VSCE_PAT
  CONFIRM=1, FORCE_TAG=1, ALLOW_PRERELEASE_PUBLISH=1, DRY_RUN=1
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
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "dry-run: skip version bump and release commit"
  else
    require_clean_tree
    echo "== bump version to $version =="
    bump_versions "$version"
    git add Cargo.toml Cargo.lock README.md action.yml editors/vscode/package.json editors/vscode/package-lock.json
    if git diff --cached --quiet; then
      echo "versions already match $version"
    else
      git commit -m "chore: release $tag"
    fi
  fi
fi

if should_run tag; then
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "dry-run: skip release tag and pushes"
  else
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
    if [[ "$DRY_RUN" == "1" ]]; then
      cargo publish --locked --dry-run --allow-dirty
    else
      cargo publish --locked
    fi
  else
    echo "skip crates.io for pre-release $tag"
  fi
fi

if should_run aur; then
  if allow_registry_stage; then
    echo "== update AUR =="
    ensure_aur_repo
    require_clean_repo "$AUR_DIR"
    git -C "$AUR_DIR" pull --ff-only

    pushd "$AUR_DIR" >/dev/null
    if command -v updpkgsums >/dev/null 2>&1 && command -v makepkg >/dev/null 2>&1; then
      sed_in_place -E "s/^pkgver=.*/pkgver=$version/" PKGBUILD
      sed_in_place -E 's/^pkgrel=.*/pkgrel=1/' PKGBUILD
      updpkgsums
      makepkg --printsrcinfo > .SRCINFO
    else
      license_sha="$(sha256_of_url "https://raw.githubusercontent.com/$GH_REPO/$tag/LICENSE")"
      linux_x64_sha="$(sha256_of_url "$linux_x64")"
      linux_arm_sha="$(sha256_of_url "$linux_arm")"

      AUR_VERSION="$version" \
      LICENSE_SHA="$license_sha" \
      LINUX_X64_SHA="$linux_x64_sha" \
      LINUX_ARM_SHA="$linux_arm_sha" \
      perl -pi -e '
        if (/^pkgver=/) { $_ = "pkgver=$ENV{AUR_VERSION}\n" }
        elsif (/^pkgrel=/) { $_ = "pkgrel=1\n" }
        elsif (/^sha256sums=/) { $_ = "sha256sums=(\x27$ENV{LICENSE_SHA}\x27)\n" }
        elsif (/^sha256sums_x86_64=/) { $_ = "sha256sums_x86_64=(\x27$ENV{LINUX_X64_SHA}\x27)\n" }
        elsif (/^sha256sums_aarch64=/) { $_ = "sha256sums_aarch64=(\x27$ENV{LINUX_ARM_SHA}\x27)\n" }
      ' PKGBUILD

      AUR_VERSION="$version" \
      LICENSE_SHA="$license_sha" \
      LINUX_X64_SHA="$linux_x64_sha" \
      LINUX_ARM_SHA="$linux_arm_sha" \
      perl -pi -e '
        s/v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?/v$ENV{AUR_VERSION}/g;
        if (/^\tpkgver = /) { $_ = "\tpkgver = $ENV{AUR_VERSION}\n" }
        elsif (/^\tsha256sums = /) { $_ = "\tsha256sums = $ENV{LICENSE_SHA}\n" }
        elsif (/^\tsha256sums_x86_64 = /) { $_ = "\tsha256sums_x86_64 = $ENV{LINUX_X64_SHA}\n" }
        elsif (/^\tsha256sums_aarch64 = /) { $_ = "\tsha256sums_aarch64 = $ENV{LINUX_ARM_SHA}\n" }
      ' .SRCINFO

      bash -n PKGBUILD
      grep -q "^pkgver=$version$" PKGBUILD || die "failed to update AUR pkgver"
      grep -q $'^\tpkgver = '"$version"'$' .SRCINFO || die "failed to update AUR .SRCINFO"
    fi
    git add PKGBUILD .SRCINFO
    if [[ "$DRY_RUN" == "1" ]]; then
      git diff --cached --check
      echo "dry-run: skip AUR commit and push"
    else
      git diff --cached --quiet || git commit -m "Release $tag"
      git push
    fi
    popd >/dev/null
  else
    echo "skip AUR for pre-release $tag"
  fi
fi

if should_run homebrew; then
  if allow_registry_stage; then
    echo "== update Homebrew tap =="
    ensure_tap_repo
    require_clean_repo "$TAP_DIR"
    [[ -f "$TAP_DIR/$TAP_FORMULA" ]] || die "formula not found: $TAP_DIR/$TAP_FORMULA"
    git -C "$TAP_DIR" pull --ff-only

    sha_linux_x64="$(sha256_of_url "$linux_x64")"
    sha_linux_arm="$(sha256_of_url "$linux_arm")"
    sha_mac_x64="$(sha256_of_url "$mac_x64")"
    sha_mac_arm="$(sha256_of_url "$mac_arm")"

    pushd "$TAP_DIR" >/dev/null
    sed_in_place -E "s|(releases/download/v)[0-9][0-9A-Za-z.-]*|\\1$version|g" "$TAP_FORMULA"

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
    if [[ "$DRY_RUN" == "1" ]]; then
      git diff --cached --check
      echo "dry-run: skip Homebrew commit and push"
    else
      git diff --cached --quiet || git commit -m "sshconfig-lint $tag"
      git push
    fi
    popd >/dev/null
  else
    echo "skip Homebrew for pre-release $tag"
  fi
fi

if should_run vscode; then
  if allow_registry_stage; then
    echo "== prepare VS Code extension =="
    extension_version="${version%%-*}"
    if [[ -n "${VSCE_PAT:-}" && "$DRY_RUN" != "1" ]]; then
      npm --prefix editors/vscode run package
      vsix="$(find editors/vscode -maxdepth 1 -name "sshconfig-lint-${extension_version}.vsix" -print -quit)"
      [[ -n "$vsix" ]] || die "VSIX package not found"
      npx --prefix editors/vscode @vscode/vsce publish --packagePath "$vsix"
    else
      mkdir -p "$RELEASE_DOWNLOAD_DIR"
      vsix="$RELEASE_DOWNLOAD_DIR/sshconfig-lint-${extension_version}.vsix"
      curl -fsSL "$base_url/sshconfig-lint-${extension_version}.vsix" -o "$vsix"
      echo "VSCE_PAT is not set; the VSIX is ready for manual upload:"
      echo "  $vsix"
      echo "  https://marketplace.visualstudio.com/manage/publishers/NoahThiering"
    fi
  else
    echo "skip VS Code Marketplace for pre-release $tag"
  fi
fi

echo
if [[ "$DRY_RUN" == "1" ]]; then
  echo "release stages rehearsed for $tag; nothing was published"
else
  echo "release stages completed for $tag"
fi
