#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT

command -v pre-commit >/dev/null 2>&1 || {
  echo "pre-commit is required to run the hook fixtures" >&2
  exit 2
}

run_hook() {
  local hook="$1"
  local expected="$2"
  shift 2

  set +e
  (cd "$fixture_repository" && pre-commit run --config .pre-commit-config.yaml "$hook" --files "$@")
  local actual=$?
  set -e

  if [[ "$expected" == "success" && "$actual" -ne 0 ]]; then
    echo "$hook unexpectedly rejected: $*" >&2
    exit 1
  fi
  if [[ "$expected" == "failure" && "$actual" -eq 0 ]]; then
    echo "$hook unexpectedly accepted: $*" >&2
    exit 1
  fi
}

fixture_repository="$fixture_root/repository"
mkdir -p "$fixture_repository"
git -C "$fixture_repository" init --quiet

revision="$(git -C "$repo_root" rev-parse HEAD)"
printf '%s\n' \
  'repos:' \
  "  - repo: file://$repo_root" \
  "    rev: $revision" \
  '    hooks:' \
  '      - id: sshconfig-lint' \
  '      - id: sshconfig-lint-strict' \
  > "$fixture_repository/.pre-commit-config.yaml"

cp -R "$repo_root/tests/fixtures/pre_commit/clean/." "$fixture_repository/"
run_hook sshconfig-lint success .ssh/config ssh_config dot_ssh/config

cp "$repo_root/tests/fixtures/pre_commit/warning/.ssh/config" "$fixture_repository/.ssh/config"
run_hook sshconfig-lint success .ssh/config
run_hook sshconfig-lint-strict failure .ssh/config

cp "$repo_root/tests/fixtures/pre_commit/error/.ssh/config" "$fixture_repository/.ssh/config"
run_hook sshconfig-lint failure .ssh/config
run_hook sshconfig-lint-strict failure .ssh/config

cp "$repo_root/tests/fixtures/pre_commit/ignored/README.md" "$fixture_repository/README.md"
run_hook sshconfig-lint success README.md

echo "Pre-Commit hook fixtures passed"
