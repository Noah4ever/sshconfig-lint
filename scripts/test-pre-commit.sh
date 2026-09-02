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
  local fixture="$1"
  local hook="$2"
  local expected="$3"
  local repository="$fixture_root/$fixture"
  shift 3

  mkdir -p "$repository"
  cp -R "$repo_root/tests/fixtures/pre_commit/$fixture/." "$repository/"
  git -C "$repository" init --quiet
  git -C "$repository" add .

  set +e
  (cd "$repository" && pre-commit try-repo "$repo_root" "$hook" --files "$@")
  local actual=$?
  set -e

  if [[ "$expected" == "success" && "$actual" -ne 0 ]]; then
    echo "$hook unexpectedly rejected the $fixture fixture" >&2
    exit 1
  fi
  if [[ "$expected" == "failure" && "$actual" -eq 0 ]]; then
    echo "$hook unexpectedly accepted the $fixture fixture" >&2
    exit 1
  fi
}

run_hook clean sshconfig-lint success .ssh/config ssh_config dot_ssh/config
run_hook warning sshconfig-lint success .ssh/config
run_hook warning sshconfig-lint-strict failure .ssh/config
run_hook error sshconfig-lint failure .ssh/config
run_hook error sshconfig-lint-strict failure .ssh/config
run_hook ignored sshconfig-lint success README.md

echo "Pre-Commit hook fixtures passed"
