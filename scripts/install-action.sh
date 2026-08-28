#!/usr/bin/env bash
set -euo pipefail

repo="Noah4ever/sshconfig-lint"
version="${SSHCONFIG_LINT_VERSION:?SSHCONFIG_LINT_VERSION is required}"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "error: SSHCONFIG_LINT_VERSION must be a release tag" >&2
  exit 2
fi

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) asset="sshconfig-lint-linux-x86_64.tar.gz" ;;
  Linux-aarch64|Linux-arm64) asset="sshconfig-lint-linux-arm64.tar.gz" ;;
  Darwin-x86_64) asset="sshconfig-lint-macos-x86_64.tar.gz" ;;
  Darwin-arm64|Darwin-aarch64) asset="sshconfig-lint-macos-arm64.tar.gz" ;;
  *) echo "error: unsupported platform $(uname -s)/$(uname -m)" >&2; exit 2 ;;
esac

install_dir="${RUNNER_TEMP}/sshconfig-lint-action/${version}"
mkdir -p "$install_dir"
base_url="https://github.com/${repo}/releases/download/${version}"
curl -fsSL "${base_url}/${asset}" -o "${install_dir}/${asset}"
curl -fsSL "${base_url}/SHA256SUMS" -o "${install_dir}/SHA256SUMS"

expected="$(awk -v asset="$asset" '$2 == asset { print $1 }' "${install_dir}/SHA256SUMS")"
if [[ -z "$expected" ]]; then
  echo "error: ${asset} is missing from SHA256SUMS" >&2
  exit 2
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${install_dir}/${asset}" | awk '{ print $1 }')"
else
  actual="$(shasum -a 256 "${install_dir}/${asset}" | awk '{ print $1 }')"
fi
if [[ "$actual" != "$expected" ]]; then
  echo "error: checksum verification failed for ${asset}" >&2
  exit 2
fi

tar -xzf "${install_dir}/${asset}" -C "$install_dir"
chmod +x "${install_dir}/${asset%.tar.gz}"
mv "${install_dir}/${asset%.tar.gz}" "${install_dir}/sshconfig-lint"
echo "$install_dir" >> "$GITHUB_PATH"
