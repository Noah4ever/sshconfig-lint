export type ReleaseAsset = { name: string; archive: boolean };

export function releaseAssetFor(
  platform: NodeJS.Platform,
  architecture: string,
): ReleaseAsset {
  const key = `${platform}-${architecture}`;
  switch (key) {
    case 'darwin-arm64': return { name: 'sshconfig-lint-macos-arm64.tar.gz', archive: true };
    case 'darwin-x64': return { name: 'sshconfig-lint-macos-x86_64.tar.gz', archive: true };
    case 'linux-arm64': return { name: 'sshconfig-lint-linux-arm64.tar.gz', archive: true };
    case 'linux-x64': return { name: 'sshconfig-lint-linux-x86_64.tar.gz', archive: true };
    case 'win32-arm64': return { name: 'sshconfig-lint-windows-arm64.exe', archive: false };
    case 'win32-x64': return { name: 'sshconfig-lint-windows-x86_64.exe', archive: false };
    default: throw new Error(`Unsupported platform: ${platform}/${architecture}`);
  }
}

export function checksumFor(contents: string, assetName: string): string | undefined {
  const escapedName = assetName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const line = contents
    .split(/\r?\n/)
    .find(value => new RegExp(`^[a-fA-F0-9]{64}\\s+\\*?${escapedName}$`).test(value.trim()));
  return line?.trim().split(/\s+/)[0]?.toLowerCase();
}
