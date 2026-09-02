import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

export type ReleaseAsset = { name: string; archive: boolean };

export type ResolveBinaryOptions = {
  configuredPath: string;
  storageDirectory: string;
  version: string;
  platform: NodeJS.Platform;
  architecture: string;
  download: (url: string, destination: string) => Promise<void>;
  extractArchive: (
    archive: string,
    destinationDirectory: string,
    executable: string,
    asset: ReleaseAsset,
  ) => Promise<void>;
  runInstall?: (operation: () => Promise<void>) => PromiseLike<void>;
  repository?: string;
};

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

async function sha256(file: string): Promise<string> {
  const hash = crypto.createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    const stream = fs.createReadStream(file);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', resolve);
    stream.on('error', reject);
  });
  return hash.digest('hex');
}

export async function resolveBinaryPath(options: ResolveBinaryOptions): Promise<string> {
  const configured = options.configuredPath.trim();
  if (configured) {
    if (!path.isAbsolute(configured) || !fs.existsSync(configured)) {
      throw new Error('sshconfigLint.binaryPath must point to an existing absolute path.');
    }
    if (!fs.statSync(configured).isFile()) {
      throw new Error('sshconfigLint.binaryPath must point to an existing executable file.');
    }
    return configured;
  }

  const directory = path.join(options.storageDirectory, options.version);
  const executable = path.join(
    directory,
    options.platform === 'win32' ? 'sshconfig-lint.exe' : 'sshconfig-lint',
  );
  if (fs.existsSync(executable)) return executable;

  const asset = releaseAssetFor(options.platform, options.architecture);
  const assetPath = path.join(directory, `${asset.name}.download`);
  const checksumsPath = path.join(directory, 'SHA256SUMS.download');
  const repository = options.repository ?? 'Noah4ever/sshconfig-lint';
  const base = `https://github.com/${repository}/releases/download/v${options.version}`;
  const runInstall = options.runInstall ?? (operation => operation());

  await fs.promises.mkdir(directory, { recursive: true });
  try {
    await runInstall(async () => {
      await Promise.all([
        options.download(`${base}/${asset.name}`, assetPath),
        options.download(`${base}/SHA256SUMS`, checksumsPath),
      ]);
      const expected = checksumFor(
        await fs.promises.readFile(checksumsPath, 'utf8'),
        asset.name,
      );
      if (!expected || await sha256(assetPath) !== expected) {
        throw new Error(`Checksum verification failed for ${asset.name}`);
      }

      if (asset.archive) {
        await options.extractArchive(assetPath, directory, executable, asset);
      } else {
        await fs.promises.rename(assetPath, executable);
      }
    });
  } finally {
    await Promise.all([
      fs.promises.rm(assetPath, { force: true }),
      fs.promises.rm(checksumsPath, { force: true }),
    ]);
  }

  return executable;
}
