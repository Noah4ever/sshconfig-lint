const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  checksumFor,
  releaseAssetFor,
  resolveBinaryPath,
} = require('../dist/release.js');

function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sshconfig-lint-vscode-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function sha256(contents) {
  return crypto.createHash('sha256').update(contents).digest('hex');
}

test('maps every supported VS Code platform to a release asset', () => {
  assert.deepEqual(releaseAssetFor('linux', 'x64'), {
    name: 'sshconfig-lint-linux-x86_64.tar.gz',
    archive: true,
  });
  assert.deepEqual(releaseAssetFor('linux', 'arm64'), {
    name: 'sshconfig-lint-linux-arm64.tar.gz',
    archive: true,
  });
  assert.deepEqual(releaseAssetFor('darwin', 'x64'), {
    name: 'sshconfig-lint-macos-x86_64.tar.gz',
    archive: true,
  });
  assert.deepEqual(releaseAssetFor('darwin', 'arm64'), {
    name: 'sshconfig-lint-macos-arm64.tar.gz',
    archive: true,
  });
  assert.deepEqual(releaseAssetFor('win32', 'x64'), {
    name: 'sshconfig-lint-windows-x86_64.exe',
    archive: false,
  });
  assert.deepEqual(releaseAssetFor('win32', 'arm64'), {
    name: 'sshconfig-lint-windows-arm64.exe',
    archive: false,
  });
});

test('rejects an unsupported platform', () => {
  assert.throws(() => releaseAssetFor('freebsd', 'x64'), /Unsupported platform/);
});

test('only accepts an exact SHA256SUMS entry', () => {
  const hash = 'a'.repeat(64);
  const asset = 'sshconfig-lint-linux-x86_64.tar.gz';
  assert.equal(checksumFor(`${hash}  ${asset}\n`, asset), hash);
  assert.equal(checksumFor(`${hash}  other-${asset}\n`, asset), undefined);
  assert.equal(checksumFor(`not-a-hash  ${asset}\n`, asset), undefined);
  assert.equal(checksumFor('', asset), undefined);
});

test('downloads and verifies a managed binary before making it executable', async t => {
  const storageDirectory = temporaryDirectory(t);
  const binary = Buffer.from('verified windows executable');
  const downloads = [];

  const resolved = await resolveBinaryPath({
    configuredPath: '',
    storageDirectory,
    version: '0.5.0',
    platform: 'win32',
    architecture: 'x64',
    download: async (url, destination) => {
      downloads.push(url);
      const contents = url.endsWith('/SHA256SUMS')
        ? `${sha256(binary)}  sshconfig-lint-windows-x86_64.exe\n`
        : binary;
      await fs.promises.writeFile(destination, contents);
    },
    extractArchive: async () => assert.fail('Windows assets are not archives'),
  });

  assert.equal(resolved, path.join(storageDirectory, '0.5.0', 'sshconfig-lint.exe'));
  assert.deepEqual(fs.readFileSync(resolved), binary);
  assert.equal(downloads.length, 2);
  assert.match(downloads[0], /\/releases\/download\/v0\.5\.0\//);
});

test('extracts a verified Unix archive into the managed executable path', async t => {
  const storageDirectory = temporaryDirectory(t);
  const archive = Buffer.from('fake but checksum-verified tarball');
  let extraction;

  const resolved = await resolveBinaryPath({
    configuredPath: '',
    storageDirectory,
    version: '0.5.0',
    platform: 'darwin',
    architecture: 'arm64',
    download: async (url, destination) => {
      const contents = url.endsWith('/SHA256SUMS')
        ? `${sha256(archive)}  sshconfig-lint-macos-arm64.tar.gz\n`
        : archive;
      await fs.promises.writeFile(destination, contents);
    },
    extractArchive: async (source, directory, executable, asset) => {
      extraction = { source, directory, executable, asset };
      await fs.promises.writeFile(executable, 'extracted binary');
    },
  });

  assert.equal(fs.readFileSync(resolved, 'utf8'), 'extracted binary');
  assert.equal(extraction.asset.name, 'sshconfig-lint-macos-arm64.tar.gz');
  assert.equal(extraction.directory, path.join(storageDirectory, '0.5.0'));
  assert.equal(extraction.executable, resolved);
  assert.match(extraction.source, /\.tar\.gz\.download$/);
});

test('rejects a checksum mismatch and leaves no runnable binary behind', async t => {
  const storageDirectory = temporaryDirectory(t);

  await assert.rejects(resolveBinaryPath({
    configuredPath: '',
    storageDirectory,
    version: '0.5.0',
    platform: 'win32',
    architecture: 'x64',
    download: async (url, destination) => {
      const contents = url.endsWith('/SHA256SUMS')
        ? `${'0'.repeat(64)}  sshconfig-lint-windows-x86_64.exe\n`
        : 'tampered executable';
      await fs.promises.writeFile(destination, contents);
    },
    extractArchive: async () => assert.fail('Windows assets are not archives'),
  }), /Checksum verification failed/);

  assert.equal(
    fs.existsSync(path.join(storageDirectory, '0.5.0', 'sshconfig-lint.exe')),
    false,
  );
});

test('uses an absolute custom binary without downloading a managed copy', async t => {
  const storageDirectory = temporaryDirectory(t);
  const configuredPath = path.join(storageDirectory, 'custom-sshconfig-lint');
  fs.writeFileSync(configuredPath, 'custom');
  let downloaded = false;

  const resolved = await resolveBinaryPath({
    configuredPath,
    storageDirectory,
    version: '0.5.0',
    platform: 'linux',
    architecture: 'x64',
    download: async () => { downloaded = true; },
    extractArchive: async () => {},
  });

  assert.equal(resolved, configuredPath);
  assert.equal(downloaded, false);
});

test('rejects relative and missing custom binary paths', async t => {
  const storageDirectory = temporaryDirectory(t);
  const base = {
    storageDirectory,
    version: '0.5.0',
    platform: 'linux',
    architecture: 'x64',
    download: async () => {},
    extractArchive: async () => {},
  };

  await assert.rejects(
    resolveBinaryPath({ ...base, configuredPath: './sshconfig-lint' }),
    /existing absolute path/,
  );
  await assert.rejects(
    resolveBinaryPath({ ...base, configuredPath: path.join(storageDirectory, 'missing') }),
    /existing absolute path/,
  );
  await assert.rejects(
    resolveBinaryPath({ ...base, configuredPath: storageDirectory }),
    /existing executable file/,
  );
});

test('reuses a cached verified binary without network access', async t => {
  const storageDirectory = temporaryDirectory(t);
  const executable = path.join(storageDirectory, '0.5.0', 'sshconfig-lint');
  fs.mkdirSync(path.dirname(executable), { recursive: true });
  fs.writeFileSync(executable, 'cached binary');

  const resolved = await resolveBinaryPath({
    configuredPath: '',
    storageDirectory,
    version: '0.5.0',
    platform: 'linux',
    architecture: 'x64',
    download: async () => { throw new Error('network is offline'); },
    extractArchive: async () => { throw new Error('archive should not be touched'); },
  });

  assert.equal(resolved, executable);
  assert.equal(fs.readFileSync(resolved, 'utf8'), 'cached binary');
});
