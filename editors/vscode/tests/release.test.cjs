const assert = require('node:assert/strict');
const test = require('node:test');

const { checksumFor, releaseAssetFor } = require('../dist/release.js');

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
