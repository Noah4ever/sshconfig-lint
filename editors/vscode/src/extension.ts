import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as https from 'node:https';
import * as path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import * as vscode from 'vscode';
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from 'vscode-languageclient/node';
import { checksumFor, releaseAssetFor } from './release';

const execFileAsync = promisify(execFile);
const repository = 'Noah4ever/sshconfig-lint';
const rules = [
  ['DUP_HOST', 'duplicate-host'],
  ['MISSING_IDENTITY', 'identity-file-exists'],
  ['WILDCARD_ORDER', 'wildcard-host-order'],
  ['WEAK_ALGO', 'deprecated-weak-algorithms'],
  ['DUP_DIRECTIVE', 'duplicate-directives'],
  ['INSECURE_OPT', 'insecure-option'],
  ['UNSAFE_CTRL_PATH', 'unsafe-control-path'],
  ['INCLUDE_CYCLE', 'include-cycle'],
  ['INCLUDE_READ', 'include-read'],
  ['INCLUDE_GLOB', 'include-glob'],
  ['INCLUDE_NO_MATCH', 'include-no-match'],
] as const;

let client: LanguageClient | undefined;
let output: vscode.OutputChannel;

function download(url: string, destination: string, redirects = 0): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { headers: { 'User-Agent': 'sshconfig-lint-vscode' } }, response => {
      if (response.statusCode && response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        if (redirects >= 5) {
          reject(new Error('Too many redirects while downloading sshconfig-lint'));
          return;
        }
        const next = new URL(response.headers.location, url).toString();
        download(next, destination, redirects + 1).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`Download failed with HTTP ${response.statusCode}`));
        return;
      }
      const file = fs.createWriteStream(destination, { mode: 0o600 });
      response.pipe(file);
      file.on('finish', () => file.close(() => resolve()));
      file.on('error', reject);
    });
    request.on('error', reject);
  });
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

async function managedBinary(context: vscode.ExtensionContext): Promise<string> {
  const version = context.extension.packageJSON.sshconfigLint.cliVersion as string;
  const directory = path.join(context.globalStorageUri.fsPath, version);
  const executable = path.join(directory, process.platform === 'win32' ? 'sshconfig-lint.exe' : 'sshconfig-lint');
  if (fs.existsSync(executable)) return executable;

  const asset = releaseAssetFor(process.platform, process.arch);
  await fs.promises.mkdir(directory, { recursive: true });
  const assetPath = path.join(directory, asset.name);
  const checksumsPath = path.join(directory, 'SHA256SUMS');
  const base = `https://github.com/${repository}/releases/download/v${version}`;

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'Installing sshconfig-lint', cancellable: false },
    async () => {
      await Promise.all([
        download(`${base}/${asset.name}`, assetPath),
        download(`${base}/SHA256SUMS`, checksumsPath),
      ]);
      const expected = checksumFor(
        await fs.promises.readFile(checksumsPath, 'utf8'),
        asset.name,
      );
      if (!expected || await sha256(assetPath) !== expected) {
        throw new Error(`Checksum verification failed for ${asset.name}`);
      }

      if (asset.archive) {
        await execFileAsync('tar', ['-xzf', assetPath, '-C', directory]);
        const unpacked = path.join(directory, asset.name.replace(/\.tar\.gz$/, ''));
        await fs.promises.rename(unpacked, executable);
        await fs.promises.chmod(executable, 0o755);
      } else {
        await fs.promises.rename(assetPath, executable);
      }
    },
  );

  return executable;
}

async function resolveBinary(context: vscode.ExtensionContext): Promise<string> {
  const configured = vscode.workspace.getConfiguration('sshconfigLint').get<string>('binaryPath', '').trim();
  if (configured) {
    if (!path.isAbsolute(configured) || !fs.existsSync(configured)) {
      throw new Error('sshconfigLint.binaryPath must point to an existing absolute path.');
    }
    return configured;
  }
  return managedBinary(context);
}

function selectors(): LanguageClientOptions['documentSelector'] {
  const additional = vscode.workspace
    .getConfiguration('sshconfigLint')
    .get<string[]>('additionalFilePatterns', []);
  return [
    { language: 'sshconfig', scheme: 'file' },
    { language: 'sshconfig', scheme: 'untitled' },
    ...additional.map(pattern => ({ scheme: 'file', pattern })),
  ];
}

async function start(context: vscode.ExtensionContext): Promise<void> {
  if (client) return;
  try {
    const binary = await resolveBinary(context);
    const serverOptions: ServerOptions = { command: binary, args: ['lsp'] };
    const clientOptions: LanguageClientOptions = {
      documentSelector: selectors(),
      outputChannel: output,
    };
    client = new LanguageClient('sshconfigLint', 'sshconfig-lint', serverOptions, clientOptions);
    await client.start();
  } catch (error) {
    output.appendLine(String(error));
    void vscode.window.showErrorMessage(
      `sshconfig-lint could not start: ${error instanceof Error ? error.message : String(error)}`,
      'Open settings',
    ).then(choice => {
      if (choice === 'Open settings') void vscode.commands.executeCommand('workbench.action.openSettings', 'sshconfigLint.binaryPath');
    });
  }
}

async function stop(): Promise<void> {
  const current = client;
  client = undefined;
  if (current) await current.stop();
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  output = vscode.window.createOutputChannel('sshconfig-lint');
  context.subscriptions.push(output);

  context.subscriptions.push(vscode.commands.registerCommand('sshconfigLint.restartServer', async () => {
    await stop();
    await start(context);
  }));

  context.subscriptions.push(vscode.commands.registerCommand('sshconfigLint.showVersion', async () => {
    try {
      const binary = await resolveBinary(context);
      const { stdout } = await execFileAsync(binary, ['--version']);
      void vscode.window.showInformationMessage(stdout.trim());
    } catch (error) {
      void vscode.window.showErrorMessage(String(error));
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('sshconfigLint.openRuleGuide', async () => {
    const selected = await vscode.window.showQuickPick(
      rules.map(([code, slug]) => ({ label: code, description: slug })),
      { placeHolder: 'Choose an sshconfig-lint rule' },
    );
    if (selected) {
      void vscode.env.openExternal(vscode.Uri.parse(`https://sshconfig-lint.apps.thiering.org/en/rules/${selected.description}`));
    }
  }));

  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration(async event => {
    if (event.affectsConfiguration('sshconfigLint')) {
      await stop();
      await start(context);
    }
  }));

  await start(context);
}

export async function deactivate(): Promise<void> {
  await stop();
}
