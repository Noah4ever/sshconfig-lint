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
import { resolveBinaryPath } from './release';
import { ruleGuides } from './rules';

const execFileAsync = promisify(execFile);
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

async function resolveBinary(context: vscode.ExtensionContext): Promise<string> {
  const version = context.extension.packageJSON.sshconfigLint.cliVersion as string;
  const configured = vscode.workspace.getConfiguration('sshconfigLint').get<string>('binaryPath', '').trim();
  return resolveBinaryPath({
    configuredPath: configured,
    storageDirectory: context.globalStorageUri.fsPath,
    version,
    platform: process.platform,
    architecture: process.arch,
    download,
    extractArchive: async (archive, directory, executable, asset) => {
      await execFileAsync('tar', ['-xzf', archive, '-C', directory]);
      const unpacked = path.join(directory, asset.name.replace(/\.tar\.gz$/, ''));
      await fs.promises.rename(unpacked, executable);
      await fs.promises.chmod(executable, 0o755);
    },
    runInstall: operation => vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Installing sshconfig-lint',
        cancellable: false,
      },
      operation,
    ),
  });
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
      ruleGuides.map(([code, slug]) => ({ label: code, description: slug })),
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
