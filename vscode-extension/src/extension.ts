import * as vscode from 'vscode';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { unvJson, runUnv } from './unv';
import {
  FIELD_NAMES,
  completionContext,
  execArgs,
  hoverText,
  parseExposureReport,
  refAt,
  type ExecTask,
} from './refs';

let names: string[] = [];
let diagnostics: vscode.DiagnosticCollection;

function exe(): string {
  return vscode.workspace.getConfiguration('unenverse').get<string>('path') || 'unv';
}

/** Entry names only; the CLI redacts everything else. */
async function refreshNames(): Promise<void> {
  try {
    const data = await unvJson<{ entries?: { provider?: string }[] } | { provider?: string }[]>(
      exe(),
      ['list'],
    );
    const list = Array.isArray(data) ? data : (data.entries ?? []);
    names = [...new Set(list.map((e) => e.provider ?? '').filter(Boolean))].sort();
  } catch {
    names = [];
  }
}

async function scanFile(doc: vscode.TextDocument): Promise<void> {
  if (doc.uri.scheme !== 'file') return;
  const dir = await mkdtemp(join(tmpdir(), 'unenverse-scan-'));
  const report = join(dir, 'report.txt');
  try {
    await runUnv(exe(), ['scan', '--exposed', doc.uri.fsPath, '--out', report]);
    const found = parseExposureReport(await readFile(report, 'utf8'));
    diagnostics.set(
      doc.uri,
      found.map((f) => {
        const line = Math.max(0, Math.min(f.line - 1, doc.lineCount - 1));
        const range = doc.lineAt(line).range;
        const d = new vscode.Diagnostic(
          range,
          `This line holds a value that is a secret in your vault (${f.fingerprint}). Use a \${Provider/field} reference instead.`,
          vscode.DiagnosticSeverity.Warning,
        );
        d.source = 'UnENVerse';
        return d;
      }),
    );
  } catch {
    diagnostics.delete(doc.uri); // locked vault or no unv: say nothing rather than guess
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export function activate(ctx: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection('unenverse');
  ctx.subscriptions.push(diagnostics);
  void refreshNames();

  ctx.subscriptions.push(
    vscode.commands.registerCommand('unenverse.refresh', () => refreshNames()),
    vscode.commands.registerCommand('unenverse.scanThisFile', async () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) await scanFile(doc);
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (vscode.workspace.getConfiguration('unenverse').get<boolean>('scanOnSave'))
        void scanFile(doc);
    }),
    vscode.workspace.onDidCloseTextDocument((doc) => diagnostics.delete(doc.uri)),

    vscode.languages.registerCompletionItemProvider(
      { scheme: 'file' },
      {
        async provideCompletionItems(doc, pos) {
          const c = completionContext(doc.lineAt(pos.line).text.slice(0, pos.character));
          if (!c) return undefined;
          if (c.kind === 'provider') {
            return names.map(
              (n) => new vscode.CompletionItem(n, vscode.CompletionItemKind.Variable),
            );
          }
          return FIELD_NAMES.map(
            (f) => new vscode.CompletionItem(f, vscode.CompletionItemKind.Field),
          );
        },
      },
      '{',
      '/',
    ),

    vscode.languages.registerHoverProvider(
      { scheme: 'file' },
      {
        async provideHover(doc, pos) {
          const ref = refAt(doc.lineAt(pos.line).text, pos.character);
          if (!ref || ref.head.includes(':')) return undefined;
          let shown: { fingerprint?: string; length?: number } | null = null;
          try {
            const args = ['get', ref.head, ...(ref.field ? ['--field', ref.field] : [])];
            const d = await unvJson<{ value?: { fingerprint?: string; length?: number } }>(
              exe(),
              args,
            );
            shown = d.value ?? null;
          } catch {
            shown = null;
          }
          return new vscode.Hover(new vscode.MarkdownString(hoverText(ref, shown)));
        },
      },
    ),

    vscode.tasks.registerTaskProvider('unv', {
      provideTasks: () => [],
      resolveTask(task) {
        const def = task.definition as unknown as ExecTask & { type: string };
        let args: string[];
        try {
          args = execArgs(def);
        } catch {
          return undefined;
        }
        // ProcessExecution: argv, no shell, so nothing in the task can be parsed as one.
        return new vscode.Task(
          task.definition,
          task.scope ?? vscode.TaskScope.Workspace,
          task.name,
          'unv',
          new vscode.ProcessExecution(exe(), args),
        );
      },
    }),
  );
}

export function deactivate(): void {}
