/**
 * A thin, argv-only wrapper around the `unv` CLI. It asks only for redacted
 * output (`--json` without `--reveal`), so a value cannot reach the editor.
 */
import { execFile } from 'node:child_process';

export interface Envelope<T> {
  ok: boolean;
  command?: string;
  data?: T;
  error?: { code: string; message: string };
}

export function runUnv(
  exe: string,
  args: string[],
  cwd?: string,
  timeoutMs = 15000,
): Promise<string> {
  return new Promise((resolve, reject) => {
    // execFile: no shell, so a file name or a provider name is never parsed as one.
    execFile(
      exe,
      args,
      { cwd, timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) reject(new Error((stderr || err.message).trim()));
        else resolve(stdout);
      },
    );
  });
}

export async function unvJson<T>(exe: string, args: string[], cwd?: string): Promise<T> {
  const out = await runUnv(exe, ['--json', ...args], cwd);
  const env = JSON.parse(out) as Envelope<T>;
  if (!env.ok || env.data === undefined) throw new Error(env.error?.message ?? 'unv failed');
  return env.data;
}
