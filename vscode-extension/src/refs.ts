/**
 * The parts of the extension that need no VS Code: finding a `${…}` under the
 * cursor, deciding what to complete, building an `unv exec` argv, and reading an
 * exposure report. Kept free of `vscode` imports so the repository's own test
 * suite (`tests/vscode-refs.test.ts`) can exercise them; the extension's glue
 * (`extension.ts`) is a thin caller.
 *
 * **Nothing here sees a secret value.** The CLI is only ever asked for redacted
 * output (names, fingerprints), and `scan --exposed` writes lines of
 * `path:line: fingerprint` and never the value.
 */

export interface RefAt {
  /** Offsets of the whole `${…}` in the line. */
  start: number;
  end: number;
  /** What is inside the braces. */
  inner: string;
  /** `Provider` (or `chunk:Name`, `bundle:Name`). */
  head: string;
  /** The field after the first `/`, if any. */
  field: string | null;
}

/** The `${…}` that contains `character`, if the cursor is inside one. */
export function refAt(line: string, character: number): RefAt | null {
  const re = /\$\{([^${}\n]*)\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) !== null) {
    const start = m.index;
    const end = start + m[0].length;
    if (character >= start && character <= end) {
      const inner = m[1];
      const slash = inner.indexOf('/');
      return {
        start,
        end,
        inner,
        head: slash < 0 ? inner : inner.slice(0, slash),
        field: slash < 0 ? null : inner.slice(slash + 1),
      };
    }
  }
  return null;
}

export type CompletionContext =
  { kind: 'provider'; prefix: string } | { kind: 'field'; provider: string; prefix: string };

/** What to complete at the end of `linePrefix`, if it ends inside an open `${`. */
export function completionContext(linePrefix: string): CompletionContext | null {
  const open = linePrefix.lastIndexOf('${');
  if (open < 0) return null;
  const after = linePrefix.slice(open + 2);
  if (after.includes('}') || after.includes('{') || after.includes('$')) return null;
  const slash = after.indexOf('/');
  if (slash < 0) return { kind: 'provider', prefix: after };
  const provider = after.slice(0, slash);
  if (provider.startsWith('chunk:') || provider.startsWith('bundle:')) return null;
  return { kind: 'field', provider, prefix: after.slice(slash + 1) };
}

/**
 * The field names a `${Provider/field}` understands, from `canonical_field` in
 * `unv-cli/src/refs.rs` (the Rust half of a twin pair pinned by
 * `tests/fixtures/parity/field-aliases.json`; `tests/vscode-refs.test.ts` fails
 * if this list names something the fixture does not know). Named variables an
 * entry carries are completed from the CLI as well.
 */
export const FIELD_NAMES: readonly string[] = [
  'KEY',
  'TOKEN',
  'PASSWORD',
  'SECRET',
  'USERNAME',
  'URL',
  'EMAIL',
  'KEY_ID',
  'ID',
  'CLIENT_ID',
  'PATH',
  'TEMPLATE',
];

export interface ExecTask {
  command: string[];
  project?: string;
  entries?: string[];
  pools?: string[];
  prefix?: string;
  clean?: boolean;
}

/** `unv exec …` as an argv for a process, never a shell string. */
export function execArgs(task: ExecTask): string[] {
  if (!Array.isArray(task.command) || task.command.length === 0) {
    throw new Error('An unv task needs a command');
  }
  const args = ['exec'];
  if (task.project) args.push('--project', task.project);
  for (const e of task.entries ?? []) args.push('--entry', e);
  for (const p of task.pools ?? []) args.push('--pool', p);
  if (task.prefix) args.push('--prefix', task.prefix);
  if (task.clean) args.push('--clean');
  if (!task.project && !(task.entries ?? []).length && !(task.pools ?? []).length) {
    throw new Error('Name a project, an entry or a pool to load');
  }
  return [...args, '--', ...task.command];
}

export interface Exposure {
  path: string;
  /** 1-based, as the CLI reports it. */
  line: number;
  fingerprint: string;
}

/** Lines of `path:line: fingerprint` from `unv scan --exposed … --out FILE`. */
export function parseExposureReport(text: string): Exposure[] {
  const out: Exposure[] = [];
  for (const l of text.split('\n')) {
    const m = /^(.*):(\d+): (sha256:[0-9a-f]+|empty)\s*$/.exec(l);
    if (m) out.push({ path: m[1], line: Number(m[2]), fingerprint: m[3] });
  }
  return out;
}

/** What a hover may say about a reference: its fingerprint and length, never the value. */
export function hoverText(
  ref: RefAt,
  shown: { fingerprint?: string; length?: number } | null,
): string {
  const what = ref.field ? `${ref.head} / ${ref.field}` : ref.head;
  if (!shown?.fingerprint) {
    return `**${what}**: not found in the vault, or the vault is locked (run \`unv login\`).`;
  }
  return `**${what}**: \`${shown.fingerprint}\`${shown.length ? `, ${shown.length} characters` : ''}\n\nThe value is never shown here; equal fingerprints mean equal secrets.`;
}
