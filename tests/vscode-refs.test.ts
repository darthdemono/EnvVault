/**
 * The editor-free logic of the VS Code extension (Phase 38). The extension's
 * providers and task are thin callers of these functions; they type-check but
 * have not been run inside a real VS Code, so what can be pinned here, is.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  FIELD_NAMES,
  completionContext,
  execArgs,
  hoverText,
  parseExposureReport,
  refAt,
} from '../vscode-extension/src/refs';

describe('refAt', () => {
  const line = 'DB=${Postgres/PASSWORD} and ${Stripe} and ${chunk:web/PORT}';
  it('finds the reference under the cursor and splits provider and field', () => {
    const r = refAt(line, 8)!;
    expect(r).toMatchObject({ head: 'Postgres', field: 'PASSWORD', inner: 'Postgres/PASSWORD' });
    expect(line.slice(r.start, r.end)).toBe('${Postgres/PASSWORD}');
    expect(refAt(line, 33)!).toMatchObject({ head: 'Stripe', field: null });
    expect(refAt(line, 50)!.head).toBe('chunk:web');
  });
  it('is null between references and for a broken one', () => {
    expect(refAt(line, 27)).toBeNull();
    expect(refAt('${unclosed and more', 3)).toBeNull();
    expect(refAt('a ${} b', 4)).toMatchObject({ inner: '', head: '' });
  });
});

describe('completionContext', () => {
  it('completes a provider after ${ and a field after the slash', () => {
    expect(completionContext('KEY=${')).toEqual({ kind: 'provider', prefix: '' });
    expect(completionContext('KEY=${Str')).toEqual({ kind: 'provider', prefix: 'Str' });
    expect(completionContext('KEY=${Stripe/')).toEqual({
      kind: 'field',
      provider: 'Stripe',
      prefix: '',
    });
    expect(completionContext('KEY=${Stripe/PA')).toEqual({
      kind: 'field',
      provider: 'Stripe',
      prefix: 'PA',
    });
  });
  it('offers nothing outside an open reference', () => {
    expect(completionContext('KEY=value')).toBeNull();
    expect(completionContext('KEY=${Stripe}')).toBeNull();
    expect(completionContext('KEY=${Stripe} then ${')).toEqual({ kind: 'provider', prefix: '' });
    expect(completionContext('KEY=${a{b')).toBeNull();
    expect(completionContext('KEY=${chunk:web/')).toBeNull();
    expect(completionContext('KEY=${bundle:x/')).toBeNull();
  });
});

describe('FIELD_NAMES', () => {
  it('names only aliases the reference resolver knows', () => {
    // canonical_field's arms, from the Rust source: a name here that the resolver
    // would pass through unchanged would complete to a reference that fails.
    const rust = readFileSync(join(process.cwd(), 'unv-cli', 'src', 'refs.rs'), 'utf8');
    for (const f of FIELD_NAMES) expect(rust, f).toContain(`"${f}"`);
  });
});

describe('execArgs', () => {
  it('builds an argv with the command after --, never a shell string', () => {
    expect(execArgs({ project: 'api', command: ['node', 'server.js', '--port', '80 80'] })).toEqual(
      ['exec', '--project', 'api', '--', 'node', 'server.js', '--port', '80 80'],
    );
    expect(
      execArgs({
        entries: ['GitHub=GH_TOKEN'],
        pools: ['ci'],
        prefix: 'X_',
        clean: true,
        command: ['gh', 'pr', 'list'],
      }),
    ).toEqual([
      'exec',
      '--entry',
      'GitHub=GH_TOKEN',
      '--pool',
      'ci',
      '--prefix',
      'X_',
      '--clean',
      '--',
      'gh',
      'pr',
      'list',
    ]);
  });
  it('keeps a hostile project name as one argument', () => {
    const a = execArgs({ project: '; rm -rf ~', command: ['true'] });
    expect(a[2]).toBe('; rm -rf ~');
    expect(a.indexOf('--')).toBe(3);
  });
  it('refuses a task with no command or nothing to load', () => {
    expect(() => execArgs({ project: 'x', command: [] })).toThrow(/needs a command/);
    expect(() => execArgs({ command: ['true'] })).toThrow(/Name a project/);
  });
});

describe('parseExposureReport', () => {
  it('reads path, line and fingerprint, including a path with a colon', () => {
    const text =
      '/home/me/app/.env:12: sha256:62e00f8ab94a\nC:\\x\\y.env:3: sha256:abc123\nWrote report\n\n/a:b/c.txt:7: empty\n';
    expect(parseExposureReport(text)).toEqual([
      { path: '/home/me/app/.env', line: 12, fingerprint: 'sha256:62e00f8ab94a' },
      { path: 'C:\\x\\y.env', line: 3, fingerprint: 'sha256:abc123' },
      { path: '/a:b/c.txt', line: 7, fingerprint: 'empty' },
    ]);
  });
  it('ignores anything that is not a finding', () => {
    expect(parseExposureReport('No exposed vault values found.\n')).toEqual([]);
  });
});

describe('hoverText', () => {
  const ref = refAt('${Stripe/KEY}', 4)!;
  it('shows the fingerprint and length and says the value is never shown', () => {
    const t = hoverText(ref, { fingerprint: 'sha256:62e00f8ab94a', length: 24 });
    expect(t).toContain('sha256:62e00f8ab94a');
    expect(t).toContain('24 characters');
    expect(t).toContain('never shown');
  });
  it('says what it does not know instead of inventing', () => {
    expect(hoverText(ref, null)).toContain('not found in the vault, or the vault is locked');
  });
});
