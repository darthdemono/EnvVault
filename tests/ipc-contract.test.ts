/**
 * Every command name the frontend sends must be a command the backend
 * registered.
 *
 * jsdom has no Tauri, so an `invoke('entry_totp_cod')` typo, or a command
 * written and never added to `generate_handler!`, fails at runtime in a real
 * window and nowhere else — the whole users panel shipped broken once for the
 * neighbouring reason (snake_case argument keys, 2026-06-05). This asserts the
 * one half of that contract a test process can see: the names.
 *
 * It reads the sources as text on purpose. Importing `src-tauri` is impossible
 * and mocking `invoke` proves only that the mock was called.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function tsFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return tsFiles(p);
    return name.endsWith('.ts') ? [p] : [];
  });
}

/** Command names passed to `invoke` as a string literal anywhere in `src/ts`. */
function frontendCommands(): Map<string, string[]> {
  const found = new Map<string, string[]>();
  for (const file of tsFiles(join(ROOT, 'src', 'ts'))) {
    const src = readFileSync(file, 'utf8');
    for (const m of src.matchAll(/invoke(?:<[^>]*>)?\(\s*'([a-z0-9_]+)'/g)) {
      const at = found.get(m[1]) ?? [];
      at.push(file.slice(ROOT.length + 1));
      found.set(m[1], at);
    }
  }
  return found;
}

/** The names inside `tauri::generate_handler![…]` — registration, not definition. */
function registeredCommands(): Set<string> {
  const src = readFileSync(join(ROOT, 'src-tauri', 'src', 'lib.rs'), 'utf8');
  const start = src.indexOf('generate_handler!');
  expect(start, 'src-tauri/src/lib.rs has a generate_handler! block').toBeGreaterThan(-1);
  const open = src.indexOf('[', start);
  let depth = 0;
  let end = open;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '[') depth++;
    else if (src[i] === ']' && --depth === 0) {
      end = i;
      break;
    }
  }
  const block = src.slice(open, end);
  return new Set([...block.matchAll(/commands::([a-z0-9_]+)/g)].map((m) => m[1]));
}

describe('IPC contract — frontend invoke names vs registered Tauri commands', () => {
  const fe = frontendCommands();
  const be = registeredCommands();

  it('finds both halves, so a silent zero-match is not mistaken for agreement', () => {
    expect(fe.size).toBeGreaterThan(10);
    expect(be.size).toBeGreaterThan(10);
  });

  for (const [cmd, files] of [...fe].sort()) {
    it(`${cmd} is registered (used in ${files.join(', ')})`, () => {
      expect(be.has(cmd)).toBe(true);
    });
  }

  it('carries both TOTP bridges: the sub-user factor and the stored seed', () => {
    // They are separate features that share only the RFC 6238 arithmetic, and
    // dropping either from `generate_handler!` is invisible until a window opens.
    for (const cmd of ['totp_status', 'totp_enroll', 'totp_confirm', 'totp_disable']) {
      expect(be.has(cmd), `${cmd} (Phase 19: UnENVerse's own second factor)`).toBe(true);
    }
    for (const cmd of ['entry_totp_code', 'totp_import_merge', 'totp_export_build']) {
      expect(be.has(cmd), `${cmd} (Phase 22: a seed held for a third party)`).toBe(true);
    }
  });

  it('write_export_file is registered (A3: every export writes through it)', () => {
    expect(be.has('write_export_file')).toBe(true);
  });
});

describe('A3 — exports write through saveFile, not a bare blob-anchor click', () => {
  // `createObjectURL` is `saveFile`'s own browser-dev-server fallback in
  // `utils.ts` — every other call site used to build a `Blob`, click a
  // `<a download>` anchor and toast success unconditionally, which downloaded
  // nothing in Tauri's WebKitGTK webview (no download handler, no dialog/fs
  // plugin) while still claiming to have worked. A second `createObjectURL`
  // anywhere in `src/ts` is that bug again.
  it('appears nowhere in src/ts except inside saveFile', () => {
    for (const file of tsFiles(join(ROOT, 'src', 'ts'))) {
      const rel = file.slice(ROOT.length + 1);
      const src = readFileSync(file, 'utf8');
      if (!src.includes('createObjectURL')) continue;
      expect(rel, "createObjectURL belongs only in saveFile's browser fallback").toBe(
        'src/ts/utils.ts',
      );
    }
  });
});
