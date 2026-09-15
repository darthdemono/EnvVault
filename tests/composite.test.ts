/**
 * Composite-secret rendering (Phase 24.1) — the TypeScript half of a twin
 * pair with `vault-core/src/composite.rs`, pinned by
 * `tests/fixtures/parity/composite.json` (`vault-core/tests/composite_parity.rs`
 * asserts the Rust side against the identical cases).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderComposite, compositePlaceholders, type CompositeKind } from '../src/ts/composite';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

interface Case {
  _why: string;
  template: string;
  kind: string;
  parts: Record<string, string>;
  out?: { text: string; used: string[]; unused: string[] };
  error?: { kind: string; name?: string; at?: number };
}

function table(): { render: Case[] } {
  const raw = readFileSync(join(ROOT, 'tests/fixtures/parity/composite.json'), 'utf8');
  return JSON.parse(raw) as { render: Case[] };
}

describe('renderComposite — golden table', () => {
  const cases = table().render;
  it('the fixture is non-empty', () => expect(cases.length).toBeGreaterThan(5));

  for (const c of cases) {
    it(c._why, () => {
      const parts = Object.entries(c.parts).map(([key, value]) => ({ key, value }));
      const res = renderComposite(c.template, parts, c.kind as CompositeKind);
      if (c.out) {
        expect(res.ok).toBe(true);
        if (res.ok) {
          expect(res.result.text).toBe(c.out.text);
          expect(res.result.used).toEqual(c.out.used);
          expect(res.result.unused).toEqual(c.out.unused);
        }
      } else {
        expect(res.ok).toBe(false);
        if (!res.ok) {
          expect(res.error.kind).toBe(c.error!.kind);
          if ('name' in res.error && c.error!.name !== undefined)
            expect(res.error.name).toBe(c.error!.name);
          if ('at' in res.error && c.error!.at !== undefined)
            expect(res.error.at).toBe(c.error!.at);
        }
      }
    });
  }
});

describe('compositePlaceholders', () => {
  it('lists names in first-use order, deduplicated', () => {
    expect(compositePlaceholders('https://x/{a}/{b}/{a}')).toEqual(['a', 'b']);
  });

  it('returns an empty list for an unrenderable template rather than throwing', () => {
    expect(() => compositePlaceholders('{unclosed')).not.toThrow();
    expect(compositePlaceholders('{unclosed')).toEqual([]);
  });

  it('sees {{literal}} as no placeholder at all', () => {
    expect(compositePlaceholders('{{not a placeholder}}')).toEqual([]);
  });
});
