import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { codeStatus, markUsed, nextCode } from '../src/ts/recovery-codes';

const doc = JSON.parse(readFileSync('tests/fixtures/parity/recovery-codes.json', 'utf8'));
const entry = (codes: string) => ({ extra_vars: [{ key: 'codes', value: codes }] });

describe('recovery codes (parity with vault-core/src/type_emit.rs)', () => {
  for (const c of doc.cases as {
    name: string;
    codes: string;
    total: number;
    remaining: number;
    next: string | null;
  }[]) {
    it(c.name, () => {
      expect(codeStatus(entry(c.codes))).toEqual({ total: c.total, remaining: c.remaining });
      expect(nextCode(entry(c.codes))).toBe(c.next);
    });
  }

  it('marks used without losing the code, and refuses the impossible', () => {
    const m = doc.mark_used;
    expect(markUsed(entry(m.codes), null, m.date)).toBe(m.first_unused);
    expect(markUsed(entry(m.codes), m.named.code, m.date)).toBe(m.named.result);
    for (const bad of m.refused as string[])
      expect(() => markUsed(entry(m.codes), bad, m.date)).toThrow();
    expect(() => markUsed(entry(m.first_unused), 'aaaa-1111', m.date)).toThrow('already');
  });

  it('reading consumes nothing', () => {
    const e = entry('a\nb');
    nextCode(e);
    expect(codeStatus(e).remaining).toBe(2);
  });
});
