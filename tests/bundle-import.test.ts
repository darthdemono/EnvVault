import { describe, expect, it } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { importPythonConfig } from '../src/ts/bundle-import';

const SRC = 'tests/fixtures/parity/bundle-import-synthetic.py';
const GOLD = 'tests/fixtures/parity/bundle-import.json';

describe('bundle import: Python config module', () => {
  const got = importPythonConfig(readFileSync(SRC, 'utf8'));

  it('matches the golden file (regenerate with PARITY_UPDATE=1)', () => {
    if (process.env.PARITY_UPDATE) writeFileSync(GOLD, JSON.stringify(got, null, 2) + '\n');
    expect(got).toEqual(JSON.parse(readFileSync(GOLD, 'utf8')));
  });

  const byKey = (k: string) => got.vars.find((v) => v.key === k);

  it('keeps ids above 2^53 as strings, never numbers', () => {
    expect(byKey('application_id')).toMatchObject({
      kind: 'large_id',
      value: '708766134927442001',
    });
    expect(typeof byKey('owner_id')!.value).toBe('string');
    expect(byKey('owner_id')!.value).toBe('123456789012345678');
  });

  it('keeps a colour as the hex int it was written as', () => {
    expect(byKey('colour')).toMatchObject({ kind: 'hex_int', value: '0x800000' });
  });

  it('a duplicate name keeps the first and rewrites later references to the second', () => {
    expect(byKey('api_key')!.value).toBe('EXAMPLE_YT_KEY_ONE');
    expect(byKey('api_key_2')!.value).toBe('EXAMPLE_YT_KEY_TWO');
    // The f-string between the two assignments binds the FIRST value.
    expect(byKey('stats_url')!.value).toContain('key={api_key}&');
    expect(byKey('channel_stats')!.value).toContain('key={api_key_2}');
    expect(got.warnings.some((w) => w.includes('api_key is assigned more than once'))).toBe(true);
    expect(
      got.warnings.some((w) => w.includes('1 later reference to api_key now uses api_key_2')),
    ).toBe(true);
  });

  it('preserves a repeated query parameter, in order', () => {
    expect(byKey('blink')!.value).toContain('?scope=bot&scope=bot&');
  });

  it('never executes code and says so for what it cannot read', () => {
    expect(byKey('other')).toMatchObject({ kind: 'string', value: 'len(token)' });
    expect(byKey('weird')!.kind).toBe('string');
    expect(got.warnings.some((w) => w.includes('other is not a supported literal'))).toBe(true);
    expect(got.warnings.some((w) => w.includes('weird is an f-string'))).toBe(true);
  });
});
