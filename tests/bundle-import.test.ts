import { describe, expect, it } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { importPythonConfig } from '../src/ts/bundle-import';

const SRC = 'tests/fixtures/parity/bundle-import-synthetic.py';
const GOLD = 'tests/fixtures/parity/bundle-import.json';
// The maintainer's own bot config (Phase 24.1 acceptance), values blanked to X.
const SETUP = 'tests/fixtures/parity/bundle-discord-setup.py';
const SETUP_GOLD = 'tests/fixtures/parity/bundle-discord-setup.json';

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

describe('bundle import: the real Discord bot config (acceptance)', () => {
  const got = importPythonConfig(readFileSync(SETUP, 'utf8'));
  const byKey = (k: string) => got.vars.find((v) => v.key === k);

  it('matches the golden file (regenerate with PARITY_UPDATE=1)', () => {
    if (process.env.PARITY_UPDATE) writeFileSync(SETUP_GOLD, JSON.stringify(got, null, 2) + '\n');
    expect(got).toEqual(JSON.parse(readFileSync(SETUP_GOLD, 'utf8')));
  });

  it('imports every assignment and reports the one duplicate by name', () => {
    expect(got.vars).toHaveLength(20);
    expect(got.warnings.some((w) => w.includes('api_key is assigned more than once'))).toBe(true);
    // The stats URL sits between the two assignments: it holds the FIRST key.
    expect(byKey('url')).toMatchObject({ kind: 'template' });
    expect(byKey('url')!.value).toContain('id={channel_id}&key={api_key}');
    expect(byKey('api_key_2')).toBeDefined();
  });

  it('keeps the colour a hex int and the f-strings with nothing to fill in plain', () => {
    expect(byKey('colour')).toMatchObject({ kind: 'hex_int', value: '0x800000', public: true });
    expect(byKey('boturl')).toMatchObject({ kind: 'markdown_link', public: true });
    expect(byKey('inv')).toMatchObject({ kind: 'markdown_link', public: true });
    expect(byKey('title')).toMatchObject({ kind: 'string', public: true });
  });

  it('marks as public only what is plainly safe, and nothing a credential could be', () => {
    const pub = got.vars.filter((v) => v.public).map((v) => v.key);
    expect(pub).toEqual(
      expect.arrayContaining([
        'defprefix',
        'boturl',
        'inv',
        'title',
        'description',
        'colour',
        'blink',
      ]),
    );
    for (const secret of [
      'api_key',
      'api_key_2',
      'channel_id',
      'clientid',
      'ownerid',
      'url',
      'failmessage',
    ]) {
      expect(byKey(secret)!.public, secret).toBeUndefined();
    }
  });

  it('a template over a secret is never public, and one over public inputs is', () => {
    const r = importPythonConfig(
      "pre = '>'\nsecret_thing = 'abc'\na = f'x{pre}'\nb = f'https://h.example/p?s={secret_thing}'\n",
    );
    expect(r.vars.find((v) => v.key === 'a')!.public).toBe(true);
    expect(r.vars.find((v) => v.key === 'b')!.public).toBeUndefined();
  });

  it('a URL that carries a credential, in its query, userinfo or a webhook path, is not public', () => {
    const src = [
      "a = 'https://h.example/x?api_key=zzz'",
      "b = 'https://user:pw@h.example/x'",
      "c = 'https://discord.com/api/webhooks/123/abcdefABCDEF'",
      "d = 'https://h.example/v1/AbCdEf0123456789AbCdEf0123456789'",
      "e = 'https://h.example/v1/things?page=2'",
    ].join('\n');
    const r = importPythonConfig(src);
    expect(r.vars.map((v) => !!v.public)).toEqual([false, false, false, false, true]);
  });
});
