import { describe, expect, it } from 'vitest';
import { buildBundleExport } from '../src/ts/copy-profile';
import { makeEntry } from './helpers';
import { readFileSync } from 'node:fs';
import { importPythonConfig } from '../src/ts/bundle-import';

describe('bundle exports', () => {
  it('emits collision-safe names in supported config dialects', () => {
    const bundle = makeEntry({
      id: 'bundle',
      provider: 'Discord',
      secretType: 'bundle',
      extra_vars: [
        { key: 'token', value: 'local' },
        { key: 'webhook_url', value: 'https://discord.com/api/{bot.api_key}', kind: 'template' },
      ],
    });
    const member = makeEntry({
      id: 'member',
      provider: 'Discord',
      bundle_slot: 'bot',
      api_key: 'bot-token',
      primary_role: 'token',
      extra_vars: [
        { key: 'application_id', value: '9007199254740993', kind: 'large_id' },
        { key: 'colour', value: '8388608', kind: 'hex_int' },
      ],
    });
    const python = buildBundleExport(bundle, [member], 'python');
    expect(python).toContain('DISCORD_TOKEN = "local"');
    expect(python).toContain('DISCORD_TOKEN_2 = "bot-token"');
    expect(python).toContain('DISCORD_WEBHOOK_URL = "https://discord.com/api/bot-token"');
    expect(python).toContain('DISCORD_APPLICATION_ID = "9007199254740993"');
    expect(python).toContain('DISCORD_COLOUR = 0x800000');
    expect(buildBundleExport(bundle, [member], 'json')).toContain('"9007199254740993"');
    expect(buildBundleExport(bundle, [member], 'dotenv')).toContain('DISCORD_TOKEN_2=bot-token');
    for (const format of ['javascript', 'typescript', 'toml', 'yaml', 'shell'] as const)
      expect(buildBundleExport(bundle, [member], format)).toContain('DISCORD_APPLICATION_ID');
  });

  it('exports a bundle composite as its rendered value and refuses unresolved parts', () => {
    const bundle = makeEntry({ id: 'bundle', provider: 'Bot', secretType: 'bundle' });
    const composite = makeEntry({
      id: 'link',
      provider: 'Webhook',
      secretType: 'composite',
      composite_template: 'https://discord.com/api/{token}',
      extra_vars: [{ key: 'token', value: 'secret-part' }],
    });
    expect(buildBundleExport(bundle, [composite], 'dotenv')).toContain(
      'WEBHOOK=https://discord.com/api/secret-part',
    );
    expect(() => buildBundleExport(bundle, [{ ...composite, extra_vars: [] }], 'dotenv')).toThrow(
      'unresolved composite',
    );
  });

  it('round-trips a Python config: import -> bundle -> Python export keeps its meaning', () => {
    const src = readFileSync('tests/fixtures/parity/bundle-import-synthetic.py', 'utf8');
    const imported = importPythonConfig(src);
    const bundle = makeEntry({
      id: 'bundle',
      provider: 'Cfg',
      secretType: 'bundle',
      extra_vars: imported.vars.map((v) => ({ key: v.key, value: v.value, kind: v.kind })),
    });
    const exported = buildBundleExport(bundle, [], 'python');

    // Templates stay symbolic and come after what they depend on.
    expect(exported).toContain(
      'CFG_STATS_URL = f"https://example.invalid/stats?key={CFG_API_KEY}&id={CFG_APPLICATION_ID}"',
    );
    expect(exported.indexOf('CFG_API_KEY =')).toBeLessThan(exported.indexOf('CFG_STATS_URL ='));
    expect(exported.indexOf('CFG_API_KEY_2 =')).toBeLessThan(
      exported.indexOf('CFG_CHANNEL_STATS ='),
    );
    // Typed literals come back as the Python they were.
    expect(exported).toContain('CFG_COLOUR = 0x800000');
    expect(exported).toContain('CFG_VOLUME = 0.5');
    expect(exported).toContain('CFG_DEBUG = True');
    expect(exported).toContain('CFG_OWNER_ID = 123456789012345678');
    expect(exported).toContain('CFG_APPLICATION_ID = "708766134927442001"');

    // Meaning: resolve both files' templates and compare every shared name.
    const resolve = (
      vars: { key: string; value: string; kind: string }[],
      rename = (k: string) => k,
    ) => {
      const byKey = new Map(vars.map((v) => [v.key, v]));
      const out = new Map<string, string>();
      const value = (key: string): string => {
        const v = byKey.get(key)!;
        return v.kind === 'template'
          ? v.value.replace(/\{([A-Za-z_]\w*)\}/g, (_m, ref: string) => value(ref))
          : v.value;
      };
      for (const v of vars) out.set(rename(v.key), value(v.key));
      return out;
    };
    const before = resolve(imported.vars);
    const back = importPythonConfig(exported);
    expect(back.warnings).toEqual([]);
    const after = resolve(back.vars);
    for (const [key, val] of before) {
      if (['nothing', 'weird', 'other', 'description'].includes(key)) continue;
      expect(after.get(`CFG_${key.toUpperCase()}`), key).toBe(val);
    }
  });
});
