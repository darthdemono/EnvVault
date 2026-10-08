import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import type { CompositeKind } from '../src/ts/composite';
import {
  renderBundleComposite,
  resolveBundleTemplate,
  referencesToBundleMember,
  renameBundleRefs,
  renameBundleSlotRefs,
  buildBundle,
  bundleSuggestions,
  type ScopedValue,
} from '../src/ts/bundle-scope';
import { makeEntry } from './helpers';
import type { VaultEntry } from '../src/ts/types';

const parity = JSON.parse(readFileSync('tests/fixtures/parity/bundle-scope.json', 'utf8')) as {
  cases: {
    name: string;
    bundle: VaultEntry;
    members: VaultEntry[];
    template: string;
    expected: ScopedValue;
  }[];
  composites: {
    name: string;
    bundle: VaultEntry;
    members: VaultEntry[];
    template: string;
    own_parts: NonNullable<VaultEntry['extra_vars']>;
    kind: CompositeKind;
    expected: { value: string; secret: boolean };
  }[];
};

describe('bundle scope', () => {
  it('cascades bundle renames through stored templates without rewriting similar names', () => {
    const template = makeEntry({
      id: 'template',
      provider: 'Config',
      extra_vars: [
        { key: 'url', value: '${bundle:Old/slot/id}', kind: 'template' },
        { key: 'other', value: '${bundle:Older/slot/id}', kind: 'template' },
      ],
    });
    const projects = [
      {
        id: 'project',
        name: 'Deploy',
        chunks: [
          {
            id: 'chunk',
            name: 'Config',
            chunk_type: 'env_file' as const,
            fields: [{ key: 'URL', value: '${bundle:Old/slot}', field_type: 'var' as const }],
          },
        ],
      },
    ];

    expect(renameBundleRefs([template], projects, 'Old', 'New')).toBe(2);
    expect(template.extra_vars?.[0].value).toBe('${bundle:New/slot/id}');
    expect(template.extra_vars?.[1].value).toBe('${bundle:Older/slot/id}');
    expect(projects[0].chunks?.[0].fields[0].value).toBe('${bundle:New/slot}');
  });

  it('cascades a slot rename through scoped templates and bundle selectors', () => {
    const bundle = makeEntry({
      id: 'bundle',
      provider: 'Discord Bot',
      secretType: 'bundle',
      extra_vars: [{ key: 'invite', value: 'https://x/{discord.api_key}', kind: 'template' }],
    });
    const member = makeEntry({
      id: 'member',
      provider: 'Discord',
      bundle_id: 'bundle',
      bundle_slot: 'discord',
      composite_template: 'https://x/{discord.api_key}',
    });
    const outside = makeEntry({
      id: 'outside',
      provider: 'Outside',
      extra_vars: [{ key: 'id', value: '${bundle:Discord Bot/discord/id}', kind: 'template' }],
    });
    const projects = [
      {
        id: 'project',
        name: 'Deploy',
        chunks: [
          {
            id: 'chunk',
            name: 'Config',
            chunk_type: 'env_file' as const,
            fields: [
              { key: 'ID', value: '${bundle:Discord Bot/discord/id}', field_type: 'var' as const },
            ],
          },
        ],
      },
    ];

    expect(
      renameBundleSlotRefs([bundle, member, outside], projects, bundle, 'discord', 'bot'),
    ).toBe(4);
    expect(bundle.extra_vars?.[0].value).toBe('https://x/{bot.api_key}');
    expect(member.composite_template).toBe('https://x/{bot.api_key}');
    expect(outside.extra_vars?.[0].value).toBe('${bundle:Discord Bot/bot/id}');
    expect(projects[0].chunks?.[0].fields[0].value).toBe('${bundle:Discord Bot/bot/id}');
  });

  it('lists member slot references in templates and project fields', () => {
    const bundle = makeEntry({ id: 'bundle', provider: 'Discord Bot', secretType: 'bundle' });
    const member = makeEntry({ id: 'discord', bundle_id: 'bundle', bundle_slot: 'discord' });
    const consumer = makeEntry({
      id: 'invite',
      provider: 'Invite',
      composite_template: 'https://x.test/?id={discord.api_key}',
      bundle_id: 'bundle',
    });
    const template = makeEntry({
      id: 'other',
      provider: 'Other',
      extra_vars: [
        { key: 'url', value: 'https://x.test/${bundle:Discord Bot/discord/id}', kind: 'template' },
      ],
    });
    const projects = [
      {
        id: 'project',
        name: 'Deploy',
        chunks: [
          {
            id: 'chunk',
            name: 'Config',
            chunk_type: 'env_file' as const,
            fields: [
              { key: 'URL', value: '${bundle:Discord Bot/discord}', field_type: 'var' as const },
            ],
          },
        ],
      },
    ];

    expect(
      referencesToBundleMember(bundle, member, [bundle, member, consumer, template], projects),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: 'Invite composite' }),
        expect.objectContaining({ label: 'Other / url' }),
        expect.objectContaining({ label: 'Deploy / Config / URL' }),
      ]),
    );
  });

  it.each(parity.cases)('matches parity case: $name', (fixture) => {
    const result = resolveBundleTemplate(fixture.bundle, fixture.members, fixture.template);
    expect(result).toMatchObject({ ok: true, value: fixture.expected });
  });

  it.each(parity.composites)('matches composite parity case: $name', (fixture) => {
    const result = renderBundleComposite(
      fixture.bundle,
      fixture.members,
      fixture.template,
      fixture.own_parts,
      fixture.kind,
    );
    expect(result).toMatchObject({ ok: true, ...fixture.expected });
  });

  it('resolves public locals and sibling fields without coercing strings', () => {
    const bundle = makeEntry({
      secretType: 'bundle',
      extra_vars: [{ key: 'prefix', value: '>', public: true }],
    });
    const discord = makeEntry({
      bundle_slot: 'discord',
      primary_public: true,
      api_key: '012345678901234567',
      extra_vars: [{ key: 'permissions', value: '8', public: true }],
    });

    expect(
      resolveBundleTemplate(bundle, [discord], '{prefix}{discord.api_key}:{discord.permissions}'),
    ).toMatchObject({
      ok: true,
      value: { value: '>012345678901234567:8', secret: false },
    });
  });

  it('taints a derived value if any member input is secret', () => {
    const bundle = makeEntry({ secretType: 'bundle' });
    const member = makeEntry({ bundle_slot: 'service', api_key: 'secret-token' });
    expect(resolveBundleTemplate(bundle, [member], 'Bearer {service.key}')).toMatchObject({
      ok: true,
      value: { value: 'Bearer secret-token', secret: true },
    });
  });

  it('encodes each scoped composite reference in its own URL zone and carries taint', () => {
    const bundle = makeEntry({
      secretType: 'bundle',
      extra_vars: [{ key: 'scope', value: 'bot applications.commands', public: true }],
    });
    const discord = makeEntry({
      bundle_slot: 'discord',
      api_key: 'secret/token',
      extra_vars: [{ key: 'id', value: '123', public: true }],
    });
    expect(
      renderBundleComposite(
        bundle,
        [discord],
        'https://discord.test/?client_id={discord.id}&scope={scope}&token={discord.key}',
        [],
        'link',
      ),
    ).toMatchObject({
      ok: true,
      value:
        'https://discord.test/?client_id=123&scope=bot%20applications.commands&token=secret%2Ftoken',
      secret: true,
    });
  });

  it('prefers composite parts over locals and reports the shadow', () => {
    const bundle = makeEntry({
      secretType: 'bundle',
      extra_vars: [{ key: 'id', value: 'local', public: true }],
    });
    const result = resolveBundleTemplate(bundle, [], '{id}', [
      { key: 'id', value: 'part', public: true },
    ]);
    expect(result).toMatchObject({ ok: true, value: { value: 'part', secret: false } });
    expect(result.warnings).toContain(
      '"id" exists at more than one scope level; the part wins over the local',
    );
  });

  it('refuses unresolved references and local cycles', () => {
    const missing = resolveBundleTemplate(makeEntry({ secretType: 'bundle' }), [], '{absent}');
    expect(missing).toMatchObject({
      ok: false,
      error: { kind: 'unresolved', reference: 'absent' },
    });
    const cyclic = resolveBundleTemplate(
      makeEntry({
        secretType: 'bundle',
        extra_vars: [
          { key: 'a', value: '{b}', kind: 'template' },
          { key: 'b', value: '{a}', kind: 'template' },
        ],
      }),
      [],
      '{a}',
    );
    expect(cyclic).toMatchObject({ ok: false, error: { kind: 'cycle', path: ['a', 'b', 'a'] } });
  });

  it('limits recursive templates and refuses hidden global references', () => {
    const extra_vars = ['a', 'b', 'c', 'd', 'e', 'f'].map((key, i) => ({
      key,
      value: i === 5 ? 'end' : `{${String.fromCharCode(98 + i)}}`,
      kind: 'template' as const,
    }));
    const deep = resolveBundleTemplate(makeEntry({ secretType: 'bundle', extra_vars }), [], '{a}');
    expect(deep).toMatchObject({ ok: false, error: { kind: 'depth' } });
    const global = resolveBundleTemplate(makeEntry({ secretType: 'bundle' }), [], '${Missing/key}');
    expect(global).toMatchObject({
      ok: false,
      error: { kind: 'unresolved', reference: '${Missing/key}' },
    });
    expect(
      resolveBundleTemplate(
        makeEntry({ secretType: 'bundle' }),
        [],
        'https://x/${Global/id}',
        [],
        () => ({
          value: '123',
          secret: false,
        }),
      ),
    ).toMatchObject({ ok: true, value: { value: 'https://x/123', secret: false } });
  });
});

describe('bundle creation and suggestions', () => {
  const e = (id: string, provider: string, extra: Partial<VaultEntry> = {}) =>
    makeEntry({ id, provider, ...extra });

  it('buildBundle gives members valid unique slots, order and a primary', () => {
    const a = e('1', 'Spotify web');
    const b = e('2', 'Spotify web');
    const c = e('3', '###');
    const bundle = buildBundle([a, b, c], 'Spotify');
    expect(bundle.secretType).toBe('bundle');
    expect(bundle.bundle_primary).toBe('1');
    expect([a, b, c].every((m) => m.bundle_id === bundle.id)).toBe(true);
    const slots = [a, b, c].map((m) => m.bundle_slot!);
    expect(new Set(slots).size).toBe(3);
    for (const slot of slots) expect(slot).toMatch(/^[A-Za-z0-9][A-Za-z0-9_-]{0,23}$/);
    expect([a, b, c].map((m) => m.bundle_order)).toEqual([10, 20, 30]);
  });

  it('suggests only undismissed, unbundled, un-pooled groups of two or more', () => {
    const list = [
      e('1', 'Spotify'),
      e('2', 'spotify'),
      e('3', 'Solo'),
      e('4', 'Pooled', { pool: 'p' }),
      e('5', 'Pooled', { pool: 'p' }),
      e('6', 'Done', { bundle_id: 'x' }),
      e('7', 'Done'),
    ];
    expect(bundleSuggestions(list, []).map((g) => g.provider)).toEqual(['Spotify']);
    expect(bundleSuggestions(list, ['SPOTIFY'])).toEqual([]);
  });
});
