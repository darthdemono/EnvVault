/**
 * @file
 * Copy profiles — how much of an entry a copy or an export actually emits.
 * @description Phase 23, step 3.
 *
 * ## The complaint this answers
 *
 * Copy carried three fields. Version, expiry, rate limit, scopes, environment,
 * account, pool, purpose and every `extra_vars` entry were dropped, whatever the
 * user was copying *for* — so the credential arrived somewhere useful and every
 * fact about how to use it stayed in the vault.
 *
 * Three profiles, and the setting is a **default rather than a wall**: the copy
 * button's caret menu offers the other two plus "Value only" on every card.
 *
 * | Profile    | Emits |
 * | ---------- | ----- |
 * | `basic`    | Primary value, `api_secret`, `api_url`, every `extra_vars` entry. |
 * | `extended` | `basic` + version, expiry, rate limit, scopes, environment, account, pool. |
 * | `full`     | `extended` + description, purpose, tags, categories, projects, timestamps, rotation, compromised. |
 *
 * ## Metadata is comments by default
 *
 * A `.env` is loaded into a process. Injecting six non-functional variables per
 * credential into every container is a cost the user did not ask for by pressing
 * Copy, so `metadataStyle` defaults to `comment` and `var` is the opt-in for
 * people who genuinely want them in the environment.
 *
 * Comment mode writes one `# name: value` line per field rather than joining
 * them into a single line: `full` adds nine of them, a `.env` comment does not
 * wrap, and a 300-character line is not a thing anybody reads.
 *
 * ## This emits real values, and that is deliberate
 *
 * The builder has no masker and no `reveal` flag. Redaction is the *caller's*
 * job and it is decided by the Phase 14 rule that already governs every other
 * artefact: `envv get --profile` refuses to stdout unless `--reveal` and writes
 * the real thing with `--out`, exactly as `envv export` does; the app's Copy
 * button is the UI's `--reveal`. Putting a masker in here would mean a second
 * redaction policy to keep in step with `out.rs`, which is the shape that
 * produced the two-lists-of-secret-fields leak in Phase 22.
 *
 * Twin: `envv-cli/src/profile.rs`, pinned by
 * `tests/fixtures/parity/copy-profiles.json` and asserted from both sides.
 */

import type { VaultEntry } from './types';
import {
  envName,
  primaryEnvName,
  quoteEnvValue,
  namesGeneratedBy,
  disambiguateNames,
  type EnvNameCase,
  type GeneratedName,
} from './state';
import { normalizeRateLimit } from './ratelimit';
import { renderBundleComposite, resolveBundleTemplate } from './bundle-scope';
import { resolveFieldRef } from './chunk-ops';

/** How much of an entry a copy emits. */
export type CopyProfile = 'basic' | 'extended' | 'full';

/** Where the metadata goes. */
export type MetadataStyle = 'comment' | 'var';

export interface CopyOpts {
  profile?: CopyProfile;
  metadataStyle?: MetadataStyle;
  case?: EnvNameCase;
  includePrefix?: boolean;
}

/** One metadata field: the role segment it generates, and its value. */
interface Meta {
  role: string;
  value: string;
}

function join(list: unknown): string {
  return Array.isArray(list) ? list.filter(Boolean).join(',') : '';
}

/**
 * The metadata a profile adds, in a fixed order.
 *
 * Fixed because it is asserted byte for byte from two implementations, and
 * because a copy whose line order depends on object-key iteration produces a
 * diff every time anybody touches the type.
 */
function metaFor(entry: VaultEntry, profile: CopyProfile): Meta[] {
  if (profile === 'basic') return [];

  const rl = normalizeRateLimit(entry);
  const out: Meta[] = [
    { role: 'VERSION', value: entry.version ?? '' },
    { role: 'EXPIRES_AT', value: entry.expires_at ?? '' },
    { role: 'RATE_LIMIT', value: rl.rate_limit ?? rl.rate_limit_note ?? '' },
    { role: 'SCOPES', value: join(entry.scopes) },
    { role: 'ENVIRONMENT', value: entry.environment ?? '' },
    { role: 'ACCOUNT', value: entry.account_name ?? '' },
    { role: 'POOL', value: entry.pool ?? '' },
  ];

  if (profile === 'full') {
    out.push(
      { role: 'DESCRIPTION', value: entry.description ?? '' },
      { role: 'PURPOSE', value: entry.purpose ?? '' },
      { role: 'TAGS', value: join(entry.tags) },
      { role: 'CATEGORIES', value: join(entry.categories) },
      // "Universal" is the catch-all every entry carries, so listing it says
      // nothing about this one.
      { role: 'PROJECTS', value: join((entry.projectIds ?? []).filter((p) => p !== 'Universal')) },
      { role: 'CREATED_AT', value: entry.created_at ?? '' },
      { role: 'LAST_ROTATED_AT', value: entry.last_rotated_at ?? '' },
      {
        role: 'ROTATION_DAYS',
        value: entry.rotation_days != null ? String(entry.rotation_days) : '',
      },
      // Only when true. `COMPROMISED=false` on every entry is noise, and the one
      // entry where it matters would be invisible among them.
      { role: 'COMPROMISED', value: entry.compromised ? 'true' : '' },
    );
  }
  return out.filter((m) => m.value !== '');
}

/**
 * The identity header.
 *
 * Present in every profile including `basic`: it is what the entry *is*, not
 * metadata about it, and `Exporter.dotenv` has written it since Phase 3.
 * Removing it from `basic` would make the cheapest profile the only one whose
 * output does not say which credential it is.
 */
function headerFor(entry: VaultEntry): string {
  const bits = [entry.provider || 'UNKNOWN'];
  if (entry.label) bits.push(`— ${entry.label}`);
  if (entry.account_name) bits.push(`— ${entry.account_name}`);
  if (entry.version) bits.push(`(${entry.version})`);
  return `# ${bits.join(' ')}`;
}

/**
 * Build the `.env` text for one entry at the given profile.
 *
 * Emits real values — see the file header for why that is the caller's problem
 * and not this function's.
 */
export function buildCopyText(entry: VaultEntry, opts: CopyOpts = {}): string {
  const profile = opts.profile ?? 'basic';
  const style = opts.metadataStyle ?? 'comment';
  const nameOpts = { case: opts.case, includePrefix: opts.includePrefix };

  const lines: string[] = [headerFor(entry)];

  const meta = metaFor(entry, profile);
  if (style === 'comment') {
    for (const m of meta) lines.push(`# ${m.role.toLowerCase()}: ${m.value}`);
  }

  // Names are disambiguated **within the entry** before anything is written
  // (E2): one entry with `primary_role: 'id'` and an `extra_vars` entry keyed
  // `ID` emits `SPOTIFY_ID` twice by itself, and every `.env` parser takes the
  // last — so the user loses a variable and is told nothing. A suffix is
  // visibly odd and recoverable; a missing variable is neither.
  //
  // An entry may also legitimately have no primary value — an authenticator
  // seed on its own is one (Phase 22), and an `env_var` entry's payload is
  // entirely named variables. Emitting `SPOTIFY=` for those writes a variable
  // meaning "unset" into a file about to be loaded.
  const generated = namesGeneratedBy(entry, nameOpts);
  const unique = disambiguateNames(generated);
  const values: string[] = [];
  if (entry.api_key) values.push(entry.api_key);
  if (entry.api_secret) values.push(entry.api_secret);
  if (entry.api_url) values.push(entry.api_url);
  for (const xv of entry.extra_vars ?? []) {
    if (xv.key) values.push(xv.value ?? '');
  }
  unique.forEach((name, i) => lines.push(`${name}=${quoteEnvValue(values[i] ?? '')}`));

  const push = (name: string, value: string) => lines.push(`${name}=${quoteEnvValue(value)}`);

  if (style === 'var') {
    for (const m of meta) push(envName(entry, { ...nameOpts, role: m.role }), m.value);
  }

  return lines.join('\n');
}

/** The whole selection, blank-line separated — the shape `Exporter.dotenv` already had. */
export function buildCopyTextAll(entries: VaultEntry[], opts: CopyOpts = {}): string {
  return entries.map((e) => buildCopyText(e, opts)).join('\n\n');
}

export type BundleExportFormat =
  'dotenv' | 'python' | 'javascript' | 'typescript' | 'json' | 'yaml' | 'toml' | 'shell';

/** Export every member/local value under collision-safe generated names. */
export function buildBundleExport(
  bundle: VaultEntry,
  members: VaultEntry[],
  format: BundleExportFormat,
): string {
  const entries = [bundle, ...members];
  const generated: GeneratedName[] = [];
  type Out = { value: string; kind?: string; template?: string; varKey?: string };
  const values: Out[] = [];
  const resolveGlobal = (reference: string) => resolveFieldRef(`\${${reference}}`, true).resolved;
  for (const entry of entries) {
    const names = namesGeneratedBy(entry);
    const out: Out[] = [];
    if (entry.api_key) out.push({ value: entry.api_key });
    if (entry.api_secret) out.push({ value: entry.api_secret });
    if (entry.api_url) out.push({ value: entry.api_url });
    for (const variable of entry.extra_vars ?? []) {
      if (!variable.key) continue;
      let value = variable.value ?? '';
      if (variable.kind === 'template' && entry.id === bundle.id) {
        const resolved = resolveBundleTemplate(bundle, members, value, [], (reference) => {
          const result = resolveFieldRef(`\${${reference}}`, true);
          return result.resolved;
        });
        if (!resolved.ok)
          throw new Error(`Cannot export ${variable.key}: ${resolved.error.kind} reference`);
        value = resolved.value.value;
      }
      out.push({
        value,
        kind: variable.kind,
        ...(entry.id === bundle.id ? { varKey: variable.key } : {}),
        ...(variable.kind === 'template' && entry.id === bundle.id
          ? { template: variable.value }
          : {}),
      });
    }
    if (entry.secretType === 'composite' && entry.composite_template) {
      const rendered = renderBundleComposite(
        bundle,
        members,
        entry.composite_template,
        entry.extra_vars ?? [],
        entry.composite_kind ?? 'custom',
        resolveGlobal,
      );
      if (!rendered.ok) throw new Error(`Cannot export ${entry.provider}: unresolved composite`);
      const keyValue = out.find((_, i) => names[i]?.role === '');
      if (keyValue) keyValue.value = rendered.value;
      else {
        names.unshift({ name: primaryEnvName(entry), entry, role: '' });
        out.unshift({ value: rendered.value });
      }
    }
    generated.push(...names);
    values.push(...out);
  }
  const names = disambiguateNames(generated);
  const rows = names.map((name, i) => ({ name, ...values[i] }));
  // Bundle-local template variables exported under the name they were given, so
  // a Python/JS export can reference them (an f-string / template literal over
  // names) instead of baking in the rendered text.
  const localName = new Map<string, string>();
  rows.forEach((row) => {
    if (row.varKey) localName.set(row.varKey, row.name);
  });
  const segments = (template: string) => {
    const parts: ({ lit: string } | { ref: string })[] = [];
    let lit = '';
    for (let k = 0; k < template.length; k++) {
      const ch = template[k];
      if ((ch === '{' || ch === '}') && template[k + 1] === ch) {
        lit += ch === '{' ? '{{' : '}}';
        k++;
      } else if (ch === '{') {
        const end = template.indexOf('}', k);
        if (end < 0) return null;
        if (lit) parts.push({ lit });
        lit = '';
        parts.push({ ref: template.slice(k + 1, end) });
        k = end;
      } else lit += ch;
    }
    if (lit) parts.push({ lit });
    return parts;
  };
  /** Names a template row depends on, or null when it cannot stay symbolic. */
  const deps = (row: (typeof rows)[number]): string[] | null => {
    if (!row.template) return [];
    const parts = segments(row.template);
    if (!parts) return null;
    const names: string[] = [];
    for (const part of parts) {
      if ('ref' in part) {
        const target = localName.get(part.ref);
        if (!target) return null; // sibling field or global reference
        names.push(target);
      }
    }
    return names;
  };
  const symbolic = (row: (typeof rows)[number], lang: 'py' | 'js'): string | null => {
    const parts = row.template ? segments(row.template) : null;
    if (!parts || deps(row) === null) return null;
    if (lang === 'py') {
      const body = parts
        .map((part) =>
          'ref' in part
            ? `{${localName.get(part.ref)}}`
            : part.lit.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n'),
        )
        .join('');
      return `f"${body}"`;
    }
    const body = parts
      .map((part) =>
        'ref' in part
          ? `\${${localName.get(part.ref)}}`
          : part.lit
              .replace(/\\/g, '\\\\')
              .replace(/`/g, '\\`')
              .replace(/\$\{/g, '\\${')
              .replace(/\{\{/g, '{')
              .replace(/\}\}/g, '}'),
      )
      .join('');
    return `\`${body}\``;
  };
  /** Dependencies first; a row whose dependencies cannot be placed goes last. */
  const inDependencyOrder = () => {
    const placed = new Set<string>();
    const pending = [...rows];
    const ordered: typeof rows = [];
    while (pending.length) {
      const at = pending.findIndex((row) => (deps(row) ?? []).every((d) => placed.has(d)));
      const [next] = pending.splice(at < 0 ? 0 : at, 1);
      placed.add(next.name);
      ordered.push(next);
    }
    return ordered;
  };
  const pyValue = (row: (typeof rows)[number]) => {
    if (row.template) {
      const symbol = symbolic(row, 'py');
      if (symbol) return symbol;
    }
    if (row.kind === 'int' && /^[-+]?\d+$/.test(row.value)) return String(BigInt(row.value));
    if (row.kind === 'float' && /^[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?$/.test(row.value))
      return row.value;
    if (row.kind === 'bool') return row.value === 'true' ? 'True' : 'False';
    if (row.kind !== 'hex_int') return JSON.stringify(row.value);
    if (!/^(?:0[xX][\da-fA-F]+|\d+)$/.test(row.value))
      throw new Error(`${row.name} is marked hex_int but is not an integer`);
    return `0x${BigInt(row.value).toString(16)}`;
  };
  const jsValue = (row: (typeof rows)[number]) => {
    if (row.template) {
      const symbol = symbolic(row, 'js');
      if (symbol) return symbol;
    }
    // A JS number silently rounds above 2^53, so only safe integers go bare.
    if (
      row.kind === 'int' &&
      /^[-+]?\d+$/.test(row.value) &&
      Number.isSafeInteger(Number(row.value))
    )
      return row.value;
    if (row.kind === 'bool') return row.value;
    return JSON.stringify(row.value);
  };
  switch (format) {
    case 'dotenv':
      return rows.map(({ name, value }) => `${name}=${quoteEnvValue(value)}`).join('\n');
    case 'shell':
      return rows
        .map(({ name, value }) => `export ${name}='${value.replace(/'/g, "'\\''")}'`)
        .join('\n');
    case 'python':
      return inDependencyOrder()
        .map((row) => `${row.name} = ${pyValue(row)}`)
        .join('\n');
    case 'javascript':
    case 'typescript':
      return inDependencyOrder()
        .map((row) => `export const ${row.name} = ${jsValue(row)};`)
        .join('\n');
    case 'toml':
      return rows.map(({ name, value }) => `${name} = ${JSON.stringify(value)}`).join('\n');
    case 'yaml':
      return rows.map(({ name, value }) => `${name}: ${JSON.stringify(value)}`).join('\n');
    case 'json':
      return JSON.stringify(
        Object.fromEntries(rows.map(({ name, value }) => [name, value])),
        null,
        2,
      );
  }
}
