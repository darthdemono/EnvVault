/** Bundle-local template resolution (Phase 24.1, step 4). */
import type { Project, VaultEntry } from './types';
import { renderComposite, type CompositeKind, type RenderError } from './composite';
import { getEntryFieldValue, isEntryFieldPublic } from './chunk-ops';
import { newEntryId } from './state';

export interface ScopedValue {
  value: string;
  secret: boolean;
}

export interface BundleReferenceSite {
  label: string;
  template: string;
}

/** Cascade a bundle-name change through bundle selectors in stored templates. */
export function renameBundleRefs(
  entries: VaultEntry[],
  projects: Project[],
  oldName: string,
  newName: string,
): number {
  if (!oldName || oldName === newName) return 0;
  const escaped = oldName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const selector = new RegExp(`\\$\\{bundle:${escaped}(?=/|\\})`, 'g');
  let changed = 0;
  const rewrite = (template: string): string =>
    template.replace(selector, () => {
      changed++;
      return `\${bundle:${newName}`;
    });
  for (const entry of entries) {
    if (entry.composite_template) entry.composite_template = rewrite(entry.composite_template);
    for (const variable of entry.extra_vars ?? []) {
      if (variable.kind === 'template') variable.value = rewrite(variable.value);
    }
  }
  for (const project of projects) {
    for (const chunk of project.chunks ?? []) {
      for (const field of chunk.fields ?? []) field.value = rewrite(field.value);
    }
  }
  return changed;
}

/** Cascade a slot rename through scoped and globally addressed templates. */
export function renameBundleSlotRefs(
  entries: VaultEntry[],
  projects: Project[],
  bundle: VaultEntry,
  oldSlot: string,
  newSlot: string,
): number {
  if (!oldSlot || oldSlot === newSlot) return 0;
  const escape = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const globalRef = new RegExp(
    `(\\$\\{bundle:${escape(bundle.provider)}/)${escape(oldSlot)}(?=/|\\})`,
    'g',
  );
  const scopedRef = new RegExp(`\\{${escape(oldSlot)}(?=\\.[A-Za-z_][A-Za-z0-9_]*\\})`, 'g');
  let changed = 0;
  const rewriteGlobal = (template: string) =>
    template.replace(globalRef, (_match, prefix: string) => {
      changed++;
      return `${prefix}${newSlot}`;
    });
  const rewriteScoped = (template: string) =>
    template.replace(scopedRef, () => {
      changed++;
      return `{${newSlot}`;
    });
  for (const entry of entries) {
    if (entry.composite_template) {
      entry.composite_template = rewriteGlobal(entry.composite_template);
      if (entry.bundle_id === bundle.id)
        entry.composite_template = rewriteScoped(entry.composite_template);
    }
    for (const variable of entry.extra_vars ?? []) {
      if (variable.kind !== 'template') continue;
      variable.value = rewriteGlobal(variable.value);
      if (entry.id === bundle.id || entry.bundle_id === bundle.id)
        variable.value = rewriteScoped(variable.value);
    }
  }
  for (const project of projects) {
    for (const chunk of project.chunks ?? []) {
      for (const field of chunk.fields ?? []) field.value = rewriteGlobal(field.value);
    }
  }
  return changed;
}

/** Cascade a local-variable rename through bundle templates and global selectors. */
export function renameBundleLocalRefs(
  entries: VaultEntry[],
  projects: Project[],
  bundle: VaultEntry,
  oldName: string,
  newName: string,
): number {
  if (!oldName || oldName === newName) return 0;
  const escape = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const globalRef = new RegExp(
    `(\\$\\{bundle:${escape(bundle.provider)}/)${escape(oldName)}(?=/|\\})`,
    'g',
  );
  const localRef = new RegExp(`\\{${escape(oldName)}\\}`, 'g');
  let changed = 0;
  const rewriteGlobal = (template: string) =>
    template.replace(globalRef, (_match, prefix: string) => {
      changed++;
      return `${prefix}${newName}`;
    });
  const rewriteLocal = (template: string) =>
    template.replace(localRef, () => {
      changed++;
      return `{${newName}}`;
    });
  for (const entry of entries) {
    if (entry.composite_template) {
      entry.composite_template = rewriteGlobal(entry.composite_template);
      if (entry.bundle_id === bundle.id)
        entry.composite_template = rewriteLocal(entry.composite_template);
    }
    for (const variable of entry.extra_vars ?? []) {
      if (variable.kind !== 'template') continue;
      variable.value = rewriteGlobal(variable.value);
      if (entry.id === bundle.id || entry.bundle_id === bundle.id)
        variable.value = rewriteLocal(variable.value);
    }
  }
  for (const project of projects) {
    for (const chunk of project.chunks ?? []) {
      for (const field of chunk.fields ?? []) field.value = rewriteGlobal(field.value);
    }
  }
  return changed;
}

/** Find bundle-scope templates that would become unresolved after member deletion. */
export function referencesToBundleMember(
  bundle: VaultEntry,
  member: VaultEntry,
  entries: VaultEntry[],
  projects: Project[] = [],
): BundleReferenceSite[] {
  const slot = member.bundle_slot || member.provider;
  const bundleName = bundle.provider.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const slotName = slot.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const globalRef = new RegExp(`\\$\\{bundle:${bundleName}/${slotName}(?:/[^}]+)?\\}`);
  const scopedRef = new RegExp(`\\{${slotName}\\.[A-Za-z_][A-Za-z0-9_]*\\}`);
  const sites: BundleReferenceSite[] = [];
  const seen = new Set<string>();
  const add = (label: string, template: string, scoped: boolean) => {
    if (!(scoped ? scopedRef.test(template) : globalRef.test(template))) return;
    const key = `${label}\0${template}`;
    if (seen.has(key)) return;
    seen.add(key);
    sites.push({ label, template });
  };

  for (const entry of entries) {
    if (entry.composite_template) {
      add(`${entry.provider} composite`, entry.composite_template, entry.bundle_id === bundle.id);
      add(`${entry.provider} composite`, entry.composite_template, false);
    }
    for (const variable of entry.extra_vars ?? []) {
      if (variable.kind === 'template') {
        const label = `${entry.provider} / ${variable.key}`;
        add(label, variable.value, entry.id === bundle.id);
        add(label, variable.value, false);
      }
    }
  }
  for (const project of projects) {
    for (const chunk of project.chunks ?? []) {
      for (const field of chunk.fields ?? []) {
        if (typeof field.value === 'string')
          add(`${project.name} / ${chunk.name} / ${field.key}`, field.value, false);
      }
    }
  }
  return sites;
}

export type ScopeError =
  | { kind: 'unresolved'; reference: string }
  | { kind: 'cycle'; path: string[] }
  | { kind: 'depth'; reference: string }
  | { kind: 'invalid'; message: string };

export type ScopeResult =
  | { ok: true; value: ScopedValue; warnings: string[] }
  | { ok: false; error: ScopeError; warnings: string[] };

export type BundleCompositeResult =
  | { ok: true; value: string; secret: boolean; warnings: string[] }
  | { ok: false; error: ScopeError | RenderError; warnings: string[] };

const MAX_DEPTH = 4;

function secretValue(value: unknown, secret: boolean): ScopedValue | null {
  return typeof value === 'string' ? { value, secret } : null;
}

function entryField(entry: VaultEntry, field: string): ScopedValue | null {
  // Global references intentionally deny the entry UUID as `id`; a bundle
  // member's explicitly named `id` variable is data, not row metadata.
  const exactVariable = entry.extra_vars?.find((item) => item.key === field);
  if (exactVariable)
    return secretValue(
      exactVariable.value,
      exactVariable.public !== true && exactVariable.secret !== false,
    );
  const value = getEntryFieldValue(entry, field);
  return value == null || value === ''
    ? null
    : secretValue(String(value), !isEntryFieldPublic(entry, field));
}

/** Resolve `{local}` and `{slot.field}`. Missing or hidden inputs fail closed. */
export function resolveBundleTemplate(
  bundle: VaultEntry,
  members: VaultEntry[],
  template: string,
  ownParts: NonNullable<VaultEntry['extra_vars']> = [],
  globalResolver?: (reference: string) => string | ScopedValue | null,
): ScopeResult {
  const warnings: string[] = [];
  const slots = new Map<string, VaultEntry>();
  for (const member of members) {
    const slot = member.bundle_slot || member.provider;
    if (slots.has(slot))
      return {
        ok: false,
        error: { kind: 'invalid', message: `duplicate bundle slot "${slot}"` },
        warnings,
      };
    slots.set(slot, member);
  }
  const locals = new Map((bundle.extra_vars ?? []).map((item) => [item.key, item]));
  const parts = new Map(ownParts.map((item) => [item.key, item]));
  for (const name of locals.keys()) {
    if (parts.has(name) || members.some((member) => member.bundle_slot === name))
      warnings.push(`"${name}" exists at more than one scope level; the part wins over the local`);
  }

  const resolveText = (text: string, stack: string[], depth: number): ScopeResult => {
    let value = '';
    let secret = false;
    const append = (piece: ScopedValue) => {
      value += piece.value;
      secret ||= piece.secret;
    };
    for (let i = 0; i < text.length;) {
      if (text.startsWith('{{', i)) {
        value += '{';
        i += 2;
        continue;
      }
      if (text.startsWith('}}', i)) {
        value += '}';
        i += 2;
        continue;
      }
      if (text.startsWith('${', i)) {
        const end = text.indexOf('}', i + 2);
        if (end < 0)
          return {
            ok: false,
            error: { kind: 'invalid', message: `unclosed global reference at ${i}` },
            warnings,
          };
        const reference = text.slice(i + 2, end);
        const resolved = globalResolver?.(reference) ?? null;
        if (resolved === null)
          return {
            ok: false,
            error: { kind: 'unresolved', reference: `\${${reference}}` },
            warnings,
          };
        append(typeof resolved === 'string' ? { value: resolved, secret: true } : resolved);
        i = end + 1;
        continue;
      }
      if (text[i] !== '{') {
        if (text[i] === '}')
          return {
            ok: false,
            error: { kind: 'invalid', message: `unmatched closing brace at ${i}` },
            warnings,
          };
        value += text[i++];
        continue;
      }
      const end = text.indexOf('}', i + 1);
      if (end < 0)
        return {
          ok: false,
          error: { kind: 'invalid', message: `unclosed brace at ${i}` },
          warnings,
        };
      const reference = text.slice(i + 1, end);
      if (!/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$/.test(reference))
        return {
          ok: false,
          error: { kind: 'invalid', message: `invalid reference "${reference}"` },
          warnings,
        };
      let part: ScopedValue | null = null;
      const own = parts.get(reference);
      const local = locals.get(reference);
      if (own) {
        part = secretValue(own.value, own.public !== true && own.secret !== false);
      } else if (local) {
        if (stack.includes(reference))
          return { ok: false, error: { kind: 'cycle', path: [...stack, reference] }, warnings };
        if (local.kind === 'template' && depth >= MAX_DEPTH && /\{(?!\{)[^{}]+\}/.test(local.value))
          return { ok: false, error: { kind: 'depth', reference }, warnings };
        const nested =
          local.kind === 'template'
            ? resolveText(local.value, [...stack, reference], depth + 1)
            : { ok: true as const, value: { value: local.value, secret: false }, warnings };
        if (!nested.ok) return nested;
        part = {
          value: nested.value.value,
          secret: nested.value.secret || (local.public !== true && local.secret !== false),
        };
      } else {
        const dot = reference.indexOf('.');
        if (dot > 0) {
          const member = slots.get(reference.slice(0, dot));
          part = member ? entryField(member, reference.slice(dot + 1)) : null;
        }
      }
      if (!part) return { ok: false, error: { kind: 'unresolved', reference }, warnings };
      append(part);
      i = end + 1;
    }
    return { ok: true, value: { value, secret }, warnings };
  };

  return resolveText(template, [], 0);
}

/** Resolve bundle references into synthetic parts, then use the zone-aware
 * composite renderer so each reference is encoded in its own URL position. */
export function renderBundleComposite(
  bundle: VaultEntry,
  members: VaultEntry[],
  template: string,
  ownParts: NonNullable<VaultEntry['extra_vars']>,
  kind: CompositeKind,
  globalResolver?: (reference: string) => string | ScopedValue | null,
): BundleCompositeResult {
  const refs: { key: string; value: string }[] = [];
  const warnings: string[] = [];
  let secret = false;
  let expanded = '';
  let index = 0;
  for (let i = 0; i < template.length;) {
    if (template.startsWith('{{', i) || template.startsWith('}}', i)) {
      expanded += template.slice(i, i + 2);
      i += 2;
      continue;
    }
    if (template.startsWith('${', i)) {
      const end = template.indexOf('}', i + 2);
      if (end < 0)
        return {
          ok: false,
          error: { kind: 'invalid', message: `unclosed global reference at ${i}` },
          warnings,
        };
      const resolved = resolveBundleTemplate(
        bundle,
        members,
        template.slice(i, end + 1),
        ownParts,
        globalResolver,
      );
      warnings.push(...resolved.warnings);
      if (!resolved.ok) return resolved;
      const key = `scope_${index++}`;
      refs.push({ key, value: resolved.value.value });
      secret ||= resolved.value.secret;
      expanded += `{${key}}`;
      i = end + 1;
      continue;
    }
    if (template[i] !== '{') {
      if (template[i] === '}')
        return {
          ok: false,
          error: { kind: 'invalid', message: `unmatched closing brace at ${i}` },
          warnings,
        };
      expanded += template[i++];
      continue;
    }
    const end = template.indexOf('}', i + 1);
    if (end < 0)
      return { ok: false, error: { kind: 'invalid', message: `unclosed brace at ${i}` }, warnings };
    const ref = template.slice(i + 1, end);
    const resolved = resolveBundleTemplate(bundle, members, `{${ref}}`, ownParts, globalResolver);
    warnings.push(...resolved.warnings);
    if (!resolved.ok) return resolved;
    const key = `scope_${index++}`;
    refs.push({ key, value: resolved.value.value });
    secret ||= resolved.value.secret;
    expanded += `{${key}}`;
    i = end + 1;
  }
  const rendered = renderComposite(expanded, refs, kind);
  return rendered.ok
    ? { ok: true, value: rendered.result.text, secret, warnings }
    : { ok: false, error: rendered.error, warnings };
}

/**
 * Attach `members` to a new bundle entry named `name`. Mutates the members and
 * returns the bundle; the caller pushes it and persists once (B14). Slots come
 * from each member's label or provider, made valid and unique.
 */
export function buildBundle(members: VaultEntry[], name: string): VaultEntry {
  const id = newEntryId();
  const bundle: VaultEntry = {
    id,
    provider: name.trim(),
    secretType: 'bundle',
    api_key: '',
    price_type: 'free',
    categories: [],
    scopes: [],
    extra_vars: [],
    projectIds: [],
    tags: [],
    pinned: false,
    ...(members[0]?.id ? { bundle_primary: members[0].id } : {}),
  };
  const slots = new Set<string>();
  members.forEach((entry, index) => {
    entry.bundle_id = id;
    const base = (entry.label || entry.provider)
      .trim()
      .replace(/[^A-Za-z0-9_-]+/g, '_')
      .slice(0, 24);
    let slot = /^[A-Za-z0-9]/.test(base) ? base : `member_${index + 1}`;
    for (let suffix = 2; slots.has(slot); suffix++) {
      const tail = `_${suffix}`;
      slot = `${base.slice(0, 24 - tail.length)}${tail}`;
    }
    slots.add(slot);
    entry.bundle_slot = slot;
    entry.bundle_order = (index + 1) * 10;
  });
  return bundle;
}

/**
 * Providers (case-folded) with two or more unbundled, un-pooled entries that
 * have not been dismissed. Suggested, never automatic.
 */
export function bundleSuggestions(
  entries: VaultEntry[],
  dismissed: string[],
): { provider: string; entries: VaultEntry[] }[] {
  const skip = new Set(dismissed.map((d) => d.toLowerCase()));
  const groups = new Map<string, VaultEntry[]>();
  for (const e of entries) {
    // Vault data is untrusted (invariant 4): a hand-edited `pool` or `provider`
    // need not be a string.
    if (e.secretType === 'bundle' || e.bundle_id || !e.id) continue;
    if (typeof e.pool === 'string' && e.pool.trim()) continue;
    if (typeof e.provider !== 'string') continue;
    const key = e.provider.trim().toLowerCase();
    if (!key || skip.has(key)) continue;
    groups.set(key, [...(groups.get(key) ?? []), e]);
  }
  return [...groups.entries()]
    .filter(([, list]) => list.length >= 2)
    .map(([, list]) => ({ provider: list[0].provider, entries: list }));
}
