/**
 * @file
 * Web session provider presets — Phase 24.5.
 *
 * `session-presets.json` names, for a handful of sites, which cookies a
 * session needs and what header a copy derives from them. Nothing here is
 * fetched or verified automatically — the form flags a missing required
 * cookie by name, and that is the whole feature. Every preset carries the
 * date its shape was last checked against a real capture; treat an old one
 * as a starting point, not a guarantee the site has not changed since.
 *
 * The one real computation is `sapisidhash` — YouTube/Google's
 * `Authorization: SAPISIDHASH <ts>_<sha1(ts + " " + SAPISID + " " + origin)>`
 * — which is why {@link deriveHeaders} is async: `crypto.subtle.digest` is a
 * promise, and there is no synchronous SHA-1 in a browser without a bundled
 * library the CSP would have to allow.
 */
import presetsJson from '../../session-presets.json';
import type { VaultEntry } from './types';
import { cookiesOf } from './cookies';

export interface HeaderRecipeEntry {
  name: string;
  source: 'static' | 'cookie' | 'derived';
  static_value?: string;
  cookie_name?: string;
  strip_quotes?: boolean;
  derived_id?: string;
}

export interface SessionPreset {
  id: string;
  label: string;
  required_cookies: string[];
  optional_cookies: string[];
  header_recipe: HeaderRecipeEntry[];
  /** What the session is bound to — `user_agent` and/or `origin`. Copying it
   * under a different one of these usually 401s or gets flagged; the form
   * warns rather than blocks, since "usually" is not "always". */
  bindings: ('user_agent' | 'origin')[];
  verified_on: string;
}

const PRESETS: SessionPreset[] = (presetsJson as { presets: SessionPreset[] }).presets;

export function presets(): SessionPreset[] {
  return PRESETS;
}

export function findPreset(id: string): SessionPreset | undefined {
  return PRESETS.find((p) => p.id === id);
}

/** Required cookies the entry's jar does not have. Empty means the session
 * is complete as far as this preset can tell. */
export function missingRequiredCookies(entry: VaultEntry, preset: SessionPreset): string[] {
  const have = new Set(cookiesOf(entry).map((c) => c.name));
  return preset.required_cookies.filter((name) => !have.has(name));
}

/**
 * `SHA1(timestamp + " " + SAPISID + " " + origin)`, hex-encoded — the one
 * derivation this module actually computes rather than copies.
 *
 * SHA-1 here is not a security choice, it is Google's: this is the exact
 * legacy algorithm their own endpoints still require for this header, unlike
 * every other use of a hash in this project.
 */
async function sapisidHash(sapisid: string, origin: string, nowMs = Date.now()): Promise<string> {
  const ts = Math.floor(nowMs / 1000).toString();
  const input = `${ts} ${sapisid} ${origin}`;
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-1', bytes);
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `SAPISIDHASH ${ts}_${hex}`;
}

/**
 * One header per recipe entry the jar can actually satisfy — a `cookie`
 * source with no matching cookie, or a `derived` source this module does not
 * know how to compute, is silently omitted rather than emitted empty or
 * thrown; the caller decides whether that is fatal.
 */
export async function deriveHeaders(
  entry: VaultEntry,
  preset: SessionPreset,
  origin?: string,
  nowMs?: number,
): Promise<{ name: string; value: string }[]> {
  const cookies = cookiesOf(entry);
  const out: { name: string; value: string }[] = [];
  for (const recipe of preset.header_recipe) {
    if (recipe.source === 'static' && recipe.static_value !== undefined) {
      out.push({ name: recipe.name, value: recipe.static_value });
      continue;
    }
    if (recipe.source === 'cookie' && recipe.cookie_name) {
      const c = cookies.find((c) => c.name === recipe.cookie_name);
      if (!c) continue;
      const value = recipe.strip_quotes ? c.value.replace(/^"|"$/g, '') : c.value;
      out.push({ name: recipe.name, value });
      continue;
    }
    if (recipe.source === 'derived' && recipe.derived_id === 'sapisidhash') {
      const sapisid = cookies.find((c) => c.name === 'SAPISID')?.value;
      const o = origin ?? entry.api_url ?? '';
      if (!sapisid || !o) continue;
      out.push({ name: recipe.name, value: await sapisidHash(sapisid, o, nowMs) });
    }
  }
  return out;
}
