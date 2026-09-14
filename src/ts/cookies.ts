/**
 * @file
 * Session cookies — Phase 23, step 5.
 * @description The twin of `envv-cli/src/cookies.rs`, pinned by
 *              `tests/fixtures/parity/cookies.json` and asserted from both sides.
 *
 * ## Why a cookie is a credential this vault has to hold
 *
 * Spotify (`sp_dc`/`sp_key`), YouTube (`SAPISID`), Instagram (`sessionid` +
 * `csrftoken` + `ds_user_id`) and everything driven by `yt-dlp` are used through
 * a session cookie and nothing else. Before this there was **no home for one**:
 * the jar went in a free-text field, the User-Agent it was minted against went
 * nowhere, and replay without the matching User-Agent usually 401s — so the
 * vault held half a credential and did not say which half was missing.
 *
 * ## The parsing exists twice, and the format writing is pinned
 *
 * The form has to split a pasted `document.cookie` **as it is typed**, and an
 * IPC round trip per keystroke is not a form — the same reason the TOTP seed
 * parser exists twice. So both halves are written twice and pinned by one
 * fixture.
 *
 * ## `cookies.txt` is refused rather than approximated
 *
 * The Netscape format needs a domain, an include-subdomains flag, a path, a
 * secure flag and an expiry **per cookie**. A jar pasted as a bare
 * `document.cookie` string carries none of them. Writing a file `yt-dlp`
 * silently ignores is worse than not offering the button, so the export refuses
 * and names the attributes it does not have.
 */

import type { VaultEntry } from './types';

/** One cookie, with whatever attributes the source carried. */
export interface Cookie {
  name: string;
  value: string;
  /** Attributes are absent for a jar pasted as a bare `document.cookie` string. */
  domain?: string;
  path?: string;
  secure?: boolean;
  http_only?: boolean;
  /** Unix seconds. `0` / absent is a session cookie. */
  expires?: number;
}

/**
 * Cookie prefixes that are an instruction to the browser, not part of the name.
 *
 * Stripped, never transliterated — see `stripCookiePrefix` in `state.ts`, which
 * does the same for the generated variable name. That three cookies can collapse
 * into one name is exactly the case the collision check has to warn about.
 */
const COOKIE_PREFIX_RE = /^__(?:Host|Secure)-/i;

/**
 * Split a `document.cookie` string, or a `Cookie:` header.
 *
 * Deliberately forgiving: half the jars people paste come out of a devtools
 * panel with a trailing `;`, a stray newline, or the `Cookie: ` prefix still
 * attached. Losing the whole jar over one of those helps nobody — and unlike an
 * `otpauth://` URI there is no checksum to tell a mangled jar from a good one, so
 * the rule is to take what parses and drop what does not.
 */
export function parseCookieHeader(raw: string): Cookie[] {
  const body = (raw ?? '').replace(/^\s*Cookie:\s*/i, '').trim();
  if (!body) return [];
  const out: Cookie[] = [];
  for (const part of body.split(/;\s*|\n/)) {
    const piece = part.trim();
    if (!piece) continue;
    const eq = piece.indexOf('=');
    if (eq <= 0) continue;
    const name = piece.slice(0, eq).trim();
    if (!name) continue;
    out.push({ name, value: piece.slice(eq + 1).trim() });
  }
  return out;
}

/**
 * Parse a Netscape `cookies.txt`.
 *
 * Seven tab-separated fields: domain, include-subdomains, path, secure, expiry,
 * name, value. The `#HttpOnly_` line prefix is curl's extension and carries the
 * flag, so it is read rather than treated as a comment.
 */
export function parseCookiesTxt(raw: string): Cookie[] {
  const out: Cookie[] = [];
  for (const line of (raw ?? '').split(/\r?\n/)) {
    let l = line.trim();
    if (!l) continue;
    let httpOnly = false;
    if (/^#HttpOnly_/i.test(l)) {
      httpOnly = true;
      l = l.replace(/^#HttpOnly_/i, '');
    } else if (l.startsWith('#')) {
      continue;
    }
    const f = l.split('\t');
    if (f.length < 7) continue;
    out.push({
      domain: f[0],
      // The flag is the file's own claim about the domain; it is recomputed on
      // write from the leading dot, so it is not stored separately.
      path: f[2],
      secure: f[3].toUpperCase() === 'TRUE',
      expires: Number(f[4]) || 0,
      name: f[5],
      value: f.slice(6).join('\t'),
      http_only: httpOnly || undefined,
    });
  }
  return out;
}

/**
 * A single value from a browser-extension JSON export, which vary in spelling.
 *
 * Every field is taken **only when it is already a string** rather than
 * stringified: this is a parsed JSON document from a file the user picked, i.e.
 * untrusted input (invariant 4), and `String(someObject)` would quietly put
 * `[object Object]` into a cookie name rather than rejecting the row.
 */
function fromJsonCookie(raw: Record<string, unknown>): Cookie | null {
  const str = (...keys: string[]): string | undefined => {
    for (const k of keys) {
      const v = raw[k];
      if (typeof v === 'string' && v !== '') return v;
    }
    return undefined;
  };
  const flag = (...keys: string[]): boolean | undefined =>
    keys.some((k) => raw[k] === true) || undefined;

  const name = str('name', 'Name');
  if (!name) return null;
  const expiry = ['expirationDate', 'expires', 'expiry', 'Expires']
    .map((k) => raw[k])
    .find((v) => typeof v === 'number');
  return {
    name,
    value: str('value', 'Value') ?? '',
    domain: str('domain'),
    path: str('path'),
    secure: flag('secure', 'Secure'),
    http_only: flag('httpOnly', 'HttpOnly'),
    expires: typeof expiry === 'number' ? Math.floor(expiry) : undefined,
  };
}

/** Parse the array shape every "Copy all as JSON" / cookie-editor extension writes. */
export function parseCookieJson(raw: string): Cookie[] {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    return [];
  }
  const arr = Array.isArray(doc)
    ? doc
    : Array.isArray((doc as { cookies?: unknown })?.cookies)
      ? (doc as { cookies: unknown[] }).cookies
      : [];
  return arr
    .map((c) => fromJsonCookie(c as Record<string, unknown>))
    .filter((c): c is Cookie => !!c);
}

/**
 * Whatever was pasted, as cookies.
 *
 * One entry point rather than three, because the user pasting a jar does not
 * know which of the three formats their browser gave them — and asking is a
 * worse question than looking.
 */
export function parseAnyCookies(raw: string): Cookie[] {
  const text = (raw ?? '').trim();
  if (!text) return [];
  if (text.startsWith('[') || text.startsWith('{')) {
    const json = parseCookieJson(text);
    if (json.length) return json;
  }
  if (text.includes('\t')) {
    const txt = parseCookiesTxt(text);
    if (txt.length) return txt;
  }
  return parseCookieHeader(text);
}

/** The `Cookie:` header value — what a request actually sends. */
export function toCookieHeader(cookies: Cookie[]): string {
  return cookies
    .filter((c) => c.name)
    .map((c) => `${c.name}=${c.value}`)
    .join('; ');
}

/** Which attributes `cookies.txt` needs and this jar does not have. */
export function missingTxtAttributes(cookies: Cookie[]): string[] {
  const missing = new Set<string>();
  for (const c of cookies) {
    if (!c.domain) missing.add('domain');
    if (!c.path) missing.add('path');
  }
  return [...missing].sort();
}

/**
 * Netscape `cookies.txt`, for `curl -b` and `yt-dlp --cookies`.
 *
 * **Throws when the attributes are not there.** A jar pasted as a bare
 * `document.cookie` string has no domain and no path, and a file missing them is
 * one `yt-dlp` reads and silently ignores — which the user discovers as "the
 * download is not logged in", with nothing pointing at the file.
 */
export function toCookiesTxt(cookies: Cookie[]): string {
  const missing = missingTxtAttributes(cookies);
  if (missing.length) {
    throw new Error(
      `cookies.txt needs ${missing.join(' and ')} for every cookie, and this jar has none. ` +
        `Re-export it from the browser as JSON or as cookies.txt rather than copying document.cookie.`,
    );
  }
  const lines = [
    '# Netscape HTTP Cookie File',
    '# Written by EnvVault. Move it somewhere safe and delete it when done.',
  ];
  for (const c of cookies) {
    const domain = c.domain!;
    // The include-subdomains column is the leading dot, restated. Deriving it
    // rather than storing it means the two can never disagree.
    const includeSub = domain.startsWith('.') ? 'TRUE' : 'FALSE';
    const line = [
      domain,
      includeSub,
      c.path || '/',
      c.secure ? 'TRUE' : 'FALSE',
      String(c.expires ?? 0),
      c.name,
      c.value,
    ].join('\t');
    lines.push(c.http_only ? `#HttpOnly_${line}` : line);
  }
  return lines.join('\n') + '\n';
}

/** The browser-extension array shape, so a jar round-trips back into a browser. */
export function toCookieJson(cookies: Cookie[]): string {
  return JSON.stringify(
    cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain ?? '',
      path: c.path ?? '/',
      secure: !!c.secure,
      httpOnly: !!c.http_only,
      // The key every extension reads back, and seconds because that is what
      // `cookies.txt` carries — a jar that round-trips must not gain or lose a
      // factor of 1000 on the way.
      expirationDate: c.expires ?? 0,
    })),
    null,
    2,
  );
}

/** The cookie name with any `__Host-` / `__Secure-` prefix removed. */
export function bareCookieName(name: string): string {
  return (name ?? '').replace(COOKIE_PREFIX_RE, '');
}

// ── Vault entry ↔ cookies ─────────────────────────────────────────────────

/**
 * Every cookie an entry holds, from wherever it keeps them.
 *
 * The jar lives in `api_key` as a header string, and the individual cookies live
 * in `extra_vars` once the user has split them — with `attrs` carrying what
 * `cookies.txt` needs and a pasted `document.cookie` string does not have.
 * Reading both and preferring the split form is what lets one entry serve the
 * header export (which needs no attributes) and the `cookies.txt` export (which
 * needs all of them).
 *
 * Twin: `cookies_of` in `envv-cli/src/entries.rs`.
 */
export function cookiesOf(entry: VaultEntry): Cookie[] {
  const split = (entry.extra_vars ?? [])
    .filter((xv) => xv.key)
    .map((xv) => ({
      name: xv.key,
      value: xv.value ?? '',
      domain: xv.attrs?.domain,
      path: xv.attrs?.path,
      secure: xv.attrs?.secure,
      http_only: xv.attrs?.http_only,
      expires: xv.attrs?.expires,
    }));
  if (split.length) return split;
  return parseCookieHeader(entry.api_key ?? '');
}

/**
 * Turn a parsed jar into `extra_vars` rows.
 *
 * One row per cookie, attributes carried in `attrs` — which is what makes the
 * `cookies.txt` export possible at all, and what tells the user *why* it is
 * refused when the paste was a bare `document.cookie` string.
 */
export function cookiesToExtraVars(cookies: Cookie[]): NonNullable<VaultEntry['extra_vars']> {
  return cookies.map((c) => {
    const attrs: NonNullable<NonNullable<VaultEntry['extra_vars']>[number]['attrs']> = {};
    if (c.domain) attrs.domain = c.domain;
    if (c.path) attrs.path = c.path;
    if (c.secure) attrs.secure = true;
    if (c.http_only) attrs.http_only = true;
    if (c.expires) attrs.expires = c.expires;
    return {
      key: c.name,
      value: c.value,
      // Every cookie in a jar is a live session credential, so none of them is
      // ever the "public half" — `redact_entry` masks a cookie entry's vars
      // whole and ignores the flag, and writing `public` here would be a claim
      // the redactor deliberately does not honour.
      secret: true,
      ...(Object.keys(attrs).length ? { attrs } : {}),
    };
  });
}
