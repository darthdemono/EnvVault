/**
 * @file
 * How a credential is *sent* — Phase 23, E16.
 * @description The twin of `unv-cli/src/authreq.rs`, pinned by
 *              `tests/fixtures/parity/auth-request.json` and asserted from both
 *              sides.
 *
 * ## Why this is a field and not a convention
 *
 * *How to send it* is part of the credential, and it was nowhere in the model.
 * Two entries holding the same-looking string are used completely differently:
 * one goes in `Authorization: Bearer`, one in `X-Api-Key`, one in `?api_key=`,
 * one is the password half of HTTP basic. The vault knew the secret and not the
 * one other thing you need in order to use it, so the user was left to remember
 * which service wants which — and to get it wrong at 3am against an API that
 * answers `401` either way.
 *
 * `auth_scheme` + `auth_param` are what turn a stored string into a working
 * request, and they are what the curl export needs anyway.
 *
 * ## Shell quoting is not optional here
 *
 * A cookie, a User-Agent or a password containing `'` breaks `-H '…'`, and the
 * value is vault data, i.e. untrusted input (invariant 4). `shellQuote` is
 * POSIX single-quoting with the one escape that form allows, so a value can
 * never end the quoted string and start a command.
 */

import type { VaultEntry } from './types';

/** The ways a credential can be attached to a request. */
export type AuthScheme = 'bearer' | 'header' | 'basic' | 'query' | 'cookie';

/** One header, as a name and a value. */
export interface AuthHeader {
  name: string;
  value: string;
}

/**
 * POSIX single-quoting.
 *
 * `'` cannot appear inside single quotes at all, so the only way to include one
 * is to close, emit an escaped quote, and reopen. Everything else — `$`, a
 * backtick, a newline, a semicolon — is literal inside single quotes, which is
 * exactly the property wanted for a value that came out of a vault.
 */
export function shellQuote(value: string): string {
  return `'${(value ?? '').replace(/'/g, `'\\''`)}'`;
}

/** The scheme this entry uses, with the legacy default spelled out. */
export function authSchemeOf(entry: VaultEntry): AuthScheme {
  const s = (entry.auth_scheme ?? '').toString().toLowerCase();
  if (s === 'bearer' || s === 'header' || s === 'basic' || s === 'query' || s === 'cookie') {
    return s;
  }
  // Absent means `bearer`: it is what most issuers want, and — more to the point
  // — it is the one that fails *loudly*. A wrong header name produces a 401 that
  // names nothing; a bearer token sent to an API that wanted a query parameter
  // produces the same 401, but the user has something to read in the command.
  return 'bearer';
}

/** The header or query-parameter name, with each scheme's default filled in. */
export function authParamOf(entry: VaultEntry): string {
  const explicit = (entry.auth_param ?? '').toString().trim();
  if (explicit) return explicit;
  switch (authSchemeOf(entry)) {
    case 'header':
      return 'X-Api-Key';
    case 'query':
      return 'api_key';
    case 'cookie':
      return 'Cookie';
    default:
      return '';
  }
}

/**
 * The value the scheme sends.
 *
 * `basic` uses `username:api_key`, which is what every issuer that asks for HTTP
 * basic means by it — Twilio's Account SID and Auth Token, Stripe's key with an
 * empty password, a registry login.
 */
function authValue(entry: VaultEntry): string {
  return entry.api_key ?? '';
}

/** base64 of a UTF-8 string. `btoa` is Latin-1 and throws above U+00FF (invariant 6). */
function b64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  // Chunked: spreading every byte as a call argument blows the stack past
  // ~100 KB (invariant 6), and a password is not usually that long but a
  // certificate pasted into the wrong field is.
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

/**
 * What a `header` entry sends: the key, or the key placed into `auth_template`
 * (Jellyfin's `MediaBrowser Token="{key}"`). A template with no `{key}`, a line
 * break, a NUL or over 128 bytes is ignored rather than guessed at: a header that
 * silently lacks the key is a 401 that names nothing. Twin of `header_value` in
 * `authreq.rs`.
 */
export function authHeaderValue(entry: VaultEntry, key: string): string {
  const t = (entry.auth_template ?? '').toString();
  if (
    !t ||
    new TextEncoder().encode(t).length > 128 ||
    !t.includes('{key}') ||
    /[\r\n\0]/.test(t)
  ) {
    return key;
  }
  return t.split('{key}').join(key);
}

/**
 * The header this entry contributes to a request, or `null` for the schemes that
 * do not use one.
 */
export function authHeaderFor(entry: VaultEntry): AuthHeader | null {
  const value = authValue(entry);
  if (!value) return null;
  switch (authSchemeOf(entry)) {
    case 'bearer':
      return { name: 'Authorization', value: `Bearer ${value}` };
    case 'header':
      return { name: authParamOf(entry), value: authHeaderValue(entry, value) };
    case 'basic':
      return {
        name: 'Authorization',
        value: `Basic ${b64(`${entry.username ?? ''}:${value}`)}`,
      };
    case 'cookie':
      return { name: 'Cookie', value };
    case 'query':
      return null;
  }
}

/** The query fragment (`api_key=…`) this entry contributes, or `null`. */
export function authQueryFor(entry: VaultEntry): string | null {
  if (authSchemeOf(entry) !== 'query') return null;
  const value = authValue(entry);
  if (!value) return null;
  return `${encodeURIComponent(authParamOf(entry))}=${encodeURIComponent(value)}`;
}

/**
 * Attach the credential to a URL. Only `query` changes it; every other scheme
 * returns it unchanged.
 */
export function authUrlFor(entry: VaultEntry, url: string): string {
  const q = authQueryFor(entry);
  if (!q) return url;
  return url.includes('?') ? `${url}&${q}` : `${url}?${q}`;
}

/**
 * A `curl` command that sends this credential to `url`.
 *
 * Every interpolated value is shell-quoted, because all of them are vault data
 * and one of them is routinely a cookie jar full of semicolons.
 *
 * This is a **materialising** path: it contains the real credential. The CLI
 * refuses it to stdout without `--reveal` and writes it with `--out`, exactly as
 * `unv export` does; in the app it is a copy, which is the UI's `--reveal`.
 */
export function curlFor(entry: VaultEntry, url?: string): string {
  const target = url || entry.api_url || 'https://example.invalid/';
  const parts = ['curl'];
  const h = authHeaderFor(entry);
  if (h) parts.push('-H', shellQuote(`${h.name}: ${h.value}`));
  if (entry.user_agent) parts.push('-H', shellQuote(`User-Agent: ${entry.user_agent}`));
  parts.push(shellQuote(authUrlFor(entry, target)));
  return parts.join(' ');
}
