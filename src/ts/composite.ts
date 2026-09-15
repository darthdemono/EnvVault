/**
 * @file
 * Composite secrets (Phase 24.1) — one value with secrets inside it.
 * @description The motivating case is a calendar-sharing URL,
 *   `https://outlook.office365.com/owa/calendar/{mailbox_id}@inf.elte.hu/{calendar_key}/calendar.ics`,
 *   where two path segments are credentials and the rest is structure. The
 *   root is the **template**; each placeholder is a **part**. Parts are
 *   ordinary `extra_vars` — key is the placeholder name, value is the secret —
 *   because that shape already has fail-closed masking with a `public`
 *   opt-out (E5), per-name history (E8), env naming and `${X/NAME}`
 *   references. A second array would re-implement all four for no reason.
 *
 * This is a twin pair with `vault-core/src/composite.rs`, pinned by
 * `tests/fixtures/parity/composite.json`. The form needs a live preview as
 * the user types, so rendering exists in both languages, and two
 * implementations of one template language drift silently if nothing asserts
 * they agree — see `tests/composite.test.ts` and `vault-core/tests`.
 *
 * ## Encoding
 *
 * Parts are stored **raw**; the renderer classifies each placeholder's zone
 * from the **template's own structure** (never from a URL built out of real
 * values, which would already contain a possibly `/`-or-`@`-bearing part) and
 * percent-encodes using exactly RFC 3986's unreserved set. Deliberately not
 * the built-in `encodeURIComponent` — it leaves `! ~ * ' ( )` unescaped in
 * addition to the RFC set, and the Rust side must byte-for-byte agree with
 * whatever this does.
 */

/** What a composite template *is* — decides encoding and whether Open is offered. */
export type CompositeKind = 'link' | 'signed_link' | 'connection' | 'custom' | (string & {});

/** One named `{part}` and the raw value it holds. */
export interface CompositePart {
  key: string;
  value: string;
}

export interface RenderedComposite {
  text: string;
  /** Placeholder names actually found in the template, in first-use order. */
  used: string[];
  /** Parts supplied but never referenced by the template — a warning, not an error. */
  unused: string[];
}

export type RenderError =
  | { kind: 'unfilled_placeholder'; name: string }
  | { kind: 'unbalanced_brace'; at: number }
  | { kind: 'control_character_in_part'; name: string };

export function renderErrorMessage(e: RenderError): string {
  switch (e.kind) {
    case 'unfilled_placeholder':
      return `no part named "${e.name}" — the template cannot render without it`;
    case 'unbalanced_brace':
      return `unbalanced '{' at position ${e.at} — use '{{' for a literal brace`;
    case 'control_character_in_part':
      return `part "${e.name}" contains a newline or control character, which a URL cannot carry`;
  }
}

type Zone =
  'unstructured' | 'userinfo' | 'host' | 'path' | 'query_name' | 'query_value' | 'fragment';

function isUrlShaped(kind: CompositeKind): boolean {
  return kind === 'link' || kind === 'signed_link' || kind === 'connection';
}

/** Exactly RFC 3986's unreserved set — see the file header for why not `encodeURIComponent`. */
function percentEncode(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let out = '';
  for (const b of bytes) {
    const ch = String.fromCharCode(b);
    if (/[A-Za-z0-9\-._~]/.test(ch)) out += ch;
    else out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

// eslint-disable-next-line no-control-regex -- deliberately matching control characters, C6
const CONTROL_CHAR_RE = /[\x00-\x1f\x7f]/;
function hasControlChar(s: string): boolean {
  return CONTROL_CHAR_RE.test(s);
}

type Token = { type: 'literal'; text: string } | { type: 'placeholder'; name: string; at: number };

function isValidName(s: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(s);
}

/**
 * Splits a template into literal and placeholder tokens, validating brace
 * balance and placeholder-name syntax — the twin of `vault-core`'s `tokenize`.
 *
 * Returns a result rather than throwing: a `RenderError` is data the caller
 * displays, not an exceptional condition, and `@typescript-eslint/only-throw-error`
 * refuses a plain object thrown as an exception anyway.
 */
function tokenize(
  template: string,
): { ok: true; tokens: Token[] } | { ok: false; error: RenderError } {
  const tokens: Token[] = [];
  let literal = '';
  let i = 0;
  while (i < template.length) {
    const c = template[i];
    if (c === '{' && template[i + 1] === '{') {
      literal += '{';
      i += 2;
    } else if (c === '}' && template[i + 1] === '}') {
      literal += '}';
      i += 2;
    } else if (c === '{') {
      const start = i;
      const close = template.indexOf('}', i);
      if (close === -1) return { ok: false, error: { kind: 'unbalanced_brace', at: start } };
      const name = template.slice(i + 1, close);
      if (!name || !isValidName(name))
        return { ok: false, error: { kind: 'unbalanced_brace', at: start } };
      if (literal) {
        tokens.push({ type: 'literal', text: literal });
        literal = '';
      }
      tokens.push({ type: 'placeholder', name, at: start });
      i = close + 1;
    } else if (c === '}') {
      return { ok: false, error: { kind: 'unbalanced_brace', at: i } };
    } else {
      literal += c;
      i += 1;
    }
  }
  if (literal) tokens.push({ type: 'literal', text: literal });
  return { ok: true, tokens };
}

/**
 * Classifies the zone a placeholder at byte-ish offset `at` sits in, by
 * scanning the **template's** structural characters. The twin of
 * `vault-core`'s `classify_zone` — read that one alongside this one, since a
 * change to either without the other is exactly the drift this pair exists to
 * prevent.
 */
function classifyZone(template: string, at: number): Zone {
  const schemeIdx = template.indexOf('://');
  if (schemeIdx === -1) return 'unstructured';
  const schemeEnd = schemeIdx + 3;
  if (at < schemeEnd) return 'unstructured';

  const rest = template.slice(schemeEnd);
  const authorityRelEnd = (() => {
    const m = rest.search(/[/?#]/);
    return m === -1 ? rest.length : m;
  })();
  const authorityEnd = schemeEnd + authorityRelEnd;

  if (at < authorityEnd) {
    const authority = template.slice(schemeEnd, authorityEnd);
    const atSignRel = authority.indexOf('@');
    if (atSignRel !== -1) {
      const atSign = schemeEnd + atSignRel;
      return at < atSign ? 'userinfo' : 'host';
    }
    return 'host';
  }

  const afterAuthority = template.slice(authorityEnd);
  const qRel = afterAuthority.indexOf('?');
  const fRel = afterAuthority.indexOf('#');
  const queryStart = qRel === -1 ? null : authorityEnd + qRel;
  const fragmentStart = fRel === -1 ? null : authorityEnd + fRel;

  if (fragmentStart !== null && at >= fragmentStart) return 'fragment';
  if (queryStart !== null && at >= queryStart) {
    const queryEnd = fragmentStart ?? template.length;
    const query = template.slice(queryStart, queryEnd);
    const rel = at - queryStart;
    const segStart = (() => {
      const amp = query.slice(0, rel).lastIndexOf('&');
      return amp === -1 ? 0 : amp + 1;
    })();
    const segEnd = (() => {
      const amp = query.slice(rel).indexOf('&');
      return amp === -1 ? query.length : rel + amp;
    })();
    const segment = query.slice(segStart, segEnd);
    const eq = segment.indexOf('=');
    if (eq === -1) return 'query_name';
    return rel - segStart > eq ? 'query_value' : 'query_name';
  }
  return 'path';
}

/**
 * Renders `template` against `parts`, refusing on any unfilled placeholder,
 * unbalanced brace, or (for a URL-shaped kind) a control character in a part.
 *
 * `custom` and any kind this function does not recognise render every
 * placeholder raw — assuming URL structure over an unrecognised shape
 * corrupts a value as easily as it protects one.
 */
export function renderComposite(
  template: string,
  parts: CompositePart[],
  kind: CompositeKind,
): { ok: true; result: RenderedComposite } | { ok: false; error: RenderError } {
  const byName = new Map(parts.map((p) => [p.key, p.value]));
  const tokenized = tokenize(template);
  if (!tokenized.ok) return { ok: false, error: tokenized.error };

  const encode = isUrlShaped(kind);
  const used: string[] = [];
  let text = '';

  for (const tok of tokenized.tokens) {
    if (tok.type === 'literal') {
      text += tok.text;
      continue;
    }
    const value = byName.get(tok.name);
    if (value === undefined) {
      return { ok: false, error: { kind: 'unfilled_placeholder', name: tok.name } };
    }
    if (encode && hasControlChar(value)) {
      return { ok: false, error: { kind: 'control_character_in_part', name: tok.name } };
    }
    if (!used.includes(tok.name)) used.push(tok.name);
    if (encode) {
      const zone = classifyZone(template, tok.at);
      text += zone === 'unstructured' ? value : percentEncode(value);
    } else {
      text += value;
    }
  }

  const unused = parts.map((p) => p.key).filter((k) => !used.includes(k));
  return { ok: true, result: { text, used, unused } };
}

/**
 * The placeholder names a template references, without needing any parts —
 * for "Make part" suggestions and the health scan's orphan-part check.
 */
export function compositePlaceholders(template: string): string[] {
  const tokenized = tokenize(template);
  if (!tokenized.ok) return [];
  const names: string[] = [];
  for (const tok of tokenized.tokens) {
    if (tok.type === 'placeholder' && !names.includes(tok.name)) names.push(tok.name);
  }
  return names;
}
