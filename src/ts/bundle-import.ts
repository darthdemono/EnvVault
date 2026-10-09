/**
 * Import a Python config module as bundle-local variables (Phase 24.1).
 *
 * Reads the **assignment subset only**: string and f-string literals, ints
 * (decimal, hex, binary, octal), floats, `True`/`False`/`None`. Nothing is
 * executed. Any other right-hand side is imported as its source text with a
 * warning naming the line, never dropped.
 *
 * Rules that exist because the alternative is a silent wrong value:
 *
 * - A name assigned twice keeps the first under its own name and imports the
 *   second as `name_2`; every f-string written *after* the second assignment is
 *   rewritten to `{name_2}`, because that is the value Python bound at that
 *   point. All three facts are reported. "Last one wins" would hand the line
 *   between the two assignments the wrong key.
 * - A snowflake-sized id stays a **string** end to end (`large_id`); a JS number
 *   would round it.
 * - An f-string becomes a `template` over `{name}` holes. An f-string that holds
 *   anything but plain names (`{x!r}`, `{x:>5}`, `{a + b}`) cannot be a
 *   template, so it is kept as a string and reported.
 *
 * Twin of `vault_core::bundle_import`, pinned by
 * `tests/fixtures/parity/bundle-import.json`.
 */
import type { ValueKind } from './types';

export interface ImportedVar {
  key: string;
  value: string;
  kind: ValueKind;
  /**
   * Safe to print: a prefix, a colour, a title, a link with no credential in it.
   * Set only when the importer is sure; everything else stays masked (redaction is
   * fail-closed). Absent, not `false`, when not public.
   */
  public?: true;
}

export interface BundleImport {
  vars: ImportedVar[];
  warnings: string[];
}

const IDENT = /^[A-Za-z_]\w*$/;

function readQuoted(source: string): { prefix: string; body: string; rest: string } | null {
  const m = /^([fFuUrRbB]{0,2})(['"])/.exec(source);
  if (!m) return null;
  const quote = m[2];
  let end = m[0].length;
  for (; end < source.length; end++) {
    if (source[end] === '\\') end++;
    else if (source[end] === quote) break;
  }
  if (source[end] !== quote) return null;
  return {
    prefix: m[1].toLowerCase(),
    body: source.slice(m[0].length, end),
    rest: source.slice(end + 1),
  };
}

function unescapePy(body: string, raw: boolean): string | null {
  if (raw) return body;
  let ok = true;
  const out = body.replace(/\\(.)/g, (_m, c: string) => {
    const known: Record<string, string> = {
      n: '\n',
      r: '\r',
      t: '\t',
      '\\': '\\',
      "'": "'",
      '"': '"',
    };
    if (c in known) return known[c];
    ok = false;
    return c;
  });
  return ok ? out : null;
}

function kindForString(name: string, body: string): ValueKind {
  if (/^\d{15,}$/.test(body) || (/(^|_)ids?$/i.test(name) && /^\d{10,}$/.test(body)))
    return 'large_id';
  if (/^\[[^\]]*\]\(https?:\/\/[^)\s]+\)$/.test(body)) return 'markdown_link';
  if (/^https?:\/\/\S+$/.test(body)) return 'url';
  return 'string';
}

/** A name that says what it holds. Beats every other signal. */
function secretishName(name: string): boolean {
  return /key|token|secret|password|passwd|pwd|auth|credential|salt|signature|private|webhook|cert/i.test(
    name,
  );
}

/** Query-parameter names and path pieces that mean a credential rides in the URL. */
function urlIsPublic(url: string): boolean {
  const u = url.trim().replace(/^</, '').replace(/>$/, '');
  const m = /^https?:\/\/(.*)$/.exec(u);
  if (!m) return false;
  const rest = m[1];
  const slash = rest.indexOf('/');
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  const tail = slash < 0 ? '' : rest.slice(slash + 1);
  if (authority.includes('@')) return false; // user:password@host
  const q = tail.indexOf('?');
  const path = (q < 0 ? tail : tail.slice(0, q)).toLowerCase();
  const query = q < 0 ? '' : tail.slice(q + 1);
  if (path.includes('hook')) return false; // a webhook URL is the credential
  const tokenish = (seg: string) =>
    seg.length >= 24 && /^[A-Za-z0-9_-]+$/.test(seg) && /\d/.test(seg) && /[A-Za-z]/.test(seg);
  if (path.split('/').some(tokenish)) return false;
  return query
    .split(/[&;]/)
    .map((kv) => kv.split('=')[0].toLowerCase())
    .every((k) => !/key|token|secret|pass|pwd|sig|auth|code|session/.test(k));
}

/** Prose: words with spaces and no assignment or long run of mixed characters. */
function isProse(v: string): boolean {
  return (
    v.includes(' ') &&
    !v.includes('=') &&
    !v.split(/\s+/).some((w) => w.length >= 16 && /\d/.test(w) && /[A-Za-z]/.test(w))
  );
}

/**
 * Whether the importer is sure a value is safe to print. `publicKeys` are the keys
 * already judged public, for templates: a template is public only if every input
 * is, so a composite can never launder a secret into a printable value. Twin of
 * `is_public` in `vault-core/src/bundle_import.rs`.
 */
function isPublic(name: string, kind: ValueKind, value: string, publicKeys: Set<string>): boolean {
  if (secretishName(name)) return false;
  switch (kind) {
    case 'hex_int':
    case 'bool':
    case 'float':
      return true;
    case 'int':
      return value.replace(/^[-+]/, '').length <= 6;
    case 'url':
      return urlIsPublic(value);
    case 'markdown_link': {
      const i = value.indexOf('](');
      return i >= 0 && urlIsPublic(value.slice(i + 2).replace(/\)+$/, ''));
    }
    case 'template': {
      let rest = value.split('{{').join('').split('}}').join('');
      const refs: string[] = [];
      for (;;) {
        const i = rest.indexOf('{');
        if (i < 0) break;
        const j = rest.indexOf('}', i);
        if (j < 0) return false;
        refs.push(rest.slice(i + 1, j));
        rest = rest.slice(0, i) + rest.slice(j + 1);
      }
      return (
        refs.every((r) => publicKeys.has(r)) &&
        (!rest.includes('://') || urlIsPublic(rest.split(' ').join('')) || isProse(rest))
      );
    }
    case 'string': {
      const t = value.trim();
      if ([...t].length <= 2) return true;
      if (t.startsWith('<') && t.endsWith('>') && t.includes('://')) return urlIsPublic(t);
      return isProse(t);
    }
    default:
      return false;
  }
}

export function importPythonConfig(text: string): BundleImport {
  const vars: ImportedVar[] = [];
  const warnings: string[] = [];
  // Python name -> the key its *current* binding was imported under.
  const bound = new Map<string, string>();
  const taken = new Set<string>();
  const rewrites = new Map<string, { to: string; n: number }>();
  const publicKeys = new Set<string>();

  const lines = text.split(/\r?\n/);
  lines.forEach((raw, index) => {
    const lineNo = index + 1;
    const line = raw.trim();
    const m = /^([A-Za-z_]\w*)\s*=(?!=)\s*(.*)$/.exec(line);
    if (!m) return;
    const [, name, sourceFull] = m;
    const source = sourceFull.replace(/\s+#[^'"]*$/, '').trim();

    let value: string;
    let kind: ValueKind;
    let extraWarning = '';

    const q = readQuoted(source);
    if (q && /^\s*(?:#.*)?$/.test(q.rest)) {
      const isF = q.prefix.includes('f');
      const body = unescapePy(q.body, q.prefix.includes('r'));
      if (body === null) {
        warnings.push(`line ${lineNo}: unsupported escape in ${name}; imported as source text`);
        value = source;
        kind = 'string';
      } else if (isF) {
        const converted = convertFString(body, bound);
        if (converted === null) {
          warnings.push(
            `line ${lineNo}: ${name} is an f-string with an expression a template cannot hold; imported as a string`,
          );
          value = body;
          kind = 'string';
        } else {
          value = converted.text;
          // An f-string with nothing to fill in is just a string; only a real hole
          // (or a literal brace) makes it a template.
          kind = /[{}]/.test(value) ? 'template' : kindForString(name, value);
          for (const [from, to] of converted.rewrote) {
            const hit = rewrites.get(from) ?? { to, n: 0 };
            rewrites.set(from, { to, n: hit.n + 1 });
          }
        }
      } else {
        value = body;
        kind = kindForString(name, body);
      }
    } else if (/^[-+]?(?:0[xX][\da-fA-F]+|0[oO][0-7]+|0[bB][01]+)$/.test(source)) {
      value = source;
      kind = 'hex_int';
    } else if (/^[-+]?\d+$/.test(source)) {
      value = source;
      kind = 'int';
    } else if (/^[-+]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?$/.test(source)) {
      value = source;
      kind = 'float';
    } else if (source === 'True' || source === 'False') {
      value = source === 'True' ? 'true' : 'false';
      kind = 'bool';
    } else if (source === 'None') {
      value = '';
      kind = 'string';
      extraWarning = `${name} is None; imported as an empty string`;
    } else {
      value = source;
      kind = 'string';
      extraWarning = `${name} is not a supported literal; imported as source text`;
    }
    if (extraWarning) warnings.push(`line ${lineNo}: ${extraWarning}`);

    let key = name;
    if (taken.has(name)) {
      let n = 2;
      while (taken.has(`${name}_${n}`)) n++;
      key = `${name}_${n}`;
      warnings.push(
        `line ${lineNo}: ${name} is assigned more than once; the first stays ${name}, this one is imported as ${key}, and later references use ${key}`,
      );
    }
    taken.add(key);
    bound.set(name, key);
    const isPub = isPublic(name, kind, value, publicKeys);
    if (isPub) publicKeys.add(key);
    vars.push(isPub ? { key, value, kind, public: true } : { key, value, kind });
  });

  for (const [from, { to, n }] of rewrites)
    warnings.push(
      `${n} later reference${n === 1 ? '' : 's'} to ${from} now ${n === 1 ? 'uses' : 'use'} ${to}`,
    );
  return { vars, warnings };
}

/** `{name}` holes only. Returns null when anything else is inside braces. */
function convertFString(
  body: string,
  bound: Map<string, string>,
): { text: string; rewrote: [string, string][] } | null {
  let out = '';
  const rewrote: [string, string][] = [];
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '{' && body[i + 1] === '{') {
      out += '{{';
      i++;
    } else if (c === '}' && body[i + 1] === '}') {
      out += '}}';
      i++;
    } else if (c === '{') {
      const end = body.indexOf('}', i);
      if (end < 0) return null;
      const ref = body.slice(i + 1, end).trim();
      if (!IDENT.test(ref)) return null;
      const key = bound.get(ref);
      if (key === undefined) return null;
      if (key !== ref) rewrote.push([ref, key]);
      out += `{${key}}`;
      i = end;
    } else if (c === '}') {
      return null;
    } else {
      out += c;
    }
  }
  return { text: out, rewrote };
}
