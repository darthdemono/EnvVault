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

export function importPythonConfig(text: string): BundleImport {
  const vars: ImportedVar[] = [];
  const warnings: string[] = [];
  // Python name -> the key its *current* binding was imported under.
  const bound = new Map<string, string>();
  const taken = new Set<string>();
  const rewrites = new Map<string, { to: string; n: number }>();

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
          kind = 'template';
          for (const [from, to] of converted.rewrote) {
            const hit = rewrites.get(from) ?? { to, n: 0 };
            rewrites.set(from, { to, n: hit.n + 1 });
          }
        }
      } else {
        value = body;
        if (/^\d{15,}$/.test(body) || (/(^|_)ids?$/i.test(name) && /^\d{10,}$/.test(body)))
          kind = 'large_id';
        else if (/^\[[^\]]*\]\(https?:\/\/[^)\s]+\)$/.test(body)) kind = 'markdown_link';
        else if (/^https?:\/\/\S+$/.test(body)) kind = 'url';
        else kind = 'string';
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
    vars.push({ key, value, kind });
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
