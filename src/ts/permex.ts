/**
 * @file Client-side mirror of the permission expression language.
 *
 * **Advisory only.** This exists so the permission editor can validate syntax as
 * you type and show "matches N of M entries" without a round trip. Enforcement
 * lives in `vault-core/src/permex.rs` and is the only thing that decides real
 * access — a browser can always lie about what it evaluated.
 *
 * Semantics are kept deliberately identical to the Rust implementation:
 * precedence `NOT` > `AND` > `OR`, `field:*` is unconditional, and a specific
 * project predicate is never satisfied by the `Universal` catch-all.
 */

import type { VaultEntry, Project } from './types';

const UNIVERSAL = 'Universal';

export type Field = 'vault' | 'project' | 'category' | 'tag' | 'env' | 'type';

const FIELD_ALIASES: Record<string, Field> = {
  vault: 'vault',
  project: 'project', proj: 'project',
  category: 'category', cat: 'category',
  tag: 'tag',
  env: 'env', environment: 'env',
  type: 'type', secrettype: 'type',
};

export const FIELDS: Field[] = ['vault', 'project', 'category', 'tag', 'env', 'type'];

export type Expr =
  | { kind: 'pred'; field: Field; glob: string }
  | { kind: 'and'; a: Expr; b: Expr }
  | { kind: 'or';  a: Expr; b: Expr }
  | { kind: 'not'; a: Expr };

type Tok =
  | { t: 'pred'; field: Field; glob: string }
  | { t: 'and' } | { t: 'or' } | { t: 'not' }
  | { t: '(' } | { t: ')' };

/** Same wildcard semantics as `glob_matches` in vault-core. */
export function globMatches(pattern: string, value: string): boolean {
  let pi = 0, vi = 0, starPi = -1, starVi = 0;
  while (vi < value.length) {
    if (pi < pattern.length && pattern[pi] === '*') { starPi = pi; starVi = vi; pi++; }
    else if (pi < pattern.length && (pattern[pi] === value[vi] || pattern[pi] === '?')) { pi++; vi++; }
    else if (starPi !== -1) { pi = starPi + 1; starVi++; vi = starVi; }
    else return false;
  }
  while (pi < pattern.length && pattern[pi] === '*') pi++;
  return pi === pattern.length;
}

function lex(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '(') { out.push({ t: '(' }); i++; continue; }
    if (c === ')') { out.push({ t: ')' }); i++; continue; }
    if (c === '!') { out.push({ t: 'not' }); i++; continue; }
    if (c === '&') { i += src[i + 1] === '&' ? 2 : 1; out.push({ t: 'and' }); continue; }
    if (c === '|') { i += src[i + 1] === '|' ? 2 : 1; out.push({ t: 'or' });  continue; }

    const start = i;
    while (i < src.length && !/[\s():]/.test(src[i])) i++;
    const word = src.slice(start, i);
    if (!word) throw new Error(`unexpected character '${c}'`);

    if (src[i] !== ':') {
      const up = word.toUpperCase();
      if (up === 'AND') out.push({ t: 'and' });
      else if (up === 'OR') out.push({ t: 'or' });
      else if (up === 'NOT') out.push({ t: 'not' });
      else throw new Error(`expected AND, OR, NOT or a \`field:value\` term, found '${word}'`);
      continue;
    }

    i++; // ':'
    const field = FIELD_ALIASES[word.toLowerCase()];
    if (!field) throw new Error(`unknown field '${word}' — use one of ${FIELDS.join(', ')}`);

    let glob: string;
    if (src[i] === '"') {
      i++;
      glob = '';
      for (;;) {
        if (i >= src.length) throw new Error('unterminated quoted value');
        if (src[i] === '\\' && i + 1 < src.length) { glob += src[i + 1]; i += 2; }
        else if (src[i] === '"') { i++; break; }
        else glob += src[i++];
      }
    } else {
      const vs = i;
      while (i < src.length && !/[\s()]/.test(src[i])) i++;
      glob = src.slice(vs, i);
    }
    if (!glob) throw new Error(`field '${word}' has no value — write ${word}:* to match everything`);
    out.push({ t: 'pred', field, glob });
  }
  return out;
}

/** Parses an expression. Throws with a readable message on malformed input. */
export function parse(src: string): Expr {
  const toks = lex(src);
  if (!toks.length) throw new Error('empty expression');
  let pos = 0;
  const peek = () => toks[pos];

  function parseOr(): Expr {
    let lhs = parseAnd();
    while (peek()?.t === 'or') { pos++; lhs = { kind: 'or', a: lhs, b: parseAnd() }; }
    return lhs;
  }
  function parseAnd(): Expr {
    let lhs = parseNot();
    while (peek()?.t === 'and') { pos++; lhs = { kind: 'and', a: lhs, b: parseNot() }; }
    return lhs;
  }
  function parseNot(): Expr {
    if (peek()?.t === 'not') { pos++; return { kind: 'not', a: parseNot() }; }
    return parsePrimary();
  }
  function parsePrimary(): Expr {
    const tok = toks[pos++];
    if (!tok) throw new Error('unexpected end of expression');
    if (tok.t === 'pred') return { kind: 'pred', field: tok.field, glob: tok.glob };
    if (tok.t === '(') {
      const inner = parseOr();
      if (toks[pos++]?.t !== ')') throw new Error("missing closing ')'");
      return inner;
    }
    if (tok.t === ')') throw new Error("unexpected ')'");
    throw new Error('expression begins with an operator');
  }

  const expr = parseOr();
  if (pos !== toks.length) throw new Error('trailing input after the end of the expression');
  return expr;
}

/** Evaluate against a vault entry. `projects` resolves project ids to names. */
export function evaluate(expr: Expr, entry: VaultEntry, projects: Project[]): boolean {
  switch (expr.kind) {
    case 'and': return evaluate(expr.a, entry, projects) && evaluate(expr.b, entry, projects);
    case 'or':  return evaluate(expr.a, entry, projects) || evaluate(expr.b, entry, projects);
    case 'not': return !evaluate(expr.a, entry, projects);
    case 'pred': {
      const { field, glob } = expr;
      const wildcard = glob === '*';
      if (field === 'vault') return true;
      if (wildcard) return true;   // "no constraint on this field"
      switch (field) {
        case 'category': return (entry.categories ?? []).some(c => globMatches(glob, c));
        case 'tag':      return (entry.tags ?? []).some(t => globMatches(glob, t));
        case 'env':      return !!entry.environment && globMatches(glob, entry.environment);
        case 'type':     return globMatches(glob, entry.secretType ?? 'api_key');
        case 'project':
          return (entry.projectIds ?? []).some(pid => {
            // Every entry carries Universal; matching it would silently promote
            // any project grant to a vault-wide one.
            if (pid === UNIVERSAL) return false;
            const name = projects.find(p => p.id === pid)?.name ?? pid;
            return globMatches(glob, pid) || globMatches(glob, name);
          });
      }
    }
  }
}

/** Parse + evaluate, treating malformed input as deny (as the server does). */
export function evaluateSrc(src: string, entry: VaultEntry, projects: Project[]): boolean {
  try { return evaluate(parse(src), entry, projects); } catch { return false; }
}

/** `null` when valid, otherwise the reason it is not. */
export function validate(src: string): string | null {
  if (!src.trim()) return null;   // blank clears the rule; not an error
  try { parse(src); return null; } catch (e: any) { return e?.message ?? String(e); }
}
