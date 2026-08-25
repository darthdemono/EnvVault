/**
 * The client-side permission language is advisory — `vault-core/src/permex.rs`
 * is what actually gates access. These tests pin the two to the same semantics,
 * because an editor that says "matches 3 entries" while the server returns 0 is
 * worse than no preview at all.
 */
import { describe, it, expect } from 'vitest';
import { globMatches, parse, evaluate, evaluateSrc, validate } from '../src/ts/permex';
import { makeEntry, makeProject } from './helpers';

const PROJECTS = [
  makeProject({ id: 'Universal', name: 'Universal' }),
  makeProject({ id: 'p-acme', name: 'Acme' }),
  makeProject({ id: 'p-web', name: 'Acme/Web' }),
];

describe('globMatches', () => {
  it.each([
    ['*', 'anything', true],
    ['abc', 'abc', true],
    ['abc', 'abd', false],
    ['a*', 'abc', true],
    ['*c', 'abc', true],
    ['a*c', 'abbbc', true],
    ['a*c', 'abbb', false],
    ['a?c', 'abc', true],
    ['a?c', 'ac', false],
    ['*a*b*', 'xxaxxbxx', true],
    ['', '', true],
    ['', 'a', false],
    ['*', '', true],
  ])('%s vs %s -> %s', (pattern, value, expected) => {
    expect(globMatches(pattern, value)).toBe(expected);
  });
});

describe('parse', () => {
  it('binds AND tighter than OR', () => {
    // a OR (b AND c), not (a OR b) AND c
    const expr = parse('tag:a OR tag:b AND tag:c');
    expect(expr.kind).toBe('or');
    expect((expr as any).b.kind).toBe('and');
  });

  it('binds NOT tighter than AND', () => {
    const expr = parse('NOT tag:a AND tag:b');
    expect(expr.kind).toBe('and');
    expect((expr as any).a.kind).toBe('not');
  });

  it('honours explicit parentheses over default precedence', () => {
    const expr = parse('(tag:a OR tag:b) AND tag:c');
    expect(expr.kind).toBe('and');
    expect((expr as any).a.kind).toBe('or');
  });

  it('accepts && || ! as symbol aliases', () => {
    expect(parse('tag:a && tag:b').kind).toBe('and');
    expect(parse('tag:a || tag:b').kind).toBe('or');
    expect(parse('!tag:a').kind).toBe('not');
  });

  it('resolves field aliases to canonical fields', () => {
    expect((parse('proj:x') as any).field).toBe('project');
    expect((parse('cat:x') as any).field).toBe('category');
    expect((parse('environment:x') as any).field).toBe('env');
    expect((parse('secretType:x') as any).field).toBe('type');
  });

  it('keeps spaces inside a quoted value', () => {
    expect((parse('cat:"my infra"') as any).glob).toBe('my infra');
  });

  it('unescapes a backslash-escaped quote', () => {
    expect((parse('cat:"a\\"b"') as any).glob).toBe('a"b');
  });

  it.each([
    ['', 'empty expression'],
    ['tag:a tag:b', 'trailing input'],
    ['bogus:x', 'unknown field'],
    ['tag:', 'has no value'],
    ['cat:"unterminated', 'unterminated quoted value'],
    ['hello', 'expected AND, OR, NOT'],
  ])('rejects %o', (src, fragment) => {
    expect(() => parse(src)).toThrow(new RegExp(fragment, 'i'));
  });
});

describe('evaluate', () => {
  it('treats vault: as unconditionally true', () => {
    expect(evaluateSrc('vault:whatever', makeEntry(), PROJECTS)).toBe(true);
  });

  it('treats field:* as no constraint on that field', () => {
    expect(evaluateSrc('tag:*', makeEntry({ tags: [] }), PROJECTS)).toBe(true);
  });

  it('never satisfies a project predicate from the Universal catch-all', () => {
    // Every entry carries Universal; matching it would silently promote any
    // project-scoped grant into a vault-wide one.
    const entry = makeEntry({ projectIds: ['Universal'] });
    expect(evaluateSrc('project:Universal', entry, PROJECTS)).toBe(false);
    expect(evaluateSrc('project:*', entry, PROJECTS)).toBe(true);
  });

  it('matches a project by id or by name', () => {
    const entry = makeEntry({ projectIds: ['Universal', 'p-acme'] });
    expect(evaluateSrc('project:p-acme', entry, PROJECTS)).toBe(true);
    expect(evaluateSrc('project:Acme', entry, PROJECTS)).toBe(true);
    expect(evaluateSrc('project:Other', entry, PROJECTS)).toBe(false);
  });

  it('glob-matches nested project names', () => {
    const entry = makeEntry({ projectIds: ['Universal', 'p-web'] });
    expect(evaluateSrc('project:Acme/*', entry, PROJECTS)).toBe(true);
  });

  it('matches category, tag and env predicates', () => {
    const entry = makeEntry({
      categories: ['infra/db'],
      tags: ['prod'],
      environment: 'production',
    });
    expect(evaluateSrc('cat:infra/*', entry, PROJECTS)).toBe(true);
    expect(evaluateSrc('tag:prod', entry, PROJECTS)).toBe(true);
    expect(evaluateSrc('env:production', entry, PROJECTS)).toBe(true);
    expect(evaluateSrc('env:staging', entry, PROJECTS)).toBe(false);
  });

  it('defaults a missing secretType to api_key', () => {
    expect(evaluateSrc('type:api_key', makeEntry(), PROJECTS)).toBe(true);
  });

  it('returns false for an entry with no environment set', () => {
    expect(evaluateSrc('env:production', makeEntry({ environment: null }), PROJECTS)).toBe(false);
  });

  it('combines predicates with AND / OR / NOT', () => {
    const entry = makeEntry({ tags: ['prod'], environment: 'production' });
    expect(evaluateSrc('tag:prod AND env:production', entry, PROJECTS)).toBe(true);
    expect(evaluateSrc('tag:prod AND env:staging', entry, PROJECTS)).toBe(false);
    expect(evaluateSrc('tag:nope OR env:production', entry, PROJECTS)).toBe(true);
    expect(evaluateSrc('NOT tag:prod', entry, PROJECTS)).toBe(false);
  });

  it('accepts a pre-parsed expression', () => {
    expect(evaluate(parse('tag:prod'), makeEntry({ tags: ['prod'] }), PROJECTS)).toBe(true);
  });
});

describe('evaluateSrc', () => {
  it('denies on malformed input rather than throwing', () => {
    // The server treats an unparseable rule as deny; the preview must agree,
    // otherwise the editor shows access that will never be granted.
    expect(evaluateSrc('tag:a AND', makeEntry({ tags: ['a'] }), PROJECTS)).toBe(false);
    expect(evaluateSrc('((', makeEntry(), PROJECTS)).toBe(false);
  });
});

describe('validate', () => {
  it('accepts a blank expression as "no rule"', () => {
    expect(validate('')).toBeNull();
    expect(validate('   ')).toBeNull();
  });

  it('returns null for valid input', () => {
    expect(validate('tag:a AND (env:prod OR cat:x)')).toBeNull();
  });

  it('returns a readable reason for invalid input', () => {
    expect(validate('bogus:x')).toMatch(/unknown field/i);
  });
});
