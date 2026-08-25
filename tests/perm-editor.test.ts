/**
 * Permission expression editor.
 *
 * The preview is advisory — the server re-evaluates every rule — so what
 * matters here is that a term the builder inserts parses back to the value the
 * user picked, and that the preview never claims a broken rule is fine.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st } from '../src/ts/state';
import { permEditorHtml, wirePermEditor } from '../src/ts/perm-editor';
import { parse } from '../src/ts/permex';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showToast: () => {} };
});

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const readBox = () => $('t-expr-read') as HTMLTextAreaElement;

function mount(
  exprs = { read: '', write: '' },
  onSave: (e: { read: string; write: string }) => Promise<void> = async () => {},
) {
  document.body.innerHTML = `<div id="host"></div>`;
  $('host').innerHTML = permEditorHtml('t', exprs);
  wirePermEditor('t', onSave);
}

/** Pick a field + value in the builder and press Insert. */
function insert(field: string, value: string) {
  ($('t-b-field') as HTMLSelectElement).value = field;
  $('t-b-field').dispatchEvent(new Event('change'));
  const valueSel = $('t-b-value') as HTMLSelectElement;
  const opt = [...valueSel.options].find((o) => o.value === value);
  expect(opt, `builder offered no value "${value}"`).toBeDefined();
  valueSel.value = value;
  $('t-b-insert').click();
}

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
});

describe('inserted terms parse back to the chosen value', () => {
  it('inserts a plain tag term', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ tags: ['prod'] })] });
    mount();
    insert('tag', 'prod');
    expect(readBox().value).toBe('tag:prod');
    expect((parse(readBox().value) as any).glob).toBe('prod');
  });

  it('quotes a value containing spaces', () => {
    st.vault = makeVault({ user_categories: ['my infra'], api_keys: [] });
    mount();
    insert('category', 'my infra');
    expect((parse(readBox().value) as any).glob).toBe('my infra');
  });

  it('round-trips a value containing a backslash', () => {
    // Inside a quoted value the lexer reads `\x` as a literal `x`, and the
    // builder escaped only the quote character — so `a\b c` came back as `ab c`
    // and the rule silently matched something the user never chose.
    st.vault = makeVault({ user_categories: ['a\\b c'], api_keys: [] });
    mount();
    insert('category', 'a\\b c');
    expect((parse(readBox().value) as any).glob).toBe('a\\b c');
  });

  it('round-trips a value containing a double quote', () => {
    st.vault = makeVault({ user_categories: ['say "hi"'], api_keys: [] });
    mount();
    insert('category', 'say "hi"');
    expect((parse(readBox().value) as any).glob).toBe('say "hi"');
  });

  it('round-trips a value containing both a backslash and a quote', () => {
    st.vault = makeVault({ user_categories: ['a\\"b c'], api_keys: [] });
    mount();
    insert('category', 'a\\"b c');
    expect((parse(readBox().value) as any).glob).toBe('a\\"b c');
  });

  it('round-trips a nested project name', () => {
    st.vault = makeVault({
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'p', name: 'Acme/Web' }),
      ],
      api_keys: [],
    });
    mount();
    insert('project', 'Acme/Web');
    expect((parse(readBox().value) as any).glob).toBe('Acme/Web');
  });

  it('joins a second term with the chosen operator', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ tags: ['prod', 'db'] })] });
    mount();
    insert('tag', 'prod');
    ($('t-b-join') as HTMLSelectElement).value = 'AND NOT';
    insert('tag', 'db');
    expect(readBox().value).toBe('tag:prod AND NOT tag:db');
    expect(() => parse(readBox().value)).not.toThrow();
  });

  it('inserts into the write box when targeted', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ tags: ['prod'] })] });
    mount();
    ($('t-b-target') as HTMLSelectElement).value = 'write';
    insert('tag', 'prod');
    expect(($('t-expr-write') as HTMLTextAreaElement).value).toBe('tag:prod');
    expect(readBox().value).toBe('');
  });
});

describe('live validation', () => {
  beforeEach(() => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({ provider: 'A', tags: ['prod'] }),
        makeEntry({ provider: 'B', tags: ['dev'] }),
        makeEntry({ provider: 'C' }),
      ],
    });
    mount();
  });

  const type = (v: string) => {
    readBox().value = v;
    readBox().dispatchEvent(new Event('input'));
  };

  it('reports how many entries a rule matches', () => {
    type('tag:prod');
    expect($('t-status-read').textContent).toBe('Valid — matches 1 of 3 entries.');
  });

  it('flags a malformed rule with the parser message', () => {
    type('tag:a AND');
    expect($('t-status-read').classList.contains('err')).toBe(true);
    expect(readBox().classList.contains('invalid')).toBe(true);
  });

  it('says plainly that an empty rule grants nothing', () => {
    type('');
    expect($('t-status-read').textContent).toMatch(/grants nothing/i);
  });

  it('recovers once the rule is corrected', () => {
    type('bogus:x');
    expect($('t-status-read').classList.contains('err')).toBe(true);
    type('tag:prod');
    expect($('t-status-read').classList.contains('err')).toBe(false);
    expect(readBox().classList.contains('invalid')).toBe(false);
  });

  it('previews the effective read set as read OR write', () => {
    readBox().value = 'tag:prod';
    ($('t-expr-write') as HTMLTextAreaElement).value = 'tag:dev';
    readBox().dispatchEvent(new Event('input'));
    expect($('t-preview').textContent).toBe('Effective read (read OR write): 2 of 3');
  });
});

describe('saving', () => {
  beforeEach(() => {
    st.vault = makeVault({ api_keys: [makeEntry({ tags: ['prod'] })] });
  });

  it('hands both trimmed expressions to the callback', async () => {
    const saved: any[] = [];
    mount({ read: '', write: '' }, async (e: any) => {
      saved.push(e);
    });
    readBox().value = '  tag:prod  ';
    readBox().dispatchEvent(new Event('input'));
    $('t-expr-save').click();
    await new Promise((r) => setTimeout(r, 10));
    expect(saved).toEqual([{ read: 'tag:prod', write: '' }]);
  });

  it('refuses to save a malformed rule', async () => {
    const saved: any[] = [];
    mount({ read: '', write: '' }, async (e: any) => {
      saved.push(e);
    });
    readBox().value = 'tag:a AND';
    readBox().dispatchEvent(new Event('input'));
    $('t-expr-save').click();
    await new Promise((r) => setTimeout(r, 10));
    expect(saved).toEqual([]);
  });
});

describe('builder suggestions', () => {
  it('escapes a value containing markup', () => {
    st.vault = makeVault({ user_categories: ['<img src=x onerror=alert(1)>'], api_keys: [] });
    mount();
    ($('t-b-field') as HTMLSelectElement).value = 'category';
    $('t-b-field').dispatchEvent(new Event('change'));
    expect($('t-b-value').querySelector('img')).toBeNull();
  });

  it('always offers the * wildcard first', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ tags: ['prod'] })] });
    mount();
    ($('t-b-field') as HTMLSelectElement).value = 'tag';
    $('t-b-field').dispatchEvent(new Event('change'));
    expect(($('t-b-value') as HTMLSelectElement).options[0].value).toBe('*');
  });
});
