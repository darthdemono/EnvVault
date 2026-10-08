/**
 * Escape by construction (Phase 28, review-01 §2.3).
 *
 * The `html` tag escapes every interpolation unless it is already `SafeHtml`.
 * These tests pin the tag itself; the two source-scanning tests at the bottom
 * pin the property that makes it worth having: nothing else writes markup, and
 * the places that vouch for a string with `raw()` are a short, named list.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { html, raw, setHtml, SafeHtml } from '../src/ts/html';

const HOSTILE = '<img src=x onerror=alert(1)>" onmouseover="x" \'a\' & b';

describe('html tag', () => {
  it('escapes strings in text and attribute position', () => {
    const out = String(html`<p title="${HOSTILE}">${HOSTILE}</p>`);
    expect(out).not.toContain('<img');
    expect(out).not.toContain('" onmouseover=');
    expect(out).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(out).toContain('&quot;');
    expect(out).toContain('&#39;a&#39;');
    expect(out).toContain('&amp; b');
  });

  it('does not escape the template literal text itself', () => {
    expect(String(html`<b>x</b>`)).toBe('<b>x</b>');
  });

  it('passes nested html through once, not twice', () => {
    const inner = html`<i>${'a&b'}</i>`;
    expect(String(html`<p>${inner}</p>`)).toBe('<p><i>a&amp;b</i></p>');
  });

  it('flattens arrays, escaping string members and keeping SafeHtml members', () => {
    const out = String(html`<ul>${[html`<li>1</li>`, '<x>', 2]}</ul>`);
    expect(out).toBe('<ul><li>1</li>&lt;x&gt;2</ul>');
  });

  it('renders null, undefined and false as nothing, but 0 and true as themselves', () => {
    expect(String(html`[${null}|${undefined}|${false}|${0}|${true}]`)).toBe('[|||0|true]');
  });

  it('a plain string that looks like markup is never trusted', () => {
    const looksSafe = String(html`<b>x</b>`); // a string, not a SafeHtml
    expect(String(html`<p>${looksSafe}</p>`)).toBe('<p>&lt;b&gt;x&lt;/b&gt;</p>');
  });

  it('raw() is the only way to vouch for a string', () => {
    expect(String(html`<p>${raw('<b>x</b>')}</p>`)).toBe('<p><b>x</b></p>');
    expect(raw('x')).toBeInstanceOf(SafeHtml);
  });
});

describe('setHtml', () => {
  it('writes SafeHtml and clears with an empty string', () => {
    const el = document.createElement('div');
    setHtml(el, html`<span>${HOSTILE}</span>`);
    expect(el.querySelector('img')).toBeNull();
    expect(el.textContent).toBe(HOSTILE);
    setHtml(el, '');
    expect(el.childNodes.length).toBe(0);
  });
});

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith('.ts')) out.push(p);
  }
  return out;
}
const SRC = walk('src/ts').filter((p) => !p.endsWith('/html.ts'));

describe('source guards', () => {
  it('nothing assigns innerHTML/outerHTML or calls insertAdjacentHTML except html.ts', () => {
    // tools-markup.ts injects one build-time constant and carries an
    // eslint-disable naming why; it is the only exemption.
    const offenders = SRC.filter((p) => {
      const s = readFileSync(p, 'utf8');
      return (
        /\.(innerHTML|outerHTML)\s*\+?=(?!=)/.test(s) ||
        (s.includes('insertAdjacentHTML(') && !p.endsWith('tools-markup.ts'))
      );
    });
    expect(offenders).toEqual([]);
  });

  it('raw() is vouched for in exactly the audited places', () => {
    // Every entry is a constant (an icon, a fixed attribute) or an encoder whose
    // output is generated geometry. Adding a call site means adding a line here,
    // which is the review.
    const expected: Record<string, number> = {
      'src/ts/render.ts': 1,
      'src/ts/ui-qol.ts': 2,
      'src/ts/utils.ts': 5,
      'src/ts/wifi-qr.ts': 1,
    };
    const found: Record<string, number> = {};
    for (const p of SRC) {
      const n = (readFileSync(p, 'utf8').match(/(?<![\w.])raw\(/g) ?? []).length;
      if (n) found[p] = n;
    }
    expect(found).toEqual(expected);
  });
});

describe('ids that used to be interpolated raw', () => {
  it('a hostile project id cannot break out of data-project-id in the config header', async () => {
    const { makeConfigViewHeaderBtns } = await import('../src/ts/chunk-ops');
    const evil = '" onmouseover="steal()" x="';
    const host = document.createElement('div');
    for (const type of ['wireguard', 'docker', 'nginx', 'apache', 'haproxy'] as const) {
      setHtml(
        host,
        makeConfigViewHeaderBtns({ id: evil, name: 'p', project_type: type, chunks: [] } as never),
      );
      expect(host.querySelector('[onmouseover]'), type).toBeNull();
      expect(host.querySelector('button')?.getAttribute('data-project-id'), type).toBe(evil);
    }
  });
});
