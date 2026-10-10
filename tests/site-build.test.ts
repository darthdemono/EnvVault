// The product site (roadmap W1): the build helpers, and the colour tokens that
// the design promises are readable. Pure functions only; the browser checks
// live in scripts/check-site.mjs.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs without types
import * as site from '../scripts/build-site.mjs';

const { build, classify, fmtSize, jsonLd, parseSums, sitemap, table } = site;

const root = path.resolve(__dirname, '..');

describe('parseSums', () => {
  it('reads sha256sum output in both text and binary form', () => {
    const a = 'a'.repeat(64);
    const b = 'b'.repeat(64);
    const m = parseSums(`${a}  one.tar.gz\n${b} *two.exe\nnot a line\n`);
    expect(m.get('one.tar.gz')).toBe(a);
    expect(m.get('two.exe')).toBe(b);
    expect(m.size).toBe(2);
  });
});

describe('download table', () => {
  const assets = [
    {
      name: 'UnENVerse_1.0.0_amd64.AppImage',
      size: 86_567_416,
      browser_download_url: 'https://x/app',
    },
    { name: 'UnENVerse_1.0.0_amd64.AppImage.sig', size: 96, browser_download_url: 'https://x/sig' },
    {
      name: 'unv-1.0.0-linux-x86_64.tar.gz',
      size: 11_523_741,
      browser_download_url: 'https://x/cli',
    },
    { name: 'unenverse-1.0.0.vsix', size: 12_063, browser_download_url: 'https://x/vsix' },
  ];
  it('lists installers and archives but never the signature files', () => {
    const rows = classify(assets);
    expect(rows.desktop.map((r: { asset: { name: string } }) => r.asset.name)).toEqual([
      'UnENVerse_1.0.0_amd64.AppImage',
    ]);
    expect(rows.cli).toHaveLength(1);
    const html = table(
      rows.desktop,
      parseSums(`${'c'.repeat(64)}  UnENVerse_1.0.0_amd64.AppImage\n`),
    );
    expect(html).toContain('86.6 MB');
    expect(html).toContain('c'.repeat(64));
    expect(html).not.toContain('.sig');
  });
  it('escapes a hostile asset name', () => {
    const html = table(
      classify([
        { name: '"><script>x</script>.AppImage', size: 5, browser_download_url: 'https://x' },
      ]).desktop,
      new Map(),
    );
    expect(html).not.toContain('<script>');
  });
  it('formats sizes', () => {
    expect(fmtSize(12_063)).toBe('12 kB');
    expect(fmtSize(5_903_994)).toBe('5.9 MB');
  });
});

describe('structured data and sitemap', () => {
  it('describes only true fields and cannot close the script tag', () => {
    const ld = jsonLd('0.42.4');
    const doc = JSON.parse(ld);
    expect(doc['@type']).toBe('SoftwareApplication');
    expect(doc.softwareVersion).toBe('0.42.4');
    expect(Object.keys(doc)).not.toContain('aggregateRating');
    expect(jsonLd('</script>')).not.toContain('</script>');
  });
  it('writes absolute https urls', () => {
    expect(sitemap(['/', '/download/'], '2026-10-10')).toContain(
      '<loc>https://unenverse.darthdemono.com/download/</loc>',
    );
  });
});

describe('assembling the site', () => {
  it('fills every placeholder, marks the current nav item and skips redirect stubs in the sitemap', () => {
    const out = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'site-'));
    const release = {
      tag_name: 'v9.9.9',
      published_at: '2030-01-02T00:00:00Z',
      html_url: 'https://example.invalid/r',
      assets: [
        {
          name: 'UnENVerse_9.9.9_amd64.AppImage',
          size: 1_000_000,
          browser_download_url: 'https://example.invalid/a',
        },
      ],
    };
    const r = build({
      src: path.join(root, 'website'),
      out,
      release,
      sums: new Map(),
      today: '2030-01-03',
    });
    expect(r.version).toBe('9.9.9');
    const dl = fs.readFileSync(path.join(out, 'download/index.html'), 'utf8');
    expect(dl).toContain('Download UnENVerse 9.9.9');
    expect(dl).toContain('<a href="/download/" aria-current="page">');
    expect(dl).not.toMatch(/\{\{/);
    const map = fs.readFileSync(path.join(out, 'sitemap.xml'), 'utf8');
    expect(map).toContain('/quickstart/');
    expect(map).not.toContain('/book/');
    expect(map).not.toContain('/rust/</loc>');
    expect(fs.existsSync(path.join(out, 'book/index.html'))).toBe(true);
    fs.rmSync(out, { recursive: true, force: true });
  });
  it('fails on a placeholder nobody fills', () => {
    const src = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'src-'));
    fs.mkdirSync(path.join(src, 'partials'));
    fs.mkdirSync(path.join(src, 'assets/shots'), { recursive: true });
    fs.writeFileSync(path.join(src, 'assets/shots/manifest.json'), '{}');
    fs.writeFileSync(path.join(src, 'partials/header.html'), '');
    fs.writeFileSync(path.join(src, 'partials/footer.html'), '');
    fs.writeFileSync(path.join(src, 'index.html'), '<p>{{NOT_A_THING}}</p>');
    const release = {
      tag_name: 'v1.0.0',
      published_at: '2030-01-02T00:00:00Z',
      html_url: 'x',
      assets: [],
    };
    expect(() => build({ src, out: path.join(src, 'out'), release, sums: new Map() })).toThrow(
      /NOT_A_THING/,
    );
  });
});

// ── Colour contrast: the design says body text 7:1, everything else 4.5:1 ─────
function lum(hex: string): number {
  const c = [1, 3, 5]
    .map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}
function ratio(a: string, b: string): number {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}
function tokens(block: string): Record<string, string> {
  return Object.fromEntries(
    [...block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1], m[2]]),
  );
}
const css = fs.readFileSync(path.join(root, 'website/styles.css'), 'utf8');
const light = tokens(
  css.slice(css.indexOf(':root {'), css.indexOf('@media (prefers-color-scheme: dark)')),
);
const darkStart = css.indexOf('@media (prefers-color-scheme: dark)');
const dark = {
  ...light,
  ...tokens(css.slice(darkStart, css.indexOf('}', css.indexOf('}', darkStart) - 0) + 1)),
};

describe.each([
  ['light', light],
  ['dark', dark],
])('%s theme contrast', (_n, t) => {
  it('body text reaches 7:1 on the page and on cards', () => {
    expect(ratio(t.ink, t.bg)).toBeGreaterThanOrEqual(7);
    expect(ratio(t.ink, t.surface)).toBeGreaterThanOrEqual(7);
  });
  it('muted text, links, buttons and the warning bar reach 4.5:1', () => {
    expect(ratio(t.muted, t.bg)).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t.muted, t.surface)).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t.accent, t.bg)).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t['accent-ink'], t.accent)).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t.warn, t.bg)).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t.accent, t['code-bg'])).toBeGreaterThanOrEqual(4.5);
  });
  it('the focus ring is a visible 3:1 against the page', () => {
    expect(ratio(t.focus, t.bg)).toBeGreaterThanOrEqual(3);
  });
});

// mdBook does not fail on a chapter that is listed but missing: it creates an
// empty file and publishes a blank page. Four ADR pages shipped that way after a
// rename, so the index is checked against the files it names.
describe('the guide index', () => {
  it('links only files that exist', () => {
    const summary = fs.readFileSync(path.join(root, 'book/src/SUMMARY.md'), 'utf8');
    const links = [...summary.matchAll(/\]\(([^)#]+\.md)\)/g)].map((m) => m[1]);
    expect(links.length).toBeGreaterThan(100);
    const missing = links.filter((l) => !fs.existsSync(path.join(root, 'book/src', l)));
    expect(missing).toEqual([]);
  });
});
