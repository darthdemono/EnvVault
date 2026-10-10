#!/usr/bin/env node
/**
 * Browser checks for the assembled product site (roadmap W1).
 *
 *   node scripts/check-site.mjs site            # serves ./site on a free port
 *
 * For every page at 1440 and 390 px wide: no horizontal scroll, exactly one h1,
 * every link and button has an accessible name, images have alt text and size,
 * the first Tab stop is the skip link and shows a visible focus ring, no console
 * errors, no failed requests. Exits 1 on any finding so CI can gate on it.
 */
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { chromium } from '@playwright/test';

const root = path.resolve(process.argv[2] ?? 'site');
const TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.xml': 'application/xml',
  '.txt': 'text/plain',
  '.json': 'application/json',
};

function serve() {
  const server = http.createServer((req, res) => {
    let p = path.join(root, decodeURIComponent(new URL(req.url, 'http://x').pathname));
    if (fs.existsSync(p) && fs.statSync(p).isDirectory()) p = path.join(p, 'index.html');
    if (!p.startsWith(root) || !fs.existsSync(p)) {
      res.writeHead(404).end('not found');
      return;
    }
    res
      .writeHead(200, { 'content-type': TYPES[path.extname(p)] ?? 'application/octet-stream' })
      .end(fs.readFileSync(p));
  });
  return new Promise((ok) => server.listen(0, '127.0.0.1', () => ok(server)));
}

/** Pages worth checking: every sitemap URL that is a product page (not the generated references). */
function pages() {
  const xml = fs.readFileSync(path.join(root, 'sitemap.xml'), 'utf8');
  return [...xml.matchAll(/<loc>https:\/\/[^/]+(\/[^<]*)<\/loc>/g)]
    .map((m) => m[1])
    .filter(
      (u) =>
        !u.startsWith('/docs/') &&
        !u.startsWith('/reference/ts/') &&
        !u.startsWith('/reference/rust/'),
    );
}

const findings = [];
const add = (page, vp, msg) => findings.push(`${page} @${vp}: ${msg}`);

const server = await serve();
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
for (const [vp, width, height] of [
  ['1440', 1440, 900],
  ['390', 390, 844],
]) {
  const ctx = await browser.newContext({ viewport: { width, height } });
  for (const url of pages()) {
    const page = await ctx.newPage();
    page.on('console', (m) => m.type() === 'error' && add(url, vp, `console error: ${m.text()}`));
    page.on('pageerror', (e) => add(url, vp, `page error: ${e.message}`));
    page.on('response', (r) => r.status() >= 400 && add(url, vp, `HTTP ${r.status()} ${r.url()}`));
    await page.goto(base + url, { waitUntil: 'networkidle' });

    const r = await page.evaluate(() => {
      const name = (el) =>
        (
          el.getAttribute('aria-label') ||
          el.textContent ||
          el.querySelector('img')?.alt ||
          ''
        ).trim();
      return {
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        h1: document.querySelectorAll('h1').length,
        title: document.title,
        desc: document.querySelector('meta[name=description]')?.content ?? '',
        canonical: document.querySelector('link[rel=canonical]')?.href ?? '',
        lang: document.documentElement.lang,
        unnamed: [...document.querySelectorAll('a, button')]
          .filter((e) => !name(e))
          .map((e) => e.outerHTML.slice(0, 80)),
        badImg: [...document.querySelectorAll('img')]
          .filter((i) => !i.alt || !i.getAttribute('width') || !i.getAttribute('height'))
          .map((i) => i.src),
        main: document.querySelectorAll('main#main').length,
      };
    });
    if (r.overflow > 0) add(url, vp, `horizontal scroll by ${r.overflow}px`);
    if (r.h1 !== 1) add(url, vp, `${r.h1} h1 elements`);
    if (!r.title || !r.desc) add(url, vp, 'missing title or description');
    if (!r.canonical.startsWith('https://')) add(url, vp, `canonical is not https: ${r.canonical}`);
    if (r.lang !== 'en') add(url, vp, 'missing lang');
    if (r.main !== 1) add(url, vp, 'needs exactly one main#main');
    for (const u of r.unnamed) add(url, vp, `link/button without a name: ${u}`);
    for (const i of r.badImg) add(url, vp, `image missing alt/width/height: ${i}`);

    await page.keyboard.press('Tab');
    const first = await page.evaluate(() => {
      const el = document.activeElement;
      const cs = el ? getComputedStyle(el) : null;
      return {
        text: el?.textContent?.trim() ?? '',
        cls: el?.className ?? '',
        outline: cs ? `${cs.outlineStyle} ${cs.outlineWidth}` : '',
      };
    });
    if (first.cls !== 'skip') add(url, vp, `first Tab stop is not the skip link (${first.text})`);
    if (!/solid [1-9]/.test(first.outline) && !/auto [1-9]/.test(first.outline))
      add(url, vp, `no visible focus ring on the skip link (${first.outline})`);
    await page.keyboard.press('Tab');
    const second = await page.evaluate(() => {
      const cs = getComputedStyle(document.activeElement);
      return `${cs.outlineStyle} ${cs.outlineWidth}`;
    });
    if (!/solid [1-9]/.test(second))
      add(url, vp, `no visible focus ring on the next Tab stop (${second})`);
    await page.close();
  }
  await ctx.close();
}
await browser.close();
server.close();
if (findings.length) {
  console.error(findings.join('\n'));
  console.error(`\n${findings.length} finding(s)`);
  process.exit(1);
}
console.log(`site checks ok: ${pages().length} pages x 2 viewports`);
