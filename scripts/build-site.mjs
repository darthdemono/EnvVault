#!/usr/bin/env node
/**
 * Assembles the product site from website/ into an output folder.
 *
 *   node scripts/build-site.mjs --out site                    # latest release, from the GitHub API
 *   node scripts/build-site.mjs --out site --release r.json --sums SHA256SUMS   # offline / tests
 *
 * The site is plain HTML and one stylesheet. This script only does what a static
 * page cannot: it stamps the version and the download table from the latest
 * *release* (not from main, so the page never advertises a build that is not
 * published), fills partials and canonical URLs, and writes sitemap.xml.
 * It fails loudly when the release cannot be read: a site that quietly shows a
 * stale version is worse than a failed deploy.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const SITE_URL = 'https://unenverse.darthdemono.com';
const REPO = 'darthdemono/UnENVerse';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** `SHA256SUMS` text to a name -> hex map. Accepts both `hash  name` and `hash *name`. */
export function parseSums(text) {
  const out = new Map();
  for (const line of text.split(/\r?\n/)) {
    const m = /^([0-9a-f]{64})\s+\*?(.+)$/i.exec(line.trim());
    if (m) out.set(m[2], m[1].toLowerCase());
  }
  return out;
}

export function fmtSize(bytes) {
  return bytes >= 1e6
    ? `${(bytes / 1e6).toFixed(1)} MB`
    : `${Math.max(1, Math.round(bytes / 1e3))} kB`;
}

export function esc(s) {
  return String(s).replace(
    /[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c],
  );
}

/** Which release assets are shown, and what each one is for. Signatures are not listed as rows. */
const KINDS = [
  { re: /\.AppImage$/, group: 'desktop', label: 'Linux, any distribution (AppImage)' },
  { re: /\.deb$/, group: 'desktop', label: 'Debian and Ubuntu (.deb)' },
  { re: /\.rpm$/, group: 'desktop', label: 'Fedora and RHEL (.rpm)' },
  { re: /-setup\.exe$/, group: 'desktop', label: 'Windows installer (.exe)' },
  { re: /^unv-.*-linux-x86_64\.tar\.gz$/, group: 'cli', label: 'Linux: unv and unv-server' },
  {
    re: /^unv-.*-windows-x86_64\.zip$/,
    group: 'cli',
    label: 'Windows: unv.exe and unv-server.exe',
  },
];

export function classify(assets) {
  const rows = { desktop: [], cli: [] };
  for (const k of KINDS) {
    const a = assets.find((x) => k.re.test(x.name));
    if (a) rows[k.group].push({ ...k, asset: a });
  }
  return rows;
}

export function table(rows, sums) {
  if (!rows.length) return '<p>No files in this release.</p>';
  const body = rows
    .map(({ label, asset }) => {
      const sha = sums.get(asset.name);
      return `<tr><td>${esc(label)}</td><td><a href="${esc(asset.browser_download_url)}">${esc(asset.name)}</a></td><td>${fmtSize(asset.size)}</td><td class="hash">${sha ? esc(sha) : 'see SHA256SUMS'}</td></tr>`;
    })
    .join('\n');
  return `<div class="scroll"><table><thead><tr><th scope="col">For</th><th scope="col">File</th><th scope="col">Size</th><th scope="col">SHA-256</th></tr></thead><tbody>\n${body}\n</tbody></table></div>`;
}

export function jsonLd(version) {
  const doc = {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'UnENVerse',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Linux, Windows',
    softwareVersion: version,
    license: 'https://www.apache.org/licenses/LICENSE-2.0',
    downloadUrl: `${SITE_URL}/download/`,
    offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
  };
  return JSON.stringify(doc).replace(/</g, '\\u003c');
}

const NAV = ['download', 'quickstart', 'guides', 'security'];

/** Fills one page. `page` is the nav key ("download") or "" for pages with none. */
export function fill(html, vars, partials, page) {
  let out = html.replace('{{HEADER}}', partials.header).replace('{{FOOTER}}', partials.footer);
  for (const n of NAV)
    out = out.replaceAll(`{{CUR_${n}}}`, n === page ? ' aria-current="page"' : '');
  for (const [k, v] of Object.entries(vars)) out = out.replaceAll(`{{${k}}}`, v);
  const left = out.match(/\{\{[A-Za-z_-]+\}\}/g);
  if (left) throw new Error(`unfilled placeholders: ${[...new Set(left)].join(', ')}`);
  return out;
}

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? walk(p) : [p];
  });
}

export function sitemap(urls, date) {
  const items = urls
    .map((u) => `  <url><loc>${SITE_URL}${u}</loc><lastmod>${date}</lastmod></url>`)
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${items}\n</urlset>\n`;
}

export function build({ src, out, release, sums, today = new Date().toISOString().slice(0, 10) }) {
  const version = release.tag_name.replace(/^v/, '');
  const parts = classify(release.assets);
  const shots = JSON.parse(fs.readFileSync(path.join(src, 'assets/shots/manifest.json'), 'utf8'));
  const vars = {
    VERSION: version,
    RELEASE_DATE: release.published_at.slice(0, 10),
    RELEASE_URL: release.html_url,
    SITE_URL,
    JSONLD: jsonLd(version),
    DESKTOP_TABLE: table(parts.desktop, sums),
    CLI_TABLE: table(parts.cli, sums),
  };
  for (const [name, d] of Object.entries(shots)) {
    vars[`W_${name}`] = String(d.width);
    vars[`H_${name}`] = String(d.height);
  }
  const partials = {
    header: fs.readFileSync(path.join(src, 'partials/header.html'), 'utf8'),
    footer: fs.readFileSync(path.join(src, 'partials/footer.html'), 'utf8'),
  };

  fs.rmSync(out, { recursive: true, force: true });
  const urls = [];
  for (const file of walk(src)) {
    const rel = path.relative(src, file);
    if (rel.startsWith('partials')) continue;
    const dest = path.join(out, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    if (rel.endsWith('.html')) {
      const page = rel === 'index.html' ? '' : rel.split(path.sep)[0];
      const html = fill(fs.readFileSync(file, 'utf8'), vars, partials, page);
      fs.writeFileSync(dest, html);
      // Redirect stubs say noindex; they are not pages to list.
      if (!/name="robots" content="noindex"/.test(html)) {
        urls.push(rel === 'index.html' ? '/' : `/${path.dirname(rel).split(path.sep).join('/')}/`);
      }
    } else {
      fs.copyFileSync(file, dest);
    }
  }
  fs.writeFileSync(path.join(out, 'sitemap.xml'), sitemap(urls.sort(), today));
  return { version, pages: urls };
}

async function latestRelease() {
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'unenverse-site-build' };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const r = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, { headers });
  if (!r.ok) throw new Error(`GitHub release lookup failed: HTTP ${r.status}`);
  const release = await r.json();
  const sumsAsset = release.assets.find((a) => a.name === 'SHA256SUMS');
  if (!sumsAsset) throw new Error('the latest release has no SHA256SUMS');
  const s = await fetch(sumsAsset.browser_download_url);
  if (!s.ok) throw new Error(`SHA256SUMS download failed: HTTP ${s.status}`);
  return { release, sumsText: await s.text() };
}

async function main() {
  const arg = (n) => {
    const i = process.argv.indexOf(n);
    return i > 0 ? process.argv[i + 1] : undefined;
  };
  const out = path.resolve(arg('--out') ?? 'site');
  let release;
  let sumsText;
  if (arg('--release')) {
    release = JSON.parse(fs.readFileSync(arg('--release'), 'utf8'));
    sumsText = fs.readFileSync(arg('--sums'), 'utf8');
  } else {
    ({ release, sumsText } = await latestRelease());
  }
  const { version, pages } = build({
    src: path.join(ROOT, 'website'),
    out,
    release,
    sums: parseSums(sumsText),
  });
  console.log(`site ${version}: ${pages.length} pages -> ${out}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
