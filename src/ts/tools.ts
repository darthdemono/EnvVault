/**
 * @file
 * Tools panel — secret generator, password generator, UUID/ULID,
 * API key patterns, hash generator, JWT validator, cert gen, SSH keygen,
 * string tools, base64.
 */

import * as yaml from 'js-yaml';
import type { VaultEntry } from './types';
import { Settings, switchPanel, switchTool, st, persist, entryId, ensureEntryIds } from './state';
import { showToast, clipboardWrite, generateULID, showConfirm, esc } from './utils';
import {
  showDropdown,
  injectIntoForm,
  quickGenerate,
  openAdd,
  fillForm,
  buildCatChips,
  openModal,
} from './modals';
import { SECRET_TEMPLATES } from './templates';
import { render } from './render';
import { resolveFieldRef } from './chunk-ops';
import { initAuditPanel } from './audit';

function parseImport(raw: string, fmt: string): any[] {
  const base = (p: string, v: string) => ({
    provider: p,
    api_key: v,
    price_type: 'local',
    secretType: 'env_var',
    categories: [],
    projectIds: ['Universal'],
    scopes: [],
  });

  if (fmt === 'env') {
    return raw.split('\n').flatMap((line) => {
      const t = line.trim();
      if (!t || t.startsWith('#')) return [];
      const eq = t.indexOf('=');
      if (eq < 1) return [];
      const key = t.slice(0, eq).trim();
      const val = t
        .slice(eq + 1)
        .trim()
        .replace(/^["']|["']$/g, '');
      return [base(key, val)];
    });
  }

  if (fmt === 'bitwarden') {
    try {
      const data = JSON.parse(raw);
      const items = data.items ?? data;
      return (Array.isArray(items) ? items : []).map((item: any) => ({
        provider: item.name || 'Unknown',
        account_name: item.login?.username ?? null,
        api_key: item.login?.password ?? item.notes ?? '',
        api_url: item.login?.uris?.[0]?.uri ?? null,
        price_type: 'paid',
        secretType: 'password',
        categories: [],
        projectIds: ['Universal'],
        scopes: [],
        description: item.notes ?? null,
      }));
    } catch {
      return [];
    }
  }

  if (fmt === '1password') {
    try {
      const items = JSON.parse(raw);
      return (Array.isArray(items) ? items : []).map((item: any) => {
        const pw = item.fields?.find(
          (f: any) => f.designation === 'password' || f.id === 'password',
        );
        const user = item.fields?.find(
          (f: any) => f.designation === 'username' || f.id === 'username',
        );
        return {
          provider: item.title || 'Unknown',
          account_name: user?.value ?? null,
          api_key: pw?.value ?? '',
          price_type: 'paid',
          secretType: 'password',
          categories: item.tags ?? [],
          projectIds: ['Universal'],
          scopes: [],
        };
      });
    } catch {
      return [];
    }
  }

  if (fmt === 'json') {
    try {
      const data = JSON.parse(raw);
      const items = Array.isArray(data) ? data : (data.api_keys ?? []);
      return items;
    } catch {
      return [];
    }
  }

  if (fmt === 'yaml') {
    try {
      const data: any = yaml.load(raw);
      // Accept a full vault ({api_keys:[...]}), a bare list, or a flat KEY: value map.
      if (Array.isArray(data)) return data;
      if (data && Array.isArray(data.api_keys)) return data.api_keys;
      if (data && typeof data === 'object') {
        return Object.entries(data).map(([k, v]) =>
          base(k, typeof v === 'string' ? v : JSON.stringify(v)),
        );
      }
      return [];
    } catch {
      return [];
    }
  }

  return [];
}

/**
 * Force an imported object into a shape the rest of the app can render.
 *
 * The `json` and `yaml` branches above hand back whatever was in the file. An
 * object with no `provider` reached `sorted()`, which calls
 * `a.provider.localeCompare(...)` and threw — a malformed import took the whole
 * grid down rather than being rejected. Missing arrays caused the same class of
 * failure further in.
 */
export function normalizeImported(raw: any): VaultEntry | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const provider = String(raw.provider ?? raw.name ?? '').trim();
  if (!provider) return null;
  const projectIds: string[] = Array.isArray(raw.projectIds) ? [...raw.projectIds] : [];
  if (!projectIds.includes('Universal')) projectIds.push('Universal');
  return {
    ...raw,
    provider,
    api_key: typeof raw.api_key === 'string' ? raw.api_key : String(raw.api_key ?? ''),
    price_type: ['free', 'local', 'paid', 'conditional'].includes(raw.price_type)
      ? raw.price_type
      : 'free',
    secretType: raw.secretType ?? 'api_key',
    categories: Array.isArray(raw.categories) ? raw.categories : [],
    scopes: Array.isArray(raw.scopes) ? raw.scopes : [],
    projectIds,
  } as VaultEntry;
}

let _toolsInited = false;

export function initTools() {
  if (_toolsInited) return;
  _toolsInited = true;
  const invoke = (window as any).__TAURI__?.core?.invoke?.bind((window as any).__TAURI__?.core);

  // ── Activity bar panel switching ──
  document.querySelectorAll<HTMLButtonElement>('.activity-btn').forEach((btn) => {
    btn.addEventListener('click', () =>
      switchPanel(btn.dataset.panel as 'secrets' | 'tools' | 'users'),
    );
  });

  // ── Tool nav switching ──
  document.querySelectorAll<HTMLButtonElement>('.tool-nav-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      switchTool(btn.dataset.tool!);
      if (btn.dataset.tool === 'expiry-calendar') setTimeout(renderCalendar, 50);
      if (btn.dataset.tool === 'diff') refreshDiffSelects();
      if (btn.dataset.tool === 'audit') document.getElementById('audit-refresh')?.click();
    });
  });

  initAuditPanel();

  // ── Section collapse toggles ──
  document.querySelectorAll<HTMLButtonElement>('.section-collapse-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const section = btn.dataset.section as
        'all' | 'price' | 'env' | 'category' | 'project' | 'tags' | 'prefixes';
      const el = document.getElementById(`sidebar-section-${section}`)!;
      el.classList.toggle('collapsed');
      const collapsed = (Settings.get('collapsedSections') || []) as (
        'all' | 'price' | 'env' | 'category' | 'project' | 'tags' | 'prefixes'
      )[];
      const isNowCollapsed = el.classList.contains('collapsed');
      const updated = isNowCollapsed
        ? [...new Set([...collapsed, section])]
        : collapsed.filter((s) => s !== section);
      Settings.set('collapsedSections', updated as any);
    });
  });

  // Restore active panel & tool from settings
  const activePanel = (Settings.get('activePanel') || 'secrets') as 'secrets' | 'tools' | 'users';
  const activeTool = Settings.get('activeTool') || 'secret-gen';
  switchPanel(activePanel === 'users' ? 'secrets' : activePanel); // don't restore users panel on init
  switchTool(activeTool);

  // ── SECRET GENERATOR ──
  let sgBytes = 32;
  document.querySelectorAll<HTMLButtonElement>('.tool-byte-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-byte-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      sgBytes = parseInt(btn.dataset.bytes!);
    });
  });
  const sgGenerate = () => {
    const buf = new Uint8Array(sgBytes);
    crypto.getRandomValues(buf);
    const fmt = (document.getElementById('sg-format') as HTMLSelectElement).value;
    let out: string;
    if (fmt === 'hex')
      out = Array.from(buf)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    else if (fmt === 'base64url')
      out = btoa(String.fromCharCode(...buf))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    else out = btoa(String.fromCharCode(...buf));
    (document.getElementById('sg-output') as HTMLTextAreaElement).value = out;
  };
  document.getElementById('sg-generate')!.addEventListener('click', sgGenerate);
  document.getElementById('sg-copy')!.addEventListener('click', () => {
    const v = (document.getElementById('sg-output') as HTMLTextAreaElement).value;
    if (v) clipboardWrite(v);
  });
  document.getElementById('sg-inject')!.addEventListener('click', () => {
    const v = (document.getElementById('sg-output') as HTMLTextAreaElement).value;
    if (v) injectIntoForm(v);
  });

  // ── PASSWORD GENERATOR ──
  const pgLength = document.getElementById('pg-length') as HTMLInputElement;
  const pgLenDisplay = document.getElementById('pg-len-display')!;
  pgLength.addEventListener('input', () => {
    pgLenDisplay.textContent = pgLength.value;
  });
  const pgGenerate = () => {
    const len = parseInt(pgLength.value);
    const upper = (document.getElementById('pg-upper') as HTMLInputElement).checked;
    const lower = (document.getElementById('pg-lower') as HTMLInputElement).checked;
    const digits = (document.getElementById('pg-digits') as HTMLInputElement).checked;
    const symbols = (document.getElementById('pg-symbols') as HTMLInputElement).checked;
    const noAmbig = (document.getElementById('pg-noambig') as HTMLInputElement).checked;
    let chars = '';
    if (upper) chars += noAmbig ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (lower) chars += noAmbig ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
    if (digits) chars += noAmbig ? '23456789' : '0123456789';
    if (symbols) chars += '!@#$%^&*()-_=+[]{}|;:,.<>?';
    if (!chars) {
      showToast('Select at least one character set', 'err');
      return;
    }
    const buf = new Uint32Array(len);
    crypto.getRandomValues(buf);
    const pwd = Array.from(buf)
      .map((n) => chars[n % chars.length])
      .join('');
    (document.getElementById('pg-output') as HTMLInputElement).value = pwd;
    const entropy = len * Math.log2(chars.length);
    const fill = document.getElementById('pg-strength-fill')!;
    const pct = Math.min(100, (entropy / 128) * 100);
    fill.style.width = pct + '%';
    fill.style.background = pct < 30 ? '#e44' : pct < 55 ? '#fa0' : pct < 75 ? '#4af' : '#0c9';
  };
  document.getElementById('pg-generate')!.addEventListener('click', pgGenerate);
  document.getElementById('pg-copy')!.addEventListener('click', () => {
    const v = (document.getElementById('pg-output') as HTMLInputElement).value;
    if (v) clipboardWrite(v);
  });
  document.getElementById('pg-inject')!.addEventListener('click', () => {
    const v = (document.getElementById('pg-output') as HTMLInputElement).value;
    if (v) injectIntoForm(v);
  });

  // ── UUID / ULID ──
  let uuType = 'uuid';
  document.querySelectorAll<HTMLButtonElement>('.tool-id-type-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-id-type-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      uuType = btn.dataset.type!;
    });
  });
  document.getElementById('uu-generate')!.addEventListener('click', () => {
    const count = parseInt((document.getElementById('uu-count') as HTMLInputElement).value) || 1;
    const lines = Array.from({ length: count }, () =>
      uuType === 'uuid' ? crypto.randomUUID() : generateULID(),
    );
    (document.getElementById('uu-output') as HTMLTextAreaElement).value = lines.join('\n');
  });
  document.getElementById('uu-copy')!.addEventListener('click', () => {
    const v = (document.getElementById('uu-output') as HTMLTextAreaElement).value;
    if (v) clipboardWrite(v);
  });

  // ── API KEY PATTERNS ──
  const akGenerate = () => {
    const pattern = (document.getElementById('ak-pattern') as HTMLSelectElement).value;
    const buf = new Uint8Array(64);
    crypto.getRandomValues(buf);
    let out = '';
    const toHex = (b: Uint8Array) =>
      Array.from(b)
        .map((x) => x.toString(16).padStart(2, '0'))
        .join('');
    const toB64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
    const toB64url = (b: Uint8Array) =>
      toB64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    if (pattern === 'jwt-secret') out = toHex(buf.slice(0, 32));
    else if (pattern === 'base64-32') out = toB64(buf.slice(0, 32));
    else if (pattern === 'hex-32') out = toHex(buf.slice(0, 32));
    else if (pattern === 'hex-16') out = toHex(buf.slice(0, 16));
    else if (pattern === 'bearer') out = toB64url(buf.slice(0, 32));
    else if (pattern === 'sk-prefix') out = 'sk-' + toB64url(buf.slice(0, 32)).slice(0, 48);
    (document.getElementById('ak-output') as HTMLInputElement).value = out;
  };
  document.getElementById('ak-generate')!.addEventListener('click', akGenerate);
  document.getElementById('ak-copy')!.addEventListener('click', () => {
    const v = (document.getElementById('ak-output') as HTMLInputElement).value;
    if (v) clipboardWrite(v);
  });
  document.getElementById('ak-inject')!.addEventListener('click', () => {
    const v = (document.getElementById('ak-output') as HTMLInputElement).value;
    if (v) injectIntoForm(v);
  });

  // ── HASH GENERATOR ──
  let hgAlgo = 'SHA-256';
  let hgFmt = 'hex';
  document.querySelectorAll<HTMLButtonElement>('.tool-hash-algo-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-hash-algo-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      hgAlgo = btn.dataset.algo!;
    });
  });
  document.querySelectorAll<HTMLButtonElement>('.tool-hash-fmt-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-hash-fmt-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      hgFmt = btn.dataset.fmt!;
    });
  });
  document.getElementById('hg-hash')!.addEventListener('click', async () => {
    const input = (document.getElementById('hg-input') as HTMLTextAreaElement).value;
    const enc = new TextEncoder().encode(input);
    const hashBuf = await crypto.subtle.digest(hgAlgo, enc);
    const hashArr = new Uint8Array(hashBuf);
    let out: string;
    if (hgFmt === 'base64') out = btoa(String.fromCharCode(...hashArr));
    else
      out = Array.from(hashArr)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    (document.getElementById('hg-output') as HTMLInputElement).value = out;
  });
  document.getElementById('hg-copy')!.addEventListener('click', () => {
    const v = (document.getElementById('hg-output') as HTMLInputElement).value;
    if (v) clipboardWrite(v);
  });
  document.getElementById('hg-inject')!.addEventListener('click', () => {
    const v = (document.getElementById('hg-output') as HTMLInputElement).value;
    if (v) injectIntoForm(v);
  });

  // ── TOKEN VALIDATOR ──
  document.getElementById('tv-decode')!.addEventListener('click', () => {
    const jwt = (document.getElementById('tv-input') as HTMLTextAreaElement).value.trim();
    const parts = jwt.split('.');
    const statusEl = document.getElementById('tv-status')!;
    if (parts.length !== 3) {
      statusEl.className = 'tool-status err';
      statusEl.textContent = 'Invalid JWT: expected 3 parts';
      statusEl.style.display = '';
      (document.getElementById('tv-header') as HTMLPreElement).textContent = '';
      (document.getElementById('tv-payload') as HTMLPreElement).textContent = '';
      return;
    }
    try {
      const decode = (s: string) =>
        JSON.parse(
          atob(
            s
              .replace(/-/g, '+')
              .replace(/_/g, '/')
              .padEnd(s.length + ((4 - (s.length % 4)) % 4), '='),
          ),
        );
      const header = decode(parts[0]);
      const payload = decode(parts[1]);
      (document.getElementById('tv-header') as HTMLPreElement).textContent = JSON.stringify(
        header,
        null,
        2,
      );
      (document.getElementById('tv-payload') as HTMLPreElement).textContent = JSON.stringify(
        payload,
        null,
        2,
      );
      statusEl.style.display = '';
      if (payload.exp) {
        const exp = new Date(payload.exp * 1000);
        const now = new Date();
        if (exp < now) {
          statusEl.className = 'tool-status err';
          statusEl.textContent = `Expired: ${exp.toISOString()}`;
        } else {
          statusEl.className = 'tool-status ok';
          statusEl.textContent = `Valid until: ${exp.toISOString()}`;
        }
      } else {
        statusEl.className = 'tool-status warn';
        statusEl.textContent = 'No expiry claim (exp) found';
      }
    } catch {
      statusEl.className = 'tool-status err';
      statusEl.textContent = 'Failed to decode JWT';
      statusEl.style.display = '';
    }
  });
  document.getElementById('tv-copy-header')?.addEventListener('click', () => {
    const v = (document.getElementById('tv-header') as HTMLPreElement).textContent;
    if (v?.trim()) clipboardWrite(v).then(() => showToast('Header copied ✓', 'ok', 1500));
    else showToast('Decode a JWT first', 'err');
  });
  document.getElementById('tv-copy-payload')?.addEventListener('click', () => {
    const v = (document.getElementById('tv-payload') as HTMLPreElement).textContent;
    if (v?.trim()) clipboardWrite(v).then(() => showToast('Payload copied ✓', 'ok', 1500));
    else showToast('Decode a JWT first', 'err');
  });

  // ── PEM CERT GEN (Rust) ──
  const pcDays = document.getElementById('pc-days') as HTMLInputElement;
  const pcDaysDisplay = document.getElementById('pc-days-display')!;
  pcDays.addEventListener('input', () => {
    pcDaysDisplay.textContent = pcDays.value;
  });
  document.getElementById('pc-generate')!.addEventListener('click', async () => {
    if (!invoke) {
      showToast('Tauri not available', 'err');
      return;
    }
    const cn = (document.getElementById('pc-cn') as HTMLInputElement).value.trim() || 'localhost';
    const days = parseInt(pcDays.value) || 365;
    const loading = document.getElementById('pc-loading')!;
    loading.style.display = '';
    try {
      const result: { cert_pem: string; key_pem: string } = await invoke('generate_certificate', {
        commonName: cn,
        validityDays: days,
      });
      (document.getElementById('pc-cert-output') as HTMLTextAreaElement).value = result.cert_pem;
      (document.getElementById('pc-key-output') as HTMLTextAreaElement).value = result.key_pem;
    } catch (e) {
      showToast(String(e), 'err');
    } finally {
      loading.style.display = 'none';
    }
  });
  document.getElementById('pc-copy-cert')!.addEventListener('click', () => {
    const v = (document.getElementById('pc-cert-output') as HTMLTextAreaElement).value;
    if (v) clipboardWrite(v);
  });
  document.getElementById('pc-copy-key')!.addEventListener('click', () => {
    const v = (document.getElementById('pc-key-output') as HTMLTextAreaElement).value;
    if (v) clipboardWrite(v);
  });

  // ── SSH KEYGEN (Rust) ──
  document.getElementById('sk-generate')!.addEventListener('click', async () => {
    if (!invoke) {
      showToast('Tauri not available', 'err');
      return;
    }
    const comment = (document.getElementById('sk-comment') as HTMLInputElement).value.trim();
    const loading = document.getElementById('sk-loading')!;
    loading.style.display = '';
    try {
      const result: { public_key: string; private_key: string } = await invoke(
        'generate_ssh_keypair',
        { comment },
      );
      (document.getElementById('sk-pub-output') as HTMLTextAreaElement).value = result.public_key;
      (document.getElementById('sk-priv-output') as HTMLTextAreaElement).value = result.private_key;
    } catch (e) {
      showToast(String(e), 'err');
    } finally {
      loading.style.display = 'none';
    }
  });
  document.getElementById('sk-copy-pub')!.addEventListener('click', () => {
    const v = (document.getElementById('sk-pub-output') as HTMLTextAreaElement).value;
    if (v) clipboardWrite(v);
  });
  document.getElementById('sk-copy-priv')!.addEventListener('click', () => {
    const v = (document.getElementById('sk-priv-output') as HTMLTextAreaElement).value;
    if (v) clipboardWrite(v);
  });

  // ── STRING TOOLS ──
  document.getElementById('st-convert')!.addEventListener('click', () => {
    const op = (document.getElementById('st-op') as HTMLSelectElement).value;
    const input = (document.getElementById('st-input') as HTMLTextAreaElement).value;
    let out = '';
    try {
      if (op === 'url-encode') out = encodeURIComponent(input);
      else if (op === 'url-decode') out = decodeURIComponent(input);
      else if (op === 'dotenv-escape') {
        out =
          input.includes('\n') || input.includes('"') || input.includes("'") || input.includes(' ')
            ? '"' +
              input
                .replace(/\\/g, '\\\\')
                .replace(/"/g, '\\"')
                .replace(/\n/g, '\\n')
                .replace(/\r/g, '\\r') +
              '"'
            : input;
      } else if (op === 'shell-quote') out = "'" + input.replace(/'/g, "'\\''") + "'";
      else if (op === 'json-escape') out = JSON.stringify(input).slice(1, -1);
      else if (op === 'json-unescape') out = JSON.parse('"' + input + '"');
    } catch (e) {
      showToast('Conversion error: ' + String(e), 'err');
      return;
    }
    (document.getElementById('st-output') as HTMLTextAreaElement).value = out;
  });
  document.getElementById('st-copy')!.addEventListener('click', () => {
    const v = (document.getElementById('st-output') as HTMLTextAreaElement).value;
    if (v) clipboardWrite(v);
  });

  // ── BASE64 ──
  let b64Op = 'encode';
  let b64Var = 'std';
  document.querySelectorAll<HTMLButtonElement>('.tool-b64-op-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-b64-op-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      b64Op = btn.dataset.op!;
    });
  });
  document.querySelectorAll<HTMLButtonElement>('.tool-b64-var-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-b64-var-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      b64Var = btn.dataset.var!;
    });
  });
  document.getElementById('b64-convert')!.addEventListener('click', () => {
    const input = (document.getElementById('b64-input') as HTMLTextAreaElement).value;
    let out = '';
    try {
      if (b64Op === 'encode') {
        let encoded = btoa(unescape(encodeURIComponent(input)));
        if (b64Var === 'url')
          encoded = encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        out = encoded;
      } else {
        let normalized = input;
        if (b64Var === 'url') normalized = input.replace(/-/g, '+').replace(/_/g, '/');
        out = decodeURIComponent(escape(atob(normalized)));
      }
    } catch (e) {
      showToast('Base64 error: ' + String(e), 'err');
      return;
    }
    (document.getElementById('b64-output') as HTMLTextAreaElement).value = out;
  });
  document.getElementById('b64-copy')!.addEventListener('click', () => {
    const v = (document.getElementById('b64-output') as HTMLTextAreaElement).value;
    if (v) clipboardWrite(v);
  });

  // ── Health Dashboard (item 7) ──────────────────────────────────────────────

  document.getElementById('health-scan-btn')?.addEventListener('click', () => {
    const results = document.getElementById('health-results')!;
    const timeEl = document.getElementById('health-scan-time')!;
    const keys = st.vault.api_keys;

    const now = Date.now();
    const today = new Date().toISOString().slice(0, 10);
    const warn30 = new Date(now + 30 * 86_400_000).toISOString().slice(0, 10);

    const issues: { severity: 'high' | 'med' | 'low'; msg: string; provider: string }[] = [];

    keys.forEach((k) => {
      const prov = k.provider || '?';
      // Marked compromised — emergency rotate
      if (k.compromised) {
        issues.push({
          severity: 'high',
          provider: prov,
          msg: 'Marked COMPROMISED — rotate immediately',
        });
      }
      // Weak password (entropy estimate): length < 12 and not a token pattern
      if (
        (k.secretType === 'password' || k.secretType === 'api_key') &&
        k.api_key.length < 12 &&
        !/^[A-Za-z0-9_-]{20,}$/.test(k.api_key)
      ) {
        issues.push({
          severity: 'high',
          provider: prov,
          msg: 'Short or weak secret value (< 12 chars)',
        });
      }
      // Common weak literal (dictionary check for JWT/cookie secrets etc.)
      if (
        k.api_key &&
        /^(password|secret|changeme|admin|test|123456|qwerty|letmein|default)/i.test(k.api_key)
      ) {
        issues.push({
          severity: 'high',
          provider: prov,
          msg: 'Secret starts with a common weak value',
        });
      }
      // Expired
      if (k.expires_at && k.expires_at.slice(0, 10) < today) {
        issues.push({
          severity: 'high',
          provider: prov,
          msg: `Expired on ${k.expires_at.slice(0, 10)}`,
        });
      }
      // Expiring soon
      else if (k.expires_at && k.expires_at.slice(0, 10) <= warn30) {
        issues.push({
          severity: 'med',
          provider: prov,
          msg: `Expiring ${k.expires_at.slice(0, 10)}`,
        });
      }
      // Rotation overdue (cadence set + last rotation older than rotation_days)
      if (k.rotation_days && k.rotation_days > 0 && k.last_rotated_at) {
        const dueMs = new Date(k.last_rotated_at).getTime() + k.rotation_days * 86_400_000;
        if (dueMs < now) {
          const overdue = Math.floor((now - dueMs) / 86_400_000);
          issues.push({
            severity: 'med',
            provider: prov,
            msg: `Rotation overdue by ${overdue}d (every ${k.rotation_days}d)`,
          });
        }
      }
      // Never rotated
      if (!k.last_rotated_at && !k.version_history?.length) {
        issues.push({ severity: 'low', provider: prov, msg: 'Never rotated' });
      }
      // No description
      if (!k.api_description && !k.description) {
        issues.push({
          severity: 'low',
          provider: prov,
          msg: 'No description — hard to identify later',
        });
      }
    });

    // Duplicate value detection — same secret stored under multiple entries
    const valueMap = new Map<string, string[]>();
    keys.forEach((k) => {
      if (!k.api_key || k.api_key.length < 6) return;
      if (!valueMap.has(k.api_key)) valueMap.set(k.api_key, []);
      valueMap.get(k.api_key)!.push(k.provider || '?');
    });
    valueMap.forEach((provs) => {
      if (provs.length > 1) {
        issues.push({
          severity: 'med',
          provider: provs.join(', '),
          msg: `Same secret value in ${provs.length} entries — consider merging`,
        });
      }
    });

    // Stale ${ref} detection — chunk fields pointing at a deleted/renamed target.
    // Suggests the closest existing provider via edit distance ("did you mean …?").
    const lev = (a: string, b: string): number => {
      const m = a.length,
        n = b.length;
      const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
      for (let j = 0; j <= n; j++) d[0][j] = j;
      for (let i = 1; i <= m; i++)
        for (let j = 1; j <= n; j++)
          d[i][j] = Math.min(
            d[i - 1][j] + 1,
            d[i][j - 1] + 1,
            d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
          );
      return d[m][n];
    };
    const providers = [...new Set(keys.map((k) => k.provider).filter(Boolean))];
    const nearest = (target: string): string | null => {
      let best: string | null = null,
        bestD = Infinity;
      for (const p of providers) {
        const dd = lev(target.toLowerCase(), p.toLowerCase());
        if (dd < bestD) {
          bestD = dd;
          best = p;
        }
      }
      return best && bestD <= Math.max(2, Math.ceil(target.length * 0.4)) ? best : null;
    };
    const seenStale = new Set<string>();
    st.vault.projects.forEach((p) => {
      (p.chunks || []).forEach((c) => {
        c.fields.forEach((f) => {
          if (!/^\$\{.+\}$/.test(f.value)) return;
          const r = resolveFieldRef(f.value);
          if (r.unresolved) {
            const dedupe = `${p.name}|${f.value}`;
            if (seenStale.has(dedupe)) return;
            seenStale.add(dedupe);
            const inner = f.value.replace(/^\$\{|\}$/g, '').replace(/^chunk:/, '');
            const provPart = inner.split('/')[0].split('_')[0];
            const guess = nearest(provPart);
            const hint = guess ? ` — did you mean \${${guess}/…}?` : '';
            issues.push({
              severity: 'high',
              provider: `${p.name} / ${c.name}`,
              msg: `Stale ref ${f.value}${hint}`,
            });
          }
        });
      });
    });

    // Orphan detection — entry assigned to a project but no chunk in it references the entry
    const refNames = new Set<string>();
    st.vault.projects.forEach((p) =>
      (p.chunks || []).forEach((c) =>
        c.fields.forEach((f) => {
          const m = /^\$\{(.+?)(?:\/.+)?\}$/.exec(f.value);
          if (m) refNames.add(m[1]);
        }),
      ),
    );
    keys.forEach((k) => {
      const realProjects = (k.projectIds || []).filter((id) => id !== 'Universal');
      if (!realProjects.length) return;
      const provRef = k.key_id ? `${k.provider}_${k.key_id}` : k.provider;
      if (!refNames.has(k.provider) && !refNames.has(provRef)) {
        issues.push({
          severity: 'low',
          provider: k.provider || '?',
          msg: 'In a project but no chunk references it',
        });
      }
    });

    timeEl.textContent = `Scanned ${keys.length} secrets · ${new Date().toLocaleTimeString()}`;

    if (!issues.length) {
      results.innerHTML = `<div class="health-ok">✓ No issues found — vault looks healthy!</div>`;
      return;
    }

    const grouped = {
      high: issues.filter((i) => i.severity === 'high'),
      med: issues.filter((i) => i.severity === 'med'),
      low: issues.filter((i) => i.severity === 'low'),
    };
    // provider and msg both embed user-controlled data (entry/project/chunk names)
    // and are injected via innerHTML — escape them.
    const renderGroup = (label: string, cls: string, items: typeof issues) =>
      items.length
        ? `
      <div class="health-group">
        <div class="health-group-title ${cls}">${label} (${items.length})</div>
        ${items.map((i) => `<div class="health-row"><span class="health-provider">${esc(i.provider)}</span><span class="health-msg">${esc(i.msg)}</span></div>`).join('')}
      </div>`
        : '';

    results.innerHTML =
      renderGroup('Critical', 'health-high', grouped.high) +
      renderGroup('Warning', 'health-med', grouped.med) +
      renderGroup('Info', 'health-low', grouped.low);
  });

  // ── Import tool (item 9) ───────────────────────────────────────────────────

  let _importFormat = 'env';
  let _importData: any[] = [];

  document.querySelectorAll<HTMLButtonElement>('.import-fmt-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.import-fmt-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      _importFormat = btn.dataset.fmt!;
    });
  });

  document.getElementById('import-file-btn')?.addEventListener('click', () => {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = '.env,.json,.csv,.txt';
    inp.onchange = () => {
      const f = inp.files?.[0];
      if (!f) return;
      document.getElementById('import-file-name')!.textContent = f.name;
      const reader = new FileReader();
      reader.onload = (e) => {
        const raw = String(e.target?.result ?? '');
        _importData = parseImport(raw, _importFormat);
        const preview = document.getElementById('import-preview')!;
        const previewText = document.getElementById('import-preview-text')!;
        preview.style.display = _importData.length ? 'block' : 'none';
        previewText.textContent =
          `Found ${_importData.length} entries:\n` +
          _importData
            .slice(0, 5)
            .map((e) => `  ${e.provider}: ${e.api_key?.slice(0, 20)}…`)
            .join('\n') +
          (_importData.length > 5 ? `\n  … +${_importData.length - 5} more` : '');
        const confirmBtn = document.getElementById('import-confirm-btn')!;
        confirmBtn.style.display = _importData.length ? '' : 'none';
      };
      reader.readAsText(f);
    };
    document.body.appendChild(inp);
    inp.click();
    inp.remove();
  });

  document.getElementById('import-confirm-btn')?.addEventListener('click', async () => {
    if (!_importData.length) return;
    // Capture the count *before* clearing the buffer — the toast used to read
    // _importData.length after the reset and so always said "all entries".
    const usable = _importData.map(normalizeImported).filter((e): e is VaultEntry => e !== null);
    const count = usable.length;
    const skipped = _importData.length - count;
    if (!count) {
      showToast('Nothing importable — every entry was missing a provider name', 'err', 4000);
      return;
    }
    st.vault.api_keys.push(...usable);
    ensureEntryIds(st.vault.api_keys);
    await persist();
    render();
    document.getElementById('import-status')!.textContent =
      `✓ Imported ${count} entries` +
      (skipped ? ` · skipped ${skipped} with no provider name` : '');
    _importData = [];
    document.getElementById('import-confirm-btn')!.style.display = 'none';
    document.getElementById('import-preview')!.style.display = 'none';
    showToast(`Imported ${count} ${count === 1 ? 'entry' : 'entries'}`, 'ok');
  });

  // ── Templates (item 23) ────────────────────────────────────────────────────

  const templateGrid = document.getElementById('template-grid');
  if (templateGrid) {
    templateGrid.innerHTML = SECRET_TEMPLATES.map(
      (t) => `
      <button class="template-card" data-tpl-id="${t.id}">
        <div class="template-icon">${t.icon.slice(0, 2).toUpperCase()}</div>
        <div class="template-info">
          <div class="template-name">${t.name}</div>
          <div class="template-cat">${t.category}</div>
        </div>
      </button>
    `,
    ).join('');
    templateGrid.addEventListener('click', (e) => {
      const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('[data-tpl-id]');
      if (!btn) return;
      const tpl = SECRET_TEMPLATES.find((t) => t.id === btn.dataset.tplId);
      if (!tpl) return;
      switchPanel('secrets');
      setTimeout(() => {
        fillForm({ ...tpl.defaults, secretType: tpl.secretType } as any);
        buildCatChips([]);
        openModal('Add Secret', -1);
      }, 100);
    });
  }

  // ── Bulk operations (item 8) ───────────────────────────────────────────────

  const bulkSelectBtn = document.getElementById('bulk-select-btn')!;
  const bulkBar = document.getElementById('bulk-bar')!;
  const bulkCount = document.getElementById('bulk-count')!;

  function updateBulkCount() {
    bulkCount.textContent = `${st.bulkSelected.size} selected`;
  }

  function enterBulkMode() {
    st.bulkMode = true;
    st.bulkSelected.clear();
    bulkSelectBtn.textContent = 'Exit Select';
    bulkBar.classList.add('active');
    document.getElementById('card-grid')?.classList.add('bulk-mode');
    updateBulkCount();
  }

  function exitBulkMode() {
    st.bulkMode = false;
    st.bulkSelected.clear();
    bulkSelectBtn.textContent = 'Select';
    bulkBar.classList.remove('active');
    document.getElementById('card-grid')?.classList.remove('bulk-mode');
    render();
  }

  /** Selected entries, resolved fresh from ids at the moment of the action. */
  function selectedEntries() {
    return st.vault.api_keys.filter((e) => e.id && st.bulkSelected.has(e.id));
  }

  bulkSelectBtn.addEventListener('click', () => (st.bulkMode ? exitBulkMode() : enterBulkMode()));
  document.getElementById('bulk-cancel-btn')?.addEventListener('click', exitBulkMode);

  document.getElementById('bulk-delete-btn')?.addEventListener('click', async () => {
    if (!st.bulkSelected.size) return;
    if (
      !(await showConfirm(
        `Delete ${st.bulkSelected.size} selected secrets? This cannot be undone.`,
      ))
    )
      return;
    // Filter by identity rather than splicing positions: the selection is a set
    // of ids, so nothing that reordered the array since ticking can misdirect
    // the delete.
    const doomed = new Set(st.bulkSelected);
    const before = st.vault.api_keys.length;
    st.vault.api_keys = st.vault.api_keys.filter((e) => !(e.id && doomed.has(e.id)));
    const removed = before - st.vault.api_keys.length;
    for (const id of doomed) {
      st.expanded.delete(id);
      delete st.revealed[`key-${id}`];
      delete st.revealed[`secret-${id}`];
    }
    await persist();
    exitBulkMode();
    render();
    showToast(`Deleted ${removed} secrets`, 'ok');
  });

  document.getElementById('bulk-export-btn')?.addEventListener('click', async () => {
    const selected = selectedEntries();
    if (!selected.length) {
      showToast('Nothing selected', 'err');
      return;
    }
    // Writing secrets to an unencrypted file on disk deserves a prompt.
    if (
      !(await showConfirm(
        `Write ${selected.length} secret${selected.length === 1 ? '' : 's'} to an unencrypted export.env file?`,
      ))
    )
      return;
    const lines = selected
      .map((e) => {
        const key = (e.provider || 'UNKNOWN').toUpperCase().replace(/[^A-Z0-9]/g, '_');
        return `${key}=${e.api_key}`;
      })
      .join('\n');
    const blob = new Blob([lines], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: 'export.env' });
    // The anchor has to be in the document, and the object URL has to outlive
    // the click — revoking synchronously cancelled the download in WebKitGTK.
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  });

  // Expose bulk toggle to card clicks
  (window as any).__envvBulkToggle = (idx: number) => {
    if (!st.bulkMode) return false;
    const entry = st.vault.api_keys[idx];
    if (!entry) return true;
    const id = entryId(entry);
    if (st.bulkSelected.has(id)) st.bulkSelected.delete(id);
    else st.bulkSelected.add(id);
    updateBulkCount();
    document
      .querySelector<HTMLElement>(`[data-idx="${idx}"]`)
      ?.classList.toggle('bulk-selected', st.bulkSelected.has(id));
    return true;
  };
  (window as any).__envvIsBulkMode = () => st.bulkMode;

  // ── SECRET DIFF ────────────────────────────────────────────────────────────

  const refreshDiffSelects = () => {
    // Option values are entry ids, not array positions. The selects are only
    // rebuilt when the Diff tool is opened, so a delete elsewhere in the app
    // used to leave stale positions behind and diff two unrelated secrets.
    ensureEntryIds(st.vault.api_keys);
    const opts =
      `<option value="">Select secret…</option>` +
      st.vault.api_keys
        .map(
          (e) =>
            `<option value="${esc(entryId(e))}">${esc(e.provider)}${e.account_name ? ' / ' + esc(e.account_name) : ''}</option>`,
        )
        .join('');
    const da = document.getElementById('diff-a') as HTMLSelectElement | null;
    const db = document.getElementById('diff-b') as HTMLSelectElement | null;
    if (da) da.innerHTML = opts;
    if (db) db.innerHTML = opts;
  };
  refreshDiffSelects();
  document.getElementById('diff-run')?.addEventListener('click', () => {
    const aId = (document.getElementById('diff-a') as HTMLSelectElement).value;
    const bId = (document.getElementById('diff-b') as HTMLSelectElement).value;
    if (!aId || !bId || aId === bId) {
      showToast('Select two different entries', 'err');
      return;
    }
    const a = st.vault.api_keys.find((e) => entryId(e) === aId);
    const b = st.vault.api_keys.find((e) => entryId(e) === bId);
    if (!a || !b) {
      showToast('That secret no longer exists — reopen the Diff tool', 'err');
      refreshDiffSelects();
      return;
    }
    const fields: [string, string][] = [
      ['provider', 'Provider'],
      ['account_name', 'Account'],
      ['api_key', 'Key (masked)'],
      ['api_secret', 'Secret'],
      ['key_id', 'Label'],
      ['price_type', 'Price'],
      ['environment', 'Environment'],
      ['api_url', 'API URL'],
      ['expires_at', 'Expires'],
      ['rate_limit', 'Rate Limit'],
      ['version', 'Version'],
      ['api_description', 'Description'],
    ];
    const esc2 = (s: string) =>
      s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const rows = fields
      .map(([f, label]) => {
        const av = String((a as any)[f] || '');
        const bv = String((b as any)[f] || '');
        const isSec = f === 'api_key' || f === 'api_secret';
        const av2 = isSec && av ? '••••••••' : esc2(av);
        const bv2 = isSec && bv ? '••••••••' : esc2(bv);
        const changed = av !== bv;
        return `<tr class="${changed ? 'diff-changed' : 'diff-same'}">
        <td class="diff-field">${label}</td>
        <td class="diff-val">${av2 || '<em style="color:var(--text3)">—</em>'}</td>
        <td class="diff-val">${bv2 || '<em style="color:var(--text3)">—</em>'}</td>
      </tr>`;
      })
      .join('');
    document.getElementById('diff-output')!.innerHTML = `
      <table class="diff-table">
        <thead><tr><th>Field</th><th>${esc2(a.provider)}</th><th>${esc2(b.provider)}</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  });

  // ── EXPIRY CALENDAR ────────────────────────────────────────────────────────

  let _calYear = new Date().getFullYear();
  let _calMonth = new Date().getMonth();

  const renderCalendar = () => {
    const label = document.getElementById('cal-month-label')!;
    const grid = document.getElementById('cal-grid')!;
    if (!label || !grid) return;
    const monthName = new Date(_calYear, _calMonth, 1).toLocaleString('default', {
      month: 'long',
      year: 'numeric',
    });
    label.textContent = monthName;

    const firstDay = new Date(_calYear, _calMonth, 1).getDay();
    const daysInMonth = new Date(_calYear, _calMonth + 1, 0).getDate();
    const today = new Date().toISOString().slice(0, 10);
    const warn30 = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);

    const byDate = new Map<string, string[]>();
    st.vault.api_keys.forEach((e) => {
      if (!e.expires_at) return;
      const d = e.expires_at.slice(0, 10);
      const [y, m] = d.split('-').map(Number);
      if (y === _calYear && m === _calMonth + 1) {
        if (!byDate.has(d)) byDate.set(d, []);
        byDate.get(d)!.push(e.provider);
      }
    });

    let html = '<div class="cal-header">';
    ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'].forEach((d) => {
      html += `<div class="cal-day-name">${d}</div>`;
    });
    html += '</div><div class="cal-body">';
    for (let i = 0; i < firstDay; i++) html += '<div class="cal-cell empty"></div>';
    for (let d = 1; d <= daysInMonth; d++) {
      const ds = `${_calYear}-${String(_calMonth + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
      const entries = byDate.get(ds) || [];
      const isPast = ds < today;
      const isWarn = !isPast && ds <= warn30;
      const isToday = ds === today;
      let cls = 'cal-cell';
      if (isToday) cls += ' cal-today';
      if (entries.length) cls += isPast ? ' cal-expired' : isWarn ? ' cal-warn' : ' cal-safe';
      const title =
        entries.slice(0, 5).join(', ') + (entries.length > 5 ? ` +${entries.length - 5}` : '');
      const dots = entries
        .slice(0, 4)
        .map(() => `<span class="cal-entry-dot"></span>`)
        .join('');
      html += `<div class="${cls}" title="${title}">
        <span class="cal-day-num">${d}</span>
        ${entries.length ? `<div class="cal-entries">${dots}${entries.length > 4 ? `<span class="cal-extra">+${entries.length - 4}</span>` : ''}</div>` : ''}
      </div>`;
    }
    html += '</div>';
    grid.innerHTML = html;
  };
  document.getElementById('cal-prev')?.addEventListener('click', () => {
    _calMonth--;
    if (_calMonth < 0) {
      _calMonth = 11;
      _calYear--;
    }
    renderCalendar();
  });
  document.getElementById('cal-next')?.addEventListener('click', () => {
    _calMonth++;
    if (_calMonth > 11) {
      _calMonth = 0;
      _calYear++;
    }
    renderCalendar();
  });
  // Render immediately if calendar tool is already active on init
  if (Settings.get('activeTool') === 'expiry-calendar') setTimeout(renderCalendar, 50);

  // ── CRON EXPLAINER ─────────────────────────────────────────────────────────

  const CRON_NAMED: Record<string, string> = {
    '@yearly': '0 0 1 1 *',
    '@annually': '0 0 1 1 *',
    '@monthly': '0 0 1 * *',
    '@weekly': '0 0 * * 0',
    '@daily': '0 0 * * *',
    '@midnight': '0 0 * * *',
    '@hourly': '0 * * * *',
    '@reboot': 'at system reboot',
  };
  // 1-indexed so MONTHS[n] works directly for cron month values 1..12. The old
  // 0-indexed table made every month name off by one (month 1 displayed "Feb").
  const MONTHS = [
    '',
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ];
  const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

  /**
   * Expand one cron field into the exact set of values it matches.
   * Handles wildcards, ranges (`a-b`), lists (`a,b,c`) and steps (`a-b/n`,
   * `a/n`, wildcard-with-step), in any combination.
   * Returns null when the field is malformed or out of range.
   */
  function cronFieldSet(spec: string, min: number, max: number): Set<number> | null {
    const out = new Set<number>();
    for (const part of spec.split(',')) {
      if (!part) return null;
      const [rangePart, stepPart] = part.split('/');
      const step = stepPart === undefined ? 1 : parseInt(stepPart, 10);
      if (!Number.isInteger(step) || step < 1) return null;
      let lo: number, hi: number;
      if (rangePart === '*' || rangePart === '?') {
        lo = min;
        hi = max;
      } else if (rangePart.includes('-')) {
        const [a, b] = rangePart.split('-').map((n) => parseInt(n, 10));
        if (!Number.isInteger(a) || !Number.isInteger(b)) return null;
        lo = a;
        hi = b;
      } else {
        const v = parseInt(rangePart, 10);
        if (!Number.isInteger(v)) return null;
        lo = v;
        // Bare "5/10" means "from 5, every 10, up to max" — not just "5".
        hi = stepPart === undefined ? v : max;
      }
      if (lo < min || hi > max || lo > hi) return null;
      for (let v = lo; v <= hi; v += step) out.add(v);
    }
    return out.size ? out : null;
  }

  function explainField(
    val: string,
    unit: string,
    min: number,
    max: number,
    names?: string[],
  ): string {
    if (val === '*' || val === '?') return `every ${unit}`;
    const set = cronFieldSet(val, min, max);
    if (!set) return `invalid (${val})`;
    const vals = [...set].sort((a, b) => a - b);
    if (vals.length === max - min + 1) return `every ${unit}`;
    const label = (n: number) => names?.[n] ?? String(n);
    if (vals.length > 12) {
      return `${vals.length} values (${label(vals[0])} … ${label(vals[vals.length - 1])})`;
    }
    return vals.map(label).join(', ');
  }

  /**
   * Next `count` fire times for a 5-field cron expression.
   *
   * Walks forward skipping whole months/days/hours that cannot match, instead of
   * testing 10 000 consecutive minutes one at a time — the old version could not
   * see past ~7 days and so returned nothing at all for anything monthly or rarer.
   */
  function nextFireTimes(expr: string, count = 5): string[] {
    const parts = expr.trim().split(/\s+/);
    if (parts.length !== 5) return [];
    const [minP, hrP, domP, monP, dowP] = parts;

    const mins = cronFieldSet(minP, 0, 59);
    const hours = cronFieldSet(hrP, 0, 23);
    const doms = cronFieldSet(domP, 1, 31);
    const mons = cronFieldSet(monP, 1, 12);
    const dows = cronFieldSet(dowP, 0, 7);
    if (!mins || !hours || !doms || !mons || !dows) return [];
    if (dows.has(7)) dows.add(0); // cron accepts both 0 and 7 for Sunday

    // POSIX rule: when day-of-month AND day-of-week are both restricted, a day
    // matches if EITHER matches (union, not intersection).
    const domRestricted = domP !== '*' && domP !== '?';
    const dowRestricted = dowP !== '*' && dowP !== '?';

    const results: string[] = [];
    const cur = new Date();
    cur.setSeconds(0, 0);
    cur.setMinutes(cur.getMinutes() + 1);
    const limit = new Date(cur);
    limit.setFullYear(limit.getFullYear() + 5); // e.g. "0 0 29 2 *" is up to 4 years out

    while (results.length < count && cur < limit) {
      if (!mons.has(cur.getMonth() + 1)) {
        cur.setMonth(cur.getMonth() + 1, 1);
        cur.setHours(0, 0, 0, 0);
        continue;
      }
      const dayOk =
        domRestricted && dowRestricted
          ? doms.has(cur.getDate()) || dows.has(cur.getDay())
          : (!domRestricted || doms.has(cur.getDate())) &&
            (!dowRestricted || dows.has(cur.getDay()));
      if (!dayOk) {
        cur.setDate(cur.getDate() + 1);
        cur.setHours(0, 0, 0, 0);
        continue;
      }
      if (!hours.has(cur.getHours())) {
        cur.setHours(cur.getHours() + 1, 0, 0, 0);
        continue;
      }
      if (!mins.has(cur.getMinutes())) {
        cur.setMinutes(cur.getMinutes() + 1);
        continue;
      }
      results.push(cur.toLocaleString());
      cur.setMinutes(cur.getMinutes() + 1);
    }
    return results;
  }

  document.getElementById('cron-parse')?.addEventListener('click', () => {
    const raw = (document.getElementById('cron-input') as HTMLInputElement).value.trim();
    const output = document.getElementById('cron-output')!;
    if (!raw) {
      showToast('Enter a cron expression', 'err');
      return;
    }

    if (CRON_NAMED[raw] === 'at system reboot') {
      output.style.display = '';
      output.innerHTML = `<div class="cron-result"><div class="cron-resolved">@reboot — runs once when system starts</div></div>`;
      return;
    }

    const resolved = CRON_NAMED[raw] || raw;
    const parts = resolved.split(/\s+/);
    if (parts.length !== 5) {
      output.style.display = '';
      output.innerHTML = `<div class="cron-result"><div class="tool-status err">Invalid: expected 5 fields (min hr dom mon dow)</div></div>`;
      return;
    }

    const [min, hr, dom, mon, dow] = parts;
    const lines = [
      `Minute:  ${explainField(min, 'minute', 0, 59)}`,
      `Hour:    ${explainField(hr, 'hour', 0, 23)}`,
      `Day:     ${explainField(dom, 'day', 1, 31)}`,
      `Month:   ${explainField(mon, 'month', 1, 12, MONTHS)}`,
      `Weekday: ${explainField(dow, 'weekday', 0, 7, DAYS)}`,
    ];

    const fires = nextFireTimes(resolved);
    const nextBlock = fires.length
      ? `<div style="margin-top:10px"><div class="tool-label" style="margin-bottom:6px">Next ${fires.length} fire times</div>${fires.map((f) => `<div style="font-size:11px;color:var(--text2);padding:2px 0">${f}</div>`).join('')}</div>`
      : '';

    output.style.display = '';
    output.innerHTML = `<div class="cron-result">
      ${resolved !== raw ? `<div class="cron-resolved"><code>${raw}</code> → <code>${resolved}</code></div>` : ''}
      <pre class="tool-pre" style="margin-top:8px">${lines.join('\n')}</pre>
      ${nextBlock}
    </div>`;
  });

  // ── CIDR CALCULATOR ────────────────────────────────────────────────────────

  function calcCidr(cidr: string): {
    network: string;
    broadcast: string;
    first: string;
    last: string;
    mask: string;
    hosts: number;
  } | null {
    const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(cidr);
    if (!m) return null;
    const prefix = parseInt(m[2]);
    if (prefix > 32) return null;
    const ipParts = m[1].split('.').map(Number);
    if (ipParts.some((p) => p > 255)) return null;
    const ip32 = ipParts.reduce((acc, v) => acc * 256 + v, 0) >>> 0;
    const mask32 = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const net32 = (ip32 & mask32) >>> 0;
    const bc32 = (net32 | (~mask32 >>> 0)) >>> 0;
    const toStr = (n: number) =>
      [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
    const hosts = prefix >= 31 ? (prefix === 32 ? 1 : 2) : Math.pow(2, 32 - prefix) - 2;
    return {
      network: toStr(net32),
      broadcast: toStr(bc32),
      first: toStr(prefix >= 31 ? net32 : net32 + 1),
      last: toStr(prefix >= 31 ? bc32 : bc32 - 1),
      mask: toStr(mask32),
      hosts,
    };
  }

  document.getElementById('cidr-calc')?.addEventListener('click', () => {
    const input = (document.getElementById('cidr-input') as HTMLInputElement).value.trim();
    const output = document.getElementById('cidr-output')!;
    const result = calcCidr(input);
    if (!result) {
      output.style.display = 'none';
      showToast('Invalid CIDR — use format 192.168.1.0/24', 'err');
      return;
    }
    output.style.display = '';
    output.innerHTML = `<table class="cidr-table">
      <tr><td class="cidr-key">Network</td><td class="cidr-val">${result.network}/${input.split('/')[1]}</td></tr>
      <tr><td class="cidr-key">Broadcast</td><td class="cidr-val">${result.broadcast}</td></tr>
      <tr><td class="cidr-key">First host</td><td class="cidr-val">${result.first}</td></tr>
      <tr><td class="cidr-key">Last host</td><td class="cidr-val">${result.last}</td></tr>
      <tr><td class="cidr-key">Subnet mask</td><td class="cidr-val">${result.mask}</td></tr>
      <tr><td class="cidr-key">Usable hosts</td><td class="cidr-val">${result.hosts.toLocaleString()}</td></tr>
    </table>`;
  });

  // Enter key submits CIDR
  document.getElementById('cidr-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('cidr-calc')?.click();
  });
  document.getElementById('cron-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('cron-parse')?.click();
  });

  // ── JSON / YAML FORMATTER ──────────────────────────────────────────────────

  let _fmtMode = 'json';
  document.querySelectorAll<HTMLButtonElement>('.tool-fmt-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-fmt-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      _fmtMode = btn.dataset.fmt!;
    });
  });

  const setFmtStatus = (msg: string, type: 'ok' | 'err' | 'warn') => {
    const el = document.getElementById('fmt-status')!;
    el.className = `tool-status ${type}`;
    el.textContent = msg;
    el.style.display = '';
  };

  const showFmtOutput = (text: string) => {
    const out = document.getElementById('fmt-output') as HTMLTextAreaElement;
    out.value = text;
    out.style.display = '';
    document.getElementById('fmt-copy-row')!.style.display = '';
  };

  document.getElementById('fmt-format')?.addEventListener('click', () => {
    const input = (document.getElementById('fmt-input') as HTMLTextAreaElement).value;
    if (!input.trim()) {
      showToast('Enter text to format', 'err');
      return;
    }
    document.getElementById('fmt-output')!.style.display = 'none';
    document.getElementById('fmt-copy-row')!.style.display = 'none';
    if (_fmtMode === 'json') {
      try {
        const formatted = JSON.stringify(JSON.parse(input), null, 2);
        showFmtOutput(formatted);
        setFmtStatus(`Valid JSON — ${formatted.split('\n').length} lines`, 'ok');
      } catch (e: any) {
        setFmtStatus(`JSON parse error: ${e.message}`, 'err');
      }
    } else {
      try {
        const parsed = yaml.load(input);
        const formatted = yaml.dump(parsed, { indent: 2, lineWidth: 120 });
        showFmtOutput(formatted);
        setFmtStatus(`Valid YAML — ${formatted.split('\n').length} lines`, 'ok');
      } catch (e: any) {
        setFmtStatus(`YAML parse error: ${e.message}`, 'err');
      }
    }
  });

  document.getElementById('fmt-validate')?.addEventListener('click', () => {
    const input = (document.getElementById('fmt-input') as HTMLTextAreaElement).value;
    if (!input.trim()) {
      showToast('Enter text to validate', 'err');
      return;
    }
    if (_fmtMode === 'json') {
      try {
        JSON.parse(input);
        setFmtStatus('Valid JSON ✓', 'ok');
      } catch (e: any) {
        setFmtStatus(`Invalid JSON: ${e.message}`, 'err');
      }
    } else {
      try {
        yaml.load(input);
        setFmtStatus('Valid YAML ✓', 'ok');
      } catch (e: any) {
        setFmtStatus(`Invalid YAML: ${e.message}`, 'err');
      }
    }
  });

  document.getElementById('fmt-minify')?.addEventListener('click', () => {
    const input = (document.getElementById('fmt-input') as HTMLTextAreaElement).value;
    if (!input.trim()) {
      showToast('Enter text to minify', 'err');
      return;
    }
    document.getElementById('fmt-output')!.style.display = 'none';
    document.getElementById('fmt-copy-row')!.style.display = 'none';
    if (_fmtMode === 'json') {
      try {
        showFmtOutput(JSON.stringify(JSON.parse(input)));
        setFmtStatus('Minified ✓', 'ok');
      } catch (e: any) {
        setFmtStatus(`JSON parse error: ${e.message}`, 'err');
      }
    } else {
      // YAML minify: round-trip through js-yaml with flow style
      try {
        const parsed = yaml.load(input);
        const minified = yaml.dump(parsed, { flowLevel: 0 }).trimEnd();
        showFmtOutput(minified);
        setFmtStatus('YAML minified (flow style) ✓', 'ok');
      } catch (e: any) {
        setFmtStatus(`YAML parse error: ${e.message}`, 'err');
      }
    }
  });

  document.getElementById('fmt-copy')?.addEventListener('click', () => {
    const v = (document.getElementById('fmt-output') as HTMLTextAreaElement).value;
    if (v) clipboardWrite(v).then(() => showToast('Copied ✓', 'ok', 1500));
  });
}
