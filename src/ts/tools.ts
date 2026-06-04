/**
 * @file Tools panel — secret generator, password generator, UUID/ULID,
 *       API key patterns, hash generator, JWT validator, cert gen, SSH keygen,
 *       string tools, base64.
 */

import { Settings, switchPanel, switchTool } from './state';
import { showToast, clipboardWrite, generateULID } from './utils';
import { showDropdown, injectIntoForm, quickGenerate } from './modals';

export function initTools() {
  const invoke = (window as any).__TAURI__?.core?.invoke?.bind((window as any).__TAURI__?.core);

  // ── Activity bar panel switching ──
  document.querySelectorAll<HTMLButtonElement>('.activity-btn').forEach(btn => {
    btn.addEventListener('click', () => switchPanel(btn.dataset.panel as 'secrets' | 'tools'));
  });

  // ── Tool nav switching ──
  document.querySelectorAll<HTMLButtonElement>('.tool-nav-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTool(btn.dataset.tool!));
  });

  // ── Section collapse toggles ──
  document.querySelectorAll<HTMLButtonElement>('.section-collapse-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const section = btn.dataset.section as 'all' | 'price' | 'category' | 'project';
      const el = document.getElementById(`sidebar-section-${section}`)!;
      el.classList.toggle('collapsed');
      const collapsed = (Settings.get('collapsedSections') || []) as ('all' | 'price' | 'category' | 'project')[];
      const isNowCollapsed = el.classList.contains('collapsed');
      const updated = isNowCollapsed
        ? [...new Set([...collapsed, section])]
        : collapsed.filter(s => s !== section);
      Settings.set('collapsedSections', updated as any);
    });
  });

  // Restore active panel & tool from settings
  const activePanel = (Settings.get('activePanel') || 'secrets') as 'secrets' | 'tools';
  const activeTool = Settings.get('activeTool') || 'secret-gen';
  switchPanel(activePanel);
  switchTool(activeTool);

  // ── SECRET GENERATOR ──
  let sgBytes = 32;
  document.querySelectorAll<HTMLButtonElement>('.tool-byte-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-byte-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      sgBytes = parseInt(btn.dataset.bytes!);
    });
  });
  const sgGenerate = () => {
    const buf = new Uint8Array(sgBytes);
    crypto.getRandomValues(buf);
    const fmt = (document.getElementById('sg-format') as HTMLSelectElement).value;
    let out: string;
    if (fmt === 'hex') out = Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
    else if (fmt === 'base64url') out = btoa(String.fromCharCode(...buf)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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
  pgLength.addEventListener('input', () => { pgLenDisplay.textContent = pgLength.value; });
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
    if (!chars) { showToast('Select at least one character set', 'err'); return; }
    const buf = new Uint32Array(len);
    crypto.getRandomValues(buf);
    const pwd = Array.from(buf).map(n => chars[n % chars.length]).join('');
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
  document.querySelectorAll<HTMLButtonElement>('.tool-id-type-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-id-type-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      uuType = btn.dataset.type!;
    });
  });
  document.getElementById('uu-generate')!.addEventListener('click', () => {
    const count = parseInt((document.getElementById('uu-count') as HTMLInputElement).value) || 1;
    const lines = Array.from({ length: count }, () => uuType === 'uuid' ? crypto.randomUUID() : generateULID());
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
    const toHex = (b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
    const toB64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
    const toB64url = (b: Uint8Array) => toB64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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
  document.querySelectorAll<HTMLButtonElement>('.tool-hash-algo-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-hash-algo-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      hgAlgo = btn.dataset.algo!;
    });
  });
  document.querySelectorAll<HTMLButtonElement>('.tool-hash-fmt-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-hash-fmt-btn').forEach(b => b.classList.remove('active'));
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
    else out = Array.from(hashArr).map(b => b.toString(16).padStart(2, '0')).join('');
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
      statusEl.className = 'tool-status err'; statusEl.textContent = 'Invalid JWT: expected 3 parts'; statusEl.style.display = '';
      (document.getElementById('tv-header') as HTMLPreElement).textContent = '';
      (document.getElementById('tv-payload') as HTMLPreElement).textContent = '';
      return;
    }
    try {
      const decode = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + (4 - s.length % 4) % 4, '=')));
      const header = decode(parts[0]);
      const payload = decode(parts[1]);
      (document.getElementById('tv-header') as HTMLPreElement).textContent = JSON.stringify(header, null, 2);
      (document.getElementById('tv-payload') as HTMLPreElement).textContent = JSON.stringify(payload, null, 2);
      statusEl.style.display = '';
      if (payload.exp) {
        const exp = new Date(payload.exp * 1000);
        const now = new Date();
        if (exp < now) { statusEl.className = 'tool-status err'; statusEl.textContent = `Expired: ${exp.toISOString()}`; }
        else { statusEl.className = 'tool-status ok'; statusEl.textContent = `Valid until: ${exp.toISOString()}`; }
      } else {
        statusEl.className = 'tool-status warn'; statusEl.textContent = 'No expiry claim (exp) found';
      }
    } catch { statusEl.className = 'tool-status err'; statusEl.textContent = 'Failed to decode JWT'; statusEl.style.display = ''; }
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
  pcDays.addEventListener('input', () => { pcDaysDisplay.textContent = pcDays.value; });
  document.getElementById('pc-generate')!.addEventListener('click', async () => {
    if (!invoke) { showToast('Tauri not available', 'err'); return; }
    const cn = (document.getElementById('pc-cn') as HTMLInputElement).value.trim() || 'localhost';
    const days = parseInt(pcDays.value) || 365;
    const loading = document.getElementById('pc-loading')!;
    loading.style.display = '';
    try {
      const result: { cert_pem: string; key_pem: string } = await invoke('generate_certificate', { commonName: cn, validityDays: days });
      (document.getElementById('pc-cert-output') as HTMLTextAreaElement).value = result.cert_pem;
      (document.getElementById('pc-key-output') as HTMLTextAreaElement).value = result.key_pem;
    } catch (e) { showToast(String(e), 'err'); }
    finally { loading.style.display = 'none'; }
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
    if (!invoke) { showToast('Tauri not available', 'err'); return; }
    const comment = (document.getElementById('sk-comment') as HTMLInputElement).value.trim();
    const loading = document.getElementById('sk-loading')!;
    loading.style.display = '';
    try {
      const result: { public_key: string; private_key: string } = await invoke('generate_ssh_keypair', { comment });
      (document.getElementById('sk-pub-output') as HTMLTextAreaElement).value = result.public_key;
      (document.getElementById('sk-priv-output') as HTMLTextAreaElement).value = result.private_key;
    } catch (e) { showToast(String(e), 'err'); }
    finally { loading.style.display = 'none'; }
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
        out = input.includes('\n') || input.includes('"') || input.includes("'") || input.includes(' ')
          ? '"' + input.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r') + '"'
          : input;
      }
      else if (op === 'shell-quote') out = "'" + input.replace(/'/g, "'\\''") + "'";
      else if (op === 'json-escape') out = JSON.stringify(input).slice(1, -1);
      else if (op === 'json-unescape') out = JSON.parse('"' + input + '"');
    } catch (e) { showToast('Conversion error: ' + String(e), 'err'); return; }
    (document.getElementById('st-output') as HTMLTextAreaElement).value = out;
  });
  document.getElementById('st-copy')!.addEventListener('click', () => {
    const v = (document.getElementById('st-output') as HTMLTextAreaElement).value;
    if (v) clipboardWrite(v);
  });

  // ── BASE64 ──
  let b64Op = 'encode';
  let b64Var = 'std';
  document.querySelectorAll<HTMLButtonElement>('.tool-b64-op-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-b64-op-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      b64Op = btn.dataset.op!;
    });
  });
  document.querySelectorAll<HTMLButtonElement>('.tool-b64-var-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-b64-var-btn').forEach(b => b.classList.remove('active'));
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
        if (b64Var === 'url') encoded = encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        out = encoded;
      } else {
        let normalized = input;
        if (b64Var === 'url') normalized = input.replace(/-/g, '+').replace(/_/g, '/');
        out = decodeURIComponent(escape(atob(normalized)));
      }
    } catch (e) { showToast('Base64 error: ' + String(e), 'err'); return; }
    (document.getElementById('b64-output') as HTMLTextAreaElement).value = out;
  });
  document.getElementById('b64-copy')!.addEventListener('click', () => {
    const v = (document.getElementById('b64-output') as HTMLTextAreaElement).value;
    if (v) clipboardWrite(v);
  });
}
