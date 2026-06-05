/**
 * @file Tools panel — secret generator, password generator, UUID/ULID,
 *       API key patterns, hash generator, JWT validator, cert gen, SSH keygen,
 *       string tools, base64.
 */

import { Settings, switchPanel, switchTool, st } from './state';
import { showToast, clipboardWrite, generateULID, showConfirm } from './utils';
import { showDropdown, injectIntoForm, quickGenerate, openAdd, fillForm, buildCatChips, openModal } from './modals';
import { SECRET_TEMPLATES } from './templates';

function parseImport(raw: string, fmt: string): any[] {
  const base = (p: string, v: string) => ({
    provider: p, api_key: v, price_type: 'local', secretType: 'env_var',
    categories: [], projectIds: ['Universal'], scopes: [],
  });

  if (fmt === 'env') {
    return raw.split('\n').flatMap(line => {
      const t = line.trim();
      if (!t || t.startsWith('#')) return [];
      const eq = t.indexOf('=');
      if (eq < 1) return [];
      const key = t.slice(0, eq).trim();
      const val = t.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
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
        price_type: 'paid', secretType: 'password',
        categories: [], projectIds: ['Universal'], scopes: [],
        description: item.notes ?? null,
      }));
    } catch { return []; }
  }

  if (fmt === '1password') {
    try {
      const items = JSON.parse(raw);
      return (Array.isArray(items) ? items : []).map((item: any) => {
        const pw = item.fields?.find((f: any) => f.designation === 'password' || f.id === 'password');
        const user = item.fields?.find((f: any) => f.designation === 'username' || f.id === 'username');
        return {
          provider: item.title || 'Unknown',
          account_name: user?.value ?? null,
          api_key: pw?.value ?? '',
          price_type: 'paid', secretType: 'password',
          categories: item.tags ?? [], projectIds: ['Universal'], scopes: [],
        };
      });
    } catch { return []; }
  }

  if (fmt === 'json') {
    try {
      const data = JSON.parse(raw);
      const items = Array.isArray(data) ? data : data.api_keys ?? [];
      return items;
    } catch { return []; }
  }

  return [];
}

export function initTools() {
  const invoke = (window as any).__TAURI__?.core?.invoke?.bind((window as any).__TAURI__?.core);

  // ── Activity bar panel switching ──
  document.querySelectorAll<HTMLButtonElement>('.activity-btn').forEach(btn => {
    btn.addEventListener('click', () => switchPanel(btn.dataset.panel as 'secrets' | 'tools' | 'users'));
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
  const activePanel = (Settings.get('activePanel') || 'secrets') as 'secrets' | 'tools' | 'users';
  const activeTool = Settings.get('activeTool') || 'secret-gen';
  switchPanel(activePanel === 'users' ? 'secrets' : activePanel); // don't restore users panel on init
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

  // ── Health Dashboard (item 7) ──────────────────────────────────────────────

  document.getElementById('health-scan-btn')?.addEventListener('click', () => {
    const results = document.getElementById('health-results')!;
    const timeEl  = document.getElementById('health-scan-time')!;
    const keys    = st.vault.api_keys;

    const now    = Date.now();
    const today  = new Date().toISOString().slice(0, 10);
    const warn30 = new Date(now + 30 * 86_400_000).toISOString().slice(0, 10);

    const issues: Array<{ severity: 'high' | 'med' | 'low'; msg: string; provider: string }> = [];

    keys.forEach(k => {
      const prov = k.provider || '?';
      // Weak password (entropy estimate): length < 12 and not a token pattern
      if ((k.secretType === 'password' || k.secretType === 'api_key') && k.api_key.length < 12 && !/^[A-Za-z0-9_-]{20,}$/.test(k.api_key)) {
        issues.push({ severity: 'high', provider: prov, msg: 'Short or weak secret value (< 12 chars)' });
      }
      // Expired
      if (k.expires_at && k.expires_at.slice(0, 10) < today) {
        issues.push({ severity: 'high', provider: prov, msg: `Expired on ${k.expires_at.slice(0, 10)}` });
      }
      // Expiring soon
      else if (k.expires_at && k.expires_at.slice(0, 10) <= warn30) {
        issues.push({ severity: 'med', provider: prov, msg: `Expiring ${k.expires_at.slice(0, 10)}` });
      }
      // Never rotated
      if (!k.last_rotated_at && !k.version_history?.length) {
        issues.push({ severity: 'low', provider: prov, msg: 'Never rotated' });
      }
      // No description
      if (!k.api_description && !k.description) {
        issues.push({ severity: 'low', provider: prov, msg: 'No description — hard to identify later' });
      }
    });

    timeEl.textContent = `Scanned ${keys.length} secrets · ${new Date().toLocaleTimeString()}`;

    if (!issues.length) {
      results.innerHTML = `<div class="health-ok">✓ No issues found — vault looks healthy!</div>`;
      return;
    }

    const grouped = { high: issues.filter(i => i.severity === 'high'), med: issues.filter(i => i.severity === 'med'), low: issues.filter(i => i.severity === 'low') };
    const renderGroup = (label: string, cls: string, items: typeof issues) => items.length ? `
      <div class="health-group">
        <div class="health-group-title ${cls}">${label} (${items.length})</div>
        ${items.map(i => `<div class="health-row"><span class="health-provider">${i.provider}</span><span class="health-msg">${i.msg}</span></div>`).join('')}
      </div>` : '';

    results.innerHTML = renderGroup('Critical', 'health-high', grouped.high) +
                        renderGroup('Warning',  'health-med',  grouped.med)  +
                        renderGroup('Info',     'health-low',  grouped.low);
  });

  // ── Import tool (item 9) ───────────────────────────────────────────────────

  let _importFormat = 'env';
  let _importData: any[] = [];

  document.querySelectorAll<HTMLButtonElement>('.import-fmt-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.import-fmt-btn').forEach(b => b.classList.remove('active'));
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
      reader.onload = e => {
        const raw = String(e.target?.result ?? '');
        _importData = parseImport(raw, _importFormat);
        const preview = document.getElementById('import-preview')!;
        const previewText = document.getElementById('import-preview-text')!;
        preview.style.display = _importData.length ? 'block' : 'none';
        previewText.textContent = `Found ${_importData.length} entries:\n` + _importData.slice(0, 5).map(e => `  ${e.provider}: ${e.api_key?.slice(0, 20)}…`).join('\n') + (_importData.length > 5 ? `\n  … +${_importData.length - 5} more` : '');
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
    st.vault.api_keys.push(..._importData);
    await (st.store as any).save(st.vault).catch(() => {});
    import('./render').then(m => m.render());
    document.getElementById('import-status')!.textContent = `✓ Imported ${_importData.length} entries`;
    _importData = [];
    document.getElementById('import-confirm-btn')!.style.display = 'none';
    document.getElementById('import-preview')!.style.display = 'none';
    showToast(`Imported ${_importData.length || 'all'} entries`, 'ok');
  });

  // ── Templates (item 23) ────────────────────────────────────────────────────

  const templateGrid = document.getElementById('template-grid');
  if (templateGrid) {
    templateGrid.innerHTML = SECRET_TEMPLATES.map(t => `
      <button class="template-card" data-tpl-id="${t.id}">
        <div class="template-icon">${t.icon.slice(0, 2).toUpperCase()}</div>
        <div class="template-info">
          <div class="template-name">${t.name}</div>
          <div class="template-cat">${t.category}</div>
        </div>
      </button>
    `).join('');
    templateGrid.addEventListener('click', e => {
      const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('[data-tpl-id]');
      if (!btn) return;
      const tpl = SECRET_TEMPLATES.find(t => t.id === btn.dataset.tplId);
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

  let _bulkMode = false;
  let _bulkSelected = new Set<number>();

  const bulkSelectBtn = document.getElementById('bulk-select-btn')!;
  const bulkBar       = document.getElementById('bulk-bar')!;
  const bulkCount     = document.getElementById('bulk-count')!;

  function updateBulkCount() {
    bulkCount.textContent = `${_bulkSelected.size} selected`;
  }

  function enterBulkMode() {
    _bulkMode = true;
    _bulkSelected.clear();
    bulkSelectBtn.textContent = 'Exit Select';
    bulkBar.style.display = 'flex';
    document.getElementById('card-grid')?.classList.add('bulk-mode');
    updateBulkCount();
  }

  function exitBulkMode() {
    _bulkMode = false;
    _bulkSelected.clear();
    bulkSelectBtn.textContent = 'Select';
    bulkBar.style.display = 'none';
    document.getElementById('card-grid')?.classList.remove('bulk-mode');
    import('./render').then(m => m.render());
  }

  bulkSelectBtn.addEventListener('click', () => _bulkMode ? exitBulkMode() : enterBulkMode());
  document.getElementById('bulk-cancel-btn')?.addEventListener('click', exitBulkMode);

  document.getElementById('bulk-delete-btn')?.addEventListener('click', async () => {
    if (!_bulkSelected.size) return;
    if (!await showConfirm(`Delete ${_bulkSelected.size} selected secrets? This cannot be undone.`)) return;
    const indices = Array.from(_bulkSelected).sort((a, b) => b - a);
    indices.forEach(i => st.vault.api_keys.splice(i, 1));
    await (st.store as any).save(st.vault).catch(() => {});
    exitBulkMode();
    import('./render').then(m => m.render());
    showToast(`Deleted ${indices.length} secrets`, 'ok');
  });

  document.getElementById('bulk-export-btn')?.addEventListener('click', () => {
    const selected = Array.from(_bulkSelected).map(i => st.vault.api_keys[i]).filter(Boolean);
    const lines = selected.map(e => {
      const key = e.provider.toUpperCase().replace(/[^A-Z0-9]/g, '_');
      return `${key}=${e.api_key}`;
    }).join('\n');
    const blob = new Blob([lines], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), { href: url, download: 'export.env' });
    a.click();
    URL.revokeObjectURL(url);
  });

  // Expose bulk toggle to card clicks
  (window as any).__apivBulkToggle = (idx: number) => {
    if (!_bulkMode) return false;
    if (_bulkSelected.has(idx)) _bulkSelected.delete(idx);
    else _bulkSelected.add(idx);
    updateBulkCount();
    document.querySelector<HTMLElement>(`[data-card-idx="${idx}"]`)?.classList.toggle('bulk-selected', _bulkSelected.has(idx));
    return true;
  };
  (window as any).__apivIsBulkMode = () => _bulkMode;
}
