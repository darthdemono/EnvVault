/** Pure utilities — no state, no DOM side effects on module load. */

export function esc(s: unknown): string {
  if (s == null) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export function escAttr(s: unknown): string {
  if (s == null) return '';
  return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

export function maskKey(val: string): string {
  if (!val) return '—';
  if (val.length <= 8) return '•'.repeat(val.length);
  return val.slice(0, 4) + '••••••••••••' + val.slice(-4);
}

export function hexAlpha(hex: string, a: number): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r},${g},${b},${a})`;
}

export function generateULID(): string {
  const CHARS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let ms = Date.now(), ts = '';
  for (let i = 9; i >= 0; i--) { ts = CHARS[ms % 32] + ts; ms = Math.floor(ms / 32); }
  const rnd = new Uint8Array(10); crypto.getRandomValues(rnd);
  let r = 0n; for (const b of rnd) r = (r << 8n) | BigInt(b);
  let rand = '';
  for (let i = 15; i >= 0; i--) { rand = CHARS[Number(r & 31n)] + rand; r >>= 5n; }
  return ts + rand;
}

// ── Toast ──────────────────────────────────────────────────────────────────
let _toastTimer: ReturnType<typeof setTimeout>;
export function showToast(msg: string, type = '', duration = 2500): void {
  const el = document.getElementById('toast')!;
  el.textContent = msg;
  el.className = 'show' + (type ? ' ' + type : '');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => (el.className = ''), duration);
}

// ── Dialogs ────────────────────────────────────────────────────────────────
export function showConfirm(msg: string): Promise<boolean> {
  return new Promise(resolve => {
    const overlay = document.getElementById('confirm-overlay')!;
    document.getElementById('confirm-message')!.textContent = msg;
    overlay.classList.add('open');
    const cleanup = (result: boolean) => {
      overlay.classList.remove('open');
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      overlay.removeEventListener('click', onBackdrop);
      document.removeEventListener('keydown', onKey);
      resolve(result);
    };
    const okBtn = document.getElementById('confirm-ok')!;
    const cancelBtn = document.getElementById('confirm-cancel')!;
    const onOk = () => cleanup(true);
    const onCancel = () => cleanup(false);
    const onBackdrop = (e: Event) => { if (e.target === overlay) cleanup(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') cleanup(false); else if (e.key === 'Enter') cleanup(true); };
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    overlay.addEventListener('click', onBackdrop);
    document.addEventListener('keydown', onKey);
  });
}

export function showPrompt(msg: string, defaultVal = ''): Promise<string | null> {
  return new Promise(resolve => {
    const overlay = document.getElementById('prompt-overlay')!;
    const input = document.getElementById('prompt-input') as HTMLInputElement;
    document.getElementById('prompt-message')!.textContent = msg;
    input.value = defaultVal;
    overlay.classList.add('open');
    setTimeout(() => input.focus(), 50);
    const cleanup = (result: string | null) => {
      overlay.classList.remove('open');
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      overlay.removeEventListener('click', onBackdrop);
      document.removeEventListener('keydown', onKey);
      resolve(result);
    };
    const okBtn = document.getElementById('prompt-ok')!;
    const cancelBtn = document.getElementById('prompt-cancel')!;
    const onOk = () => cleanup(input.value.trim() || null);
    const onCancel = () => cleanup(null);
    const onBackdrop = (e: Event) => { if (e.target === overlay) cleanup(null); };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); cleanup(null); }
      else if (e.key === 'Enter') { e.stopPropagation(); cleanup(input.value.trim() || null); }
    };
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    overlay.addEventListener('click', onBackdrop);
    document.addEventListener('keydown', onKey);
  });
}

// ── Clipboard ──────────────────────────────────────────────────────────────
export async function clipboardWrite(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text).catch(() => execCopy(text));
  return execCopy(text);
}

export function execCopy(text: string): Promise<void> {
  const ta = Object.assign(document.createElement('textarea'), { value: text });
  Object.assign(ta.style, { position: 'fixed', left: '-9999px', top: '-9999px', opacity: '0' });
  document.body.appendChild(ta); ta.focus(); ta.select();
  return new Promise((resolve, reject) => {
    try { document.execCommand('copy'); resolve(); }
    catch (e) { reject(e); }
    finally { document.body.removeChild(ta); }
  });
}

// ── SVGs ───────────────────────────────────────────────────────────────────
export const eyeSVG  = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
export const copySVG = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
export const editSVG = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`;
export const delSVG  = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4h6v2"/></svg>`;
export const dupSVG  = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="1" width="13" height="13" rx="2"/><path d="M8 8h13v13H8z"/></svg>`;
