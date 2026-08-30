/**
 * @file
 * Audit log viewer — reads the append-only, hash-chained `vault_audit`
 * table and lets the user verify that the chain is intact.
 *
 * The backend has written this chain since Phase 3 but nothing ever displayed
 * it, so the tamper-evidence it provides was invisible. Each row stores
 * `entry_hash = SHA256("action|provider|timestamp|prev_hash")` with the literal
 * string `genesis` standing in for the first row's absent predecessor — mirror
 * of `compute_audit_hash` in `vault-core/src/lib.rs`.
 */

import type { AuditRow } from './types';
import { st, RemoteVaultStore } from './state';
import { esc, showToast, clipboardWrite } from './utils';

const invoke = (cmd: string, args?: Record<string, unknown>) =>
  (window as any).__TAURI__?.core?.invoke?.(cmd, args) as Promise<any> | undefined;

/** Rows from the last successful load, newest-first (as the backend returns them). */
let _rows: AuditRow[] = [];

/**
 * Audit rows for callers outside this module.
 *
 * `finishInit` uses it to date entries written before `created_at` existed. It
 * is the same read the viewer does, exported rather than duplicated so there is
 * one place that knows whether the rows come over IPC or over HTTP.
 */
export async function loadAuditRows(): Promise<AuditRow[]> {
  return loadRows();
}

async function loadRows(): Promise<AuditRow[]> {
  if (st.store instanceof RemoteVaultStore) {
    return (await (st.store as RemoteVaultStore).getAuditLog()) as AuditRow[];
  }
  return (await invoke('get_audit_log')) ?? [];
}

/** Hex SHA-256 of a UTF-8 string, matching the Rust side byte for byte. */
async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export interface ChainResult {
  ok: boolean;
  checked: number;
  /** 1-based position of the first bad row in oldest-first order, if any. */
  brokenAt: number | null;
  reason: string;
}

/**
 * Recompute the hash chain oldest-first.
 *
 * Two independent checks per row: the stored `entry_hash` must equal a fresh
 * hash of the row's own contents, and the stored `prev_hash` must equal the
 * previous row's `entry_hash`. Either mismatch means a row was altered,
 * inserted or removed.
 */
export async function verifyChain(rows: AuditRow[]): Promise<ChainResult> {
  const ordered = [...rows].sort((a, b) => a.id - b.id);
  // Pre-hash-chain rows (written before the columns existed) carry no hashes;
  // skip them rather than reporting a false tamper.
  const chained = ordered.filter((r) => r.entry_hash);
  if (!chained.length) {
    return {
      ok: true,
      checked: 0,
      brokenAt: null,
      reason: 'No hash-chained rows yet — nothing to verify.',
    };
  }

  // The first chained row must anchor to genesis.
  //
  // Without this, deleting the *start* of the log verified clean: whatever row
  // survived first still hashed correctly over its own stored prev_hash, and
  // the link check below is skipped on the first iteration because there is no
  // predecessor to compare against. Truncating the beginning of an append-only
  // audit log — the most useful thing to erase — was undetectable.
  const first = chained[0];
  if (first.prev_hash && first.prev_hash !== 'genesis') {
    return {
      ok: false,
      checked: 0,
      brokenAt: 1,
      reason: `Row #${first.id} is the oldest hashed row but links to an earlier hash — rows before it were removed.`,
    };
  }

  let prev: string | null = null;
  for (let i = 0; i < chained.length; i++) {
    const r = chained[i];
    const prevForHash = r.prev_hash ?? 'genesis';
    // Two chain formats coexist, mirroring `compute_audit_hash` in vault-core:
    //   v2  action|provider|timestamp|actor|prev   (actor bound into the chain)
    //   v1  action|provider|timestamp|prev         (rows predating actor tracking)
    // Try v2 when an actor is present, else v1, so existing logs still verify.
    const expected = r.actor
      ? await sha256Hex(
          `${r.action}|${r.entry_provider ?? ''}|${r.timestamp}|${r.actor}|${prevForHash}`,
        )
      : await sha256Hex(`${r.action}|${r.entry_provider ?? ''}|${r.timestamp}|${prevForHash}`);
    if (expected !== r.entry_hash) {
      return {
        ok: false,
        checked: i + 1,
        brokenAt: i + 1,
        reason: `Row #${r.id} contents do not match its stored hash.`,
      };
    }
    if (prev !== null && r.prev_hash !== prev) {
      return {
        ok: false,
        checked: i + 1,
        brokenAt: i + 1,
        reason: `Row #${r.id} does not link to the previous row — a row was altered or removed.`,
      };
    }
    prev = r.entry_hash!;
  }
  return {
    ok: true,
    checked: chained.length,
    brokenAt: null,
    reason: `All ${chained.length} chained rows verified.`,
  };
}

const ACTION_CLASS: Record<string, string> = {
  add: 'audit-add',
  update: 'audit-update',
  delete: 'audit-delete',
  read: 'audit-read',
};

/** Usernames by id, so audit rows show a name instead of a raw UUID. */
let _userNames = new Map<string, string>();

/**
 * Drops everything loaded from the previous vault.
 *
 * `_rows` and `_userNames` are module state that outlived a vault switch: the
 * table kept showing the old vault's audit trail, "Verify" reported on it, and
 * "Export" copied it to the clipboard while the UI claimed to be looking at the
 * new vault. Call whenever the backing store changes.
 */
export function resetAuditPanel(): void {
  _rows = [];
  _userNames = new Map();
  const out = document.getElementById('audit-results');
  if (out) out.innerHTML = '';
  const countEl = document.getElementById('audit-count');
  if (countEl) countEl.textContent = '';
  const status = document.getElementById('audit-status');
  if (status) status.style.display = 'none';
}

async function loadUserNames(): Promise<void> {
  try {
    const users =
      st.store instanceof RemoteVaultStore
        ? await (st.store as RemoteVaultStore).api('/api/users')
        : await invoke('list_users');
    _userNames = new Map((users ?? []).map((u: any) => [u.id, u.username]));
  } catch {
    /* not permitted to list users — fall back to raw ids */
  }
}

function actorLabel(actor: string | null): string {
  if (!actor) return '—';
  return _userNames.get(actor) ?? actor.slice(0, 8);
}

function render(rows: AuditRow[]) {
  const out = document.getElementById('audit-results')!;
  const countEl = document.getElementById('audit-count')!;
  countEl.textContent = rows.length ? `${rows.length} entries` : '';

  if (!rows.length) {
    out.innerHTML = `<div class="health-ok">No audit entries yet — the log fills as you add, edit and delete secrets.</div>`;
    return;
  }

  out.innerHTML = `
    <table class="audit-table">
      <thead>
        <tr><th>#</th><th>Action</th><th>Target</th><th>By</th><th>When</th><th>Details</th><th>Hash</th></tr>
      </thead>
      <tbody>
        ${rows
          .map(
            (r) => `
          <tr>
            <td class="audit-id">${esc(r.id)}</td>
            <td><span class="audit-action ${ACTION_CLASS[r.action] ?? ''}">${esc(r.action)}</span></td>
            <td class="audit-target">${esc(r.entry_provider ?? '—')}</td>
            <td class="audit-actor" title="${esc(r.actor ?? '')}">${esc(actorLabel(r.actor))}</td>
            <td class="audit-ts">${esc(r.timestamp)}</td>
            <td class="audit-details">${esc(r.details ?? '')}</td>
            <td class="audit-hash" title="${esc(r.entry_hash ?? '')}">${esc((r.entry_hash ?? '—').slice(0, 12))}</td>
          </tr>`,
          )
          .join('')}
      </tbody>
    </table>`;
}

function setStatus(msg: string, type: 'ok' | 'err' | 'warn') {
  const el = document.getElementById('audit-status')!;
  el.className = `tool-status ${type}`;
  el.textContent = msg;
  el.style.display = '';
}

export function initAuditPanel() {
  document.getElementById('audit-refresh')?.addEventListener('click', async () => {
    try {
      await loadUserNames();
      _rows = await loadRows();
      render(_rows);
      setStatus(`Loaded ${_rows.length} entries.`, 'ok');
    } catch (e: any) {
      setStatus(`Could not load audit log: ${e?.message ?? e}`, 'err');
    }
  });

  document.getElementById('audit-verify')?.addEventListener('click', async () => {
    if (!_rows.length) {
      try {
        _rows = await loadRows();
        render(_rows);
      } catch (e: any) {
        setStatus(`Could not load audit log: ${e?.message ?? e}`, 'err');
        return;
      }
    }
    setStatus('Verifying…', 'warn');
    const result = await verifyChain(_rows);
    setStatus(
      result.ok ? `✓ Chain intact — ${result.reason}` : `✗ Chain broken — ${result.reason}`,
      result.ok ? 'ok' : 'err',
    );
  });

  document.getElementById('audit-export')?.addEventListener('click', () => {
    if (!_rows.length) {
      showToast('Load the log first', 'err');
      return;
    }
    clipboardWrite(JSON.stringify(_rows, null, 2)).then(() =>
      showToast('Audit log copied ✓', 'ok', 1500),
    );
  });
}
