/**
 * @file
 * The Key Pools tool pane.
 *
 * A pool is several interchangeable credentials for one service, held so a rate
 * limit on one does not stop the work. Membership is a field on the entry
 * (`pool`) and lives in the vault; the *swap state* — which key is next, which
 * are cooling, how often each has been used — does not.
 *
 * That state is `pools.json` in the per-user state directory, written by both
 * this app and the `envv` CLI. The app's data directory and the CLI's default
 * resolve to the same `io.envvault`, so a key reported rate limited from CI
 * shows as cooling here within one refresh. See `vault-core/src/pool.rs` for
 * why it is not in the vault: `save_vault` appends an audit row per update and
 * is a compare-and-swap, so putting a read-path counter there would grow the
 * hash chain without bound and turn concurrent reads into write conflicts.
 *
 * Outside Tauri — a browser dev server, or the test suite — there is no state
 * file to read. The pane still renders membership from the vault and says so,
 * rather than showing zeros that look like real counts.
 */

import { st, inTauri } from './state';
import type { VaultEntry } from './types';
import { esc, escAttr, showToast, showConfirm } from './utils';
import { relativeTime } from './ui-qol';

const invoke = (cmd: string, args?: Record<string, unknown>) =>
  (window as any).__TAURI__?.core?.invoke?.(cmd, args) as Promise<any> | undefined;

/** Default cooldown offered by the button, matching the CLI's `--for` default. */
const DEFAULT_COOLDOWN_MIN = 15;

/** Per-member state as the Rust side reports it. */
interface MemberState {
  ck: string;
  uses: number;
  cooling: boolean;
  cooling_until: string | null;
  last_used_at: string | null;
}

/**
 * The identity fields `entry_ck` needs, and nothing else.
 *
 * Deliberately not the whole entry: `pool_state` and `pool_set_cooldown` have no
 * use for a secret, so none crosses the IPC boundary. The key itself is computed
 * in Rust by the same `entry_ck` version history and audit attribution use —
 * recomputing it here would be a second identity scheme that agrees until it
 * does not.
 */
function memberRef(e: VaultEntry) {
  return {
    id: e.id ?? '',
    provider: e.provider ?? '',
    account_name: e.account_name ?? '',
    key_id: e.key_id ?? '',
  };
}

/** A label that distinguishes members of one pool. Mirrors `Member::label`. */
function label(e: VaultEntry): string {
  return e.key_id ? `${e.provider}:${e.key_id}` : e.provider || '(unnamed)';
}

/** Pool name → its entries, in vault order. */
export function poolsOf(vault: { api_keys?: VaultEntry[] }): Map<string, VaultEntry[]> {
  const out = new Map<string, VaultEntry[]>();
  for (const e of vault.api_keys ?? []) {
    // Vault data is untrusted input and the declared type is erased at runtime,
    // so a non-string `pool` must not become a pool named "[object Object]".
    const name = typeof e.pool === 'string' ? e.pool.trim() : '';
    if (!name) continue;
    const list = out.get(name);
    if (list) list.push(e);
    else out.set(name, [e]);
  }
  return new Map([...out.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

/**
 * `remote_base` for the Rust commands, so a remote session does not read the
 * local vault's cursors.
 *
 * The same mistake the LAN gate exists to prevent: acting on this machine's
 * vault while the screen shows someone else's.
 */
function remoteBase(): string | null {
  const store = st.store as { isRemote?: boolean; baseUrl?: string } | undefined;
  return store?.isRemote ? (store.baseUrl ?? null) : null;
}

/** Where the state file lives, cached after the first successful lookup. */
let statePath = '';

export async function renderPoolsPane(): Promise<void> {
  const host = document.getElementById('pools-body');
  if (!host) return;

  const pools = poolsOf(st.vault ?? {});
  if (pools.size === 0) {
    host.innerHTML = `
      <div class="empty-state">
        <p>No key pools yet.</p>
        <p class="tool-note">
          Put two or more credentials for one service in a pool by setting
          <strong>Key Pool</strong> on each of them in the edit form, then swap between
          them with <code>envv get --pool &lt;name&gt;</code> or
          <code>envv exec --pool &lt;name&gt;</code>.
        </p>
        <p class="tool-note">
          Membership is explicit on purpose. Two keys for the same provider do not pool
          automatically, because a command refusing an ambiguous match is what stops it
          acting on a credential you did not mean.
        </p>
      </div>`;
    return;
  }

  // Ask Rust for the state of every member in one call per pool. Failures are
  // not fatal: membership still renders, and the pane says the counts are
  // unavailable rather than showing zeros that look real.
  const states = new Map<string, Map<string, MemberState>>();
  let stateAvailable = inTauri;
  if (inTauri) {
    const base = remoteBase();
    for (const [name, members] of pools) {
      try {
        const rows = (await invoke('pool_state', {
          pool: name,
          members: members.map(memberRef),
          remoteBase: base,
        })) as MemberState[] | undefined;
        states.set(name, new Map((rows ?? []).map((r) => [r.ck, r])));
      } catch {
        stateAvailable = false;
      }
    }
    if (!statePath) {
      try {
        statePath = ((await invoke('pool_state_path')) as string | null) ?? '';
      } catch {
        statePath = '';
      }
    }
  }

  const rows = [...pools.entries()]
    .map(([name, members], poolIdx) => {
      const byCk = states.get(name);
      const memberRows = members
        .map((e, i) => {
          const s = byCk ? [...byCk.values()][i] : undefined;
          const cooling = s?.cooling ?? false;
          const until = s?.cooling_until ?? null;
          const usage = stateAvailable ? `${s?.uses ?? 0}` : '—';
          const lastUsed = s?.last_used_at ? relativeTime(s.last_used_at) : 'never';
          return `
            <tr class="${cooling ? 'pool-row-cooling' : ''}">
              <td class="pool-member">${esc(label(e))}</td>
              <td class="pool-uses mono">${esc(usage)}</td>
              <td class="pool-last mono">${esc(lastUsed)}</td>
              <td class="pool-status">
                ${
                  cooling
                    ? `<span class="badge badge-cooling" title="Skipped by envv get --pool until ${escAttr(
                        until ?? '',
                      )}">cooling</span>`
                    : `<span class="pool-ok">available</span>`
                }
              </td>
              <td class="pool-actions">
                ${
                  stateAvailable
                    ? cooling
                      ? `<button class="btn btn-sm" data-pool-action="clear" data-pool="${escAttr(
                          name,
                        )}" data-member="${escAttr(String(i))}">Clear</button>`
                      : `<button class="btn btn-sm" data-pool-action="limit" data-pool="${escAttr(
                          name,
                        )}" data-member="${escAttr(String(i))}">Mark limited</button>`
                    : ''
                }
              </td>
            </tr>`;
        })
        .join('');

      const coolingCount = byCk ? [...byCk.values()].filter((s) => s.cooling).length : 0;
      return `
        <section class="pool-card" data-pool-index="${poolIdx}">
          <header class="pool-card-header">
            <h4 class="mono">${esc(name)}</h4>
            <span class="pool-summary">
              ${members.length} key${members.length === 1 ? '' : 's'}${
                stateAvailable && coolingCount
                  ? ` · <span class="pool-cooling-count">${coolingCount} cooling</span>`
                  : ''
              }
            </span>
            ${
              stateAvailable
                ? `<button class="btn btn-sm" data-pool-action="reset" data-pool="${escAttr(
                    name,
                  )}">Reset</button>`
                : ''
            }
          </header>
          <table class="pool-table">
            <thead>
              <tr><th>Key</th><th>Uses</th><th>Last used</th><th>Status</th><th></th></tr>
            </thead>
            <tbody>${memberRows}</tbody>
          </table>
        </section>`;
    })
    .join('');

  const footer = !inTauri
    ? `<p class="tool-note">Swap state is read from the CLI's <code>pools.json</code>, which is only
       available in the desktop app. Membership above is from the vault and is correct;
       use counts and cooldowns are not shown.</p>`
    : !stateAvailable
      ? `<p class="tool-note">Could not read <code>pools.json</code>. Membership is from the vault and is
         correct; use counts and cooldowns are unavailable.</p>`
      : `<p class="tool-note">Counts and cooldowns live in
         <code>${esc(statePath || 'pools.json')}</code> — per machine, outside the vault and
         outside backups, and shared with the <code>envv</code> CLI. Resetting affects this
         machine only.</p>`;

  host.innerHTML = rows + footer;
}

/**
 * Wire the pane's delegated click handler.
 *
 * Assigned, never added: this pane is re-rendered on every visit, and
 * `addEventListener` would stack a duplicate each time — the bug this project
 * has hit at least three separate times (CLAUDE.md invariant 9).
 */
export function initPoolsPane(): void {
  const host = document.getElementById('pools-body');
  if (!host) return;

  host.onclick = (ev) => {
    const btn = (ev.target as HTMLElement | null)?.closest<HTMLElement>('[data-pool-action]');
    if (!btn) return;
    const action = btn.dataset.poolAction;
    const name = btn.dataset.pool ?? '';
    // `data-member` is a position in the list this render produced. It is
    // resolved immediately, never stored — the same rule as `data-idx` on a
    // card (CLAUDE.md invariant 1).
    const members = poolsOf(st.vault ?? {}).get(name) ?? [];
    const entry = members[Number(btn.dataset.member ?? -1)];

    void (async () => {
      try {
        if (action === 'reset') {
          if (!(await showConfirm(`Reset cursor, cooldowns and counts for "${name}"?`))) return;
          await invoke('pool_reset', { pool: name, remoteBase: remoteBase() });
          showToast(`Pool "${name}" reset`, 'ok');
        } else if (action === 'limit' && entry) {
          await invoke('pool_set_cooldown', {
            pool: name,
            member: memberRef(entry),
            seconds: DEFAULT_COOLDOWN_MIN * 60,
            remoteBase: remoteBase(),
          });
          showToast(`${label(entry)} cooling for ${DEFAULT_COOLDOWN_MIN}m`, 'ok');
        } else if (action === 'clear' && entry) {
          await invoke('pool_set_cooldown', {
            pool: name,
            member: memberRef(entry),
            seconds: null,
            remoteBase: remoteBase(),
          });
          showToast(`${label(entry)} available again`, 'ok');
        } else {
          return;
        }
        await renderPoolsPane();
      } catch (e) {
        showToast(`Pool update failed: ${String(e)}`, 'err');
      }
    })();
  };
}
