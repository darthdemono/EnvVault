/**
 * @file
 * The Authenticator screen — Phase 22.2's dedicated panel.
 *
 * ## Why this exists when the sidebar section already did
 *
 * Phase 22 put the authenticator in a `sidebar-section` inside the Secrets
 * panel and wrote down why: it is a filter over the secrets already in that
 * panel, not a new place to be, and a fifth activity-bar entry would add a
 * second navigation idiom for one feature.
 *
 * **That call is reversed here, deliberately and on request.** What changed is
 * the amount of surface: Phase 22.2 adds three kinds of seed, a counter that a
 * user advances by hand, and a next-code view. A sidebar row is one line high —
 * it can hold a label, a code and a ring, and it cannot hold a kind badge, a
 * counter, an Advance button and a second code without becoming unreadable.
 * Recording the reversal rather than quietly widening the row, because an
 * unwritten reversal is indistinguishable from having forgotten the reasoning.
 *
 * The sidebar section **stays** and is unchanged: it is still the fastest path
 * to one code, and it still filters the grid. This panel is the place you go to
 * manage them.
 *
 * ## What is not here
 *
 * No code generation. There is one HMAC in this project and it is Rust's
 * (`vault-core/src/totp.rs`); this asks over IPC exactly as the card does. And
 * no QR rendering — the CSP allows no external script, and relaxing it in order
 * to draw a *secret* is a poor trade.
 */

import { st, Settings, inTauri } from './state';
import type { VaultEntry } from './types';
import { esc, escAttr, showToast, clipboardWrite } from './utils';
import {
  hasTotp,
  totpParamsOf,
  startTotpTicker,
  stopTotpTicker,
  resetTotpCache,
  type TotpKind,
} from './totp';

/** Which kinds the panel is showing. Panel-local: it filters nothing else. */
let kindFilter: 'all' | TotpKind = 'all';
/** The search box's current text, lowercased. */
let query = '';

/** Every entry carrying a seed, in the order the panel shows them. */
function seeded(): VaultEntry[] {
  const all = st.vault?.api_keys ?? [];
  return all
    .filter(hasTotp)
    .filter((e) => kindFilter === 'all' || totpParamsOf(e).kind === kindFilter)
    .filter((e) => {
      if (!query) return true;
      const hay = `${e.provider} ${e.account_name ?? ''} ${e.username ?? ''}`.toLowerCase();
      return hay.includes(query);
    })
    .sort((a, b) => a.provider.localeCompare(b.provider));
}

/** How a kind is labelled on a card. */
const KIND_LABEL: Record<TotpKind, string> = {
  totp: 'Time-based',
  hotp: 'Counter',
  steam: 'Steam',
};

/**
 * One card.
 *
 * `data-totp-for` is the ticker's contract and carries the entry **id**, never
 * an index (invariant 1): the ticker re-looks-up the entry every second, so a
 * card left over from a previous render resolves to nothing rather than to
 * whatever took its position. The digits are deliberately absent from this
 * markup — the ticker writes them, so a re-render cannot bake a live code into
 * the document.
 */
function cardHtml(entry: VaultEntry, showNext: boolean): string {
  const id = entry.id ?? '';
  const params = totpParamsOf(entry);
  const label = entry.account_name ? `${entry.provider} · ${entry.account_name}` : entry.provider;
  const isHotp = params.kind === 'hotp';
  return `<article class="auth-card" data-totp-for="${escAttr(id)}"${
    showNext ? ' data-totp-next="1"' : ''
  } data-totp-kind="${escAttr(params.kind)}">
    <header class="auth-card-head">
      <span class="auth-card-name">${esc(label)}</span>
      <span class="auth-kind-badge auth-kind-${escAttr(params.kind)}">${esc(
        KIND_LABEL[params.kind],
      )}</span>
    </header>
    <button class="auth-code-row" data-action="copy-totp"
      aria-label="${escAttr('Copy the code for ' + label)}">
      <span class="totp-code auth-code">— — —</span>
      ${
        isHotp
          ? '<span class="totp-counter auth-counter" aria-hidden="true"></span>'
          : '<span class="totp-countdown auth-ring"><i class="totp-countdown-fill"></i></span><span class="totp-secs auth-secs" aria-hidden="true"></span>'
      }
    </button>
    <div class="auth-next-row"${showNext ? '' : ' hidden'}>
      <span class="auth-next-label">next</span>
      <span class="totp-next auth-next" hidden></span>
    </div>
    ${
      isHotp
        ? `<footer class="auth-card-foot">
             <button class="btn btn-xs" data-auth-advance="${escAttr(id)}"
               title="Move this seed to its next position. Reading a code never advances it.">Advance</button>
           </footer>`
        : ''
    }
  </article>`;
}

/**
 * Paint the panel.
 *
 * Safe to call on every render: the ticker it starts is idempotent by
 * assignment (invariant 9), so this leaves one interval rather than one per
 * call.
 */
export function renderAuthPanel(): void {
  const grid = document.getElementById('auth-grid');
  const empty = document.getElementById('auth-empty');
  const count = document.getElementById('auth-count');
  const side = document.getElementById('auth-side-list');
  if (!grid) return;

  const rows = seeded();
  const total = (st.vault?.api_keys ?? []).filter(hasTotp).length;
  const showNext = !!Settings.get('authShowNext');

  if (count) {
    count.textContent = inTauri
      ? `${total} seed${total === 1 ? '' : 's'}${rows.length !== total ? `, ${rows.length} shown` : ''}`
      : 'Codes are generated by the desktop app.';
  }
  if (empty) empty.hidden = total !== 0;

  grid.innerHTML = rows.map((e) => cardHtml(e, showNext)).join('');
  if (side) {
    side.innerHTML = rows
      .map(
        (e) =>
          `<button class="auth-side-item" data-auth-focus="${escAttr(e.id ?? '')}">
             <span class="auth-side-name">${esc(e.provider)}</span>
             <span class="auth-side-kind">${esc(totpParamsOf(e).kind)}</span>
           </button>`,
      )
      .join('');
  }

  if (rows.length) startTotpTicker();
  else stopTotpTicker();
}

/**
 * Advance a counter-based seed by one.
 *
 * Reading a code deliberately does not do this. A counter-based code stands
 * until it is used and the service moves on only when it accepts one, so
 * advancing on every read would walk the vault past the service the first time
 * somebody looked at a card twice — and the resulting failure, a second factor
 * that stops working with no error anywhere, looks exactly like a wrong seed.
 */
async function advance(id: string): Promise<void> {
  const entry = (st.vault?.api_keys ?? []).find((e) => e.id === id);
  if (!entry) return;
  const params = totpParamsOf(entry);
  if (params.kind !== 'hotp') return;

  entry.totp_counter = params.counter + 1;
  // The cache is keyed by the counter, so the new position shows immediately
  // rather than serving the code for the position just left.
  try {
    await st.store.save(st.vault!);
    showToast(`Advanced to #${entry.totp_counter}`);
  } catch {
    entry.totp_counter = params.counter;
    showToast('Could not save the new counter');
    return;
  }
  renderAuthPanel();
}

let wired = false;

/**
 * Bind the panel's controls.
 *
 * Assignment, not `addEventListener` (invariant 9): this panel is shown, hidden
 * and shown again across a lock cycle, and a stacked handler would advance a
 * counter twice per click — which is the one action here that cannot be undone
 * without resynchronising against the service.
 */
export function initAuthPanel(): void {
  if (wired) return;
  wired = true;

  const search = document.getElementById('auth-search') as HTMLInputElement | null;
  if (search) {
    search.oninput = () => {
      query = search.value.trim().toLowerCase();
      renderAuthPanel();
    };
  }

  document.querySelectorAll<HTMLButtonElement>('.auth-kind-btn').forEach((btn) => {
    btn.onclick = () => {
      kindFilter = (btn.dataset.kind as typeof kindFilter) || 'all';
      document
        .querySelectorAll('.auth-kind-btn')
        .forEach((b) => b.classList.toggle('active', b === btn));
      renderAuthPanel();
    };
  });

  const next = document.getElementById('auth-show-next') as HTMLInputElement | null;
  if (next) {
    next.checked = !!Settings.get('authShowNext');
    next.onchange = () => {
      Settings.set('authShowNext', next.checked);
      // The next code is fetched separately and cached separately, so turning
      // this on must not be served a cached answer that has no next code in it.
      resetTotpCache();
      renderAuthPanel();
    };
  }

  const grid = document.getElementById('auth-grid');
  if (grid) {
    grid.onclick = (ev) => {
      const el = ev.target as HTMLElement;
      const adv = el.closest<HTMLElement>('[data-auth-advance]');
      if (adv) {
        void advance(adv.dataset.authAdvance!);
        return;
      }
      const card = el.closest<HTMLElement>('.auth-card');
      const code = card?.dataset.totpCode;
      if (code && el.closest('.auth-code-row')) {
        // The code the ticker painted, not a re-derived one: re-deriving hands
        // over the *next* code when the click crosses a step boundary.
        void clipboardWrite(code);
        showToast('Code copied');
      }
    };
  }
}
