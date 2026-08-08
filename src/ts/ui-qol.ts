/**
 * @file Small cross-cutting UX affordances: password reveal toggles, Caps Lock
 *       warnings, a password strength meter, and the recent-search dropdown.
 *
 * These are deliberately independent of `vault.ts`'s init: each `wire*` helper
 * is idempotent and binds to elements by id, so a screen that is rebuilt (the
 * unlock modal is shown, hidden and shown again across a lock cycle) can call
 * them freely without stacking duplicate listeners.
 */

import { Settings, pushRecentSearch, RECENT_SEARCH_MAX, st } from './state';
import { esc } from './utils';

// ── Password reveal ───────────────────────────────────────────────────────────

const EYE_OPEN = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
const EYE_OFF  = `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>`;

/**
 * Wires every `[data-reveal="<input id>"]` button to toggle its input's type.
 *
 * Assignment (`onclick`), not `addEventListener`: the unlock and relock screens
 * are re-shown across a lock cycle, and stacking handlers there would toggle
 * the field twice per click and leave it exactly as it was — the same bug
 * `showUnlockModal` already guards against on the server-URL field.
 */
export function wireRevealButtons(root: ParentNode = document): void {
  root.querySelectorAll<HTMLButtonElement>('[data-reveal]').forEach(btn => {
    const input = document.getElementById(btn.dataset.reveal!) as HTMLInputElement | null;
    if (!input) return;
    btn.onclick = () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.classList.toggle('active', show);
      btn.title = show ? 'Hide password' : 'Show password';
      btn.setAttribute('aria-label', btn.title);
      const svg = btn.querySelector('svg');
      if (svg) svg.innerHTML = show ? EYE_OFF : EYE_OPEN;
      input.focus();
    };
  });
}

/**
 * Puts a password field back in its masked state.
 *
 * Called whenever a password screen opens. Without it, revealing a password
 * once leaves *every later* visit to that screen showing plaintext — including
 * the auto-lock screen, which is precisely the moment the user walked away
 * from the machine.
 */
export function resetReveal(inputId: string): void {
  const input = document.getElementById(inputId) as HTMLInputElement | null;
  if (!input) return;
  input.type = 'password';
  const btn = document.querySelector<HTMLButtonElement>(`[data-reveal="${inputId}"]`);
  if (!btn) return;
  btn.classList.remove('active');
  btn.title = 'Show password';
  btn.setAttribute('aria-label', 'Show password');
  const svg = btn.querySelector('svg');
  if (svg) svg.innerHTML = EYE_OPEN;
}

// ── Caps Lock warning ─────────────────────────────────────────────────────────

/**
 * Shows `hintId` while Caps Lock is on and `inputId` has focus.
 *
 * A masked field gives no feedback at all about case, so a Caps Lock slip on a
 * master password reads as "wrong password" with no way to tell the difference.
 */
export function wireCapsLockHint(inputId: string, hintId: string): void {
  const input = document.getElementById(inputId) as HTMLInputElement | null;
  const hint  = document.getElementById(hintId);
  if (!input || !hint) return;

  const update = (e: KeyboardEvent) => {
    // getModifierState is absent on synthetic events in tests and on some
    // older WebKit builds — treat "unknown" as "off" rather than throwing.
    const on = typeof e.getModifierState === 'function' && e.getModifierState('CapsLock');
    hint.style.display = on ? 'flex' : 'none';
  };
  input.onkeyup = update;
  input.onkeydown = update;
  input.onblur = () => { hint.style.display = 'none'; };
}

// ── Password strength ─────────────────────────────────────────────────────────

export interface PasswordStrength { score: 0 | 1 | 2 | 3 | 4; label: string; color: string; }

/**
 * A deliberately coarse strength estimate for the create-vault screen.
 *
 * Length dominates because it is the only input that reliably survives an
 * offline attack on an Argon2id-derived key; the character-class bonuses exist
 * mainly to stop a long run of one repeated character scoring well.
 */
export function passwordStrength(pw: string): PasswordStrength {
  if (!pw) return { score: 0, label: '', color: 'transparent' };

  let bits = 0;
  if (pw.length >= 12) bits++;
  if (pw.length >= 16) bits++;
  if (pw.length >= 24) bits++;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(re => re.test(pw)).length;
  if (classes >= 3) bits++;
  if (new Set(pw).size < Math.min(6, pw.length)) bits--;   // "aaaaaaaaaaaa" is not strong

  const score = Math.max(0, Math.min(4, bits)) as 0 | 1 | 2 | 3 | 4;
  const table: Record<number, [string, string]> = {
    0: ['Weak',       'var(--danger, #e05)'],
    1: ['Weak',       'var(--danger, #e05)'],
    2: ['Fair',       'var(--warn, #e8a33d)'],
    3: ['Good',       'var(--accent)'],
    4: ['Strong',     'var(--ok, #3ec98a)'],
  };
  const [label, color] = table[score];
  return { score, label, color };
}

/** Live-updates the strength meter beside a new-password field. */
export function wirePasswordStrength(inputId: string, wrapId: string): void {
  const input = document.getElementById(inputId) as HTMLInputElement | null;
  const wrap  = document.getElementById(wrapId);
  const fill  = document.getElementById(`${wrapId}-fill`);
  const label = document.getElementById(`${wrapId}-label`);
  if (!input || !wrap || !fill || !label) return;

  const update = () => {
    const { score, label: text, color } = passwordStrength(input.value);
    wrap.style.display = input.value ? 'flex' : 'none';
    fill.style.width = `${(score / 4) * 100}%`;
    fill.style.background = color;
    label.textContent = text;
  };
  input.oninput = update;
  update();
}

// ── Recent search history ─────────────────────────────────────────────────────

const CLOCK_SVG = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/></svg>`;

/** Closes the recent-search dropdown if it is open. */
export function closeSearchHistory(): void {
  const panel = document.getElementById('search-history');
  if (panel) panel.style.display = 'none';
}

/**
 * Renders and opens the recent-search dropdown, if there is anything to show.
 *
 * @returns true when the panel was opened.
 */
export function openSearchHistory(onPick: (q: string) => void): boolean {
  const panel = document.getElementById('search-history');
  if (!panel) return false;

  const items = (Settings.get('recentSearches') || []).slice(0, RECENT_SEARCH_MAX);
  if (!items.length) { panel.style.display = 'none'; return false; }

  // Search strings are user input that has been round-tripped through
  // localStorage — a vault imported from elsewhere never touches this, but the
  // settings blob is still plain JSON on disk, so escape it like any other
  // untrusted field (invariant 4).
  panel.innerHTML =
    `<div class="search-history-head">Recent searches` +
    `<button type="button" class="search-history-clear" data-clear-history>Clear</button></div>` +
    items.map(q =>
      `<button type="button" class="search-history-item" data-recent="${esc(q)}">` +
      `${CLOCK_SVG}<span>${esc(q)}</span></button>`,
    ).join('');
  panel.style.display = 'block';

  panel.onclick = (e) => {
    const target = e.target as HTMLElement;
    if (target.closest('[data-clear-history]')) {
      Settings.set('recentSearches', []);
      closeSearchHistory();
      return;
    }
    const item = target.closest<HTMLElement>('[data-recent]');
    if (!item) return;
    closeSearchHistory();
    onPick(item.dataset.recent!);
  };
  return true;
}

/**
 * Binds the search box to its history dropdown.
 *
 * Recording happens on blur and on Enter rather than on every keystroke — an
 * `input` handler would fill the list with every prefix of the query the user
 * was still typing.
 */
export function wireSearchHistory(onPick: (q: string) => void): void {
  const input = document.getElementById('search') as HTMLInputElement | null;
  if (!input) return;

  input.addEventListener('focus', () => { if (!input.value.trim()) openSearchHistory(onPick); });
  input.addEventListener('input', () => { if (input.value) closeSearchHistory(); });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter')  { pushRecentSearch(input.value); closeSearchHistory(); }
    if (e.key === 'Escape') closeSearchHistory();
  });
  input.addEventListener('blur', () => {
    pushRecentSearch(input.value);
    // Delay: a click on a history row fires blur before click, and hiding the
    // panel synchronously removes the row out from under the pending click.
    setTimeout(closeSearchHistory, 150);
  });
}

// ── Relative time ─────────────────────────────────────────────────────────────

/**
 * "3 minutes ago" / "yesterday" for the saved-remote list.
 *
 * @param iso ISO timestamp, or undefined/invalid for never-connected.
 */
export function relativeTime(iso: string | undefined | null): string {
  if (!iso) return 'never connected';
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return 'never connected';

  // `< 60` rather than `Math.abs(...) < 60`: a negative delta means the server's
  // clock runs ahead of ours, which is normal across machines, and it must read
  // as "just now" rather than "in -3 minutes".
  const secs = Math.round((Date.now() - then) / 1000);
  if (secs < 60)    return 'just now';
  const mins = Math.round(secs / 60);
  if (mins < 60)    return `${mins} minute${mins === 1 ? '' : 's'} ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24)   return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  const days = Math.round(hours / 24);
  if (days === 1)   return 'yesterday';
  if (days < 30)    return `${days} days ago`;
  const months = Math.round(days / 30);
  if (months < 12)  return `${months} month${months === 1 ? '' : 's'} ago`;
  return `${Math.round(months / 12)} year${Math.round(months / 12) === 1 ? '' : 's'} ago`;
}

// ── Unsaved-work guard ────────────────────────────────────────────────────────

/**
 * Warns before the window closes while an undo is still pending.
 *
 * `st.undoStack` holds deletes that have not been committed yet; closing the
 * app discarded them silently, so a mis-click plus a quit lost the secret with
 * no way back.
 */
export function wireCloseGuard(): void {
  window.addEventListener('beforeunload', (e) => {
    if (!st.undoStack.length) return;
    e.preventDefault();
    e.returnValue = '';
  });
}
