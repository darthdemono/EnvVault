/**
 * @file
 * Small cross-cutting UX affordances: password reveal toggles, Caps Lock
 * warnings, a password strength meter, and the recent-search dropdown.
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
const EYE_OFF = `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>`;

/**
 * Wires every `[data-reveal="<input id>"]` button to toggle its input's type.
 *
 * Assignment (`onclick`), not `addEventListener`: the unlock and relock screens
 * are re-shown across a lock cycle, and stacking handlers there would toggle
 * the field twice per click and leave it exactly as it was — the same bug
 * `showUnlockModal` already guards against on the server-URL field.
 */
export function wireRevealButtons(root: ParentNode = document): void {
  root.querySelectorAll<HTMLButtonElement>('[data-reveal]').forEach((btn) => {
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
 *
 * **The state is derived from the character a key actually produced, never from
 * `KeyboardEvent.getModifierState('CapsLock')`.** WebKitGTK reports that from
 * GDK's raw modifier mask, which is not the Caps Lock state: it was true on this
 * app's unlock screen with Caps Lock off, so the hint appeared for every user,
 * and keydown and keyup disagreed about it, so it flickered off again as soon as
 * anyone typed. A cased letter is unambiguous evidence — `a` unshifted means off,
 * `A` unshifted means on, and holding Shift inverts both — and it is the same
 * answer on every platform.
 *
 * The cost was that the hint could not appear before the first letter is typed.
 * That is the right trade against a warning that is confidently wrong all
 * session — but it is not the only option, and [[`_capsProbe`]] buys most of it
 * back: every derived reading is also used to *check* what
 * `getModifierState('CapsLock')` claimed, and once the platform has agreed with
 * observed reality it is believed for the cheap paths (a click into the field, a
 * press of the Caps Lock key itself) where there is no character to derive from.
 * A platform that contradicts itself once is never asked again.
 */
/**
 * Whether `getModifierState('CapsLock')` has earned being believed *on this
 * platform*, in this session.
 *
 * `unknown` until typed characters have said what the lock really was;
 * `trusted` after `CAPS_PROBE_QUORUM` consecutive agreements; `untrusted`
 * permanently on the first disagreement — which is what WebKitGTK's always-true
 * mask produces on the first lowercase letter anyone types.
 *
 * There is deliberately no "consistently inverted" state. A mask that is always
 * one value looks exactly like an inverted one until the lock changes, so
 * believing an inversion would reintroduce the original bug in mirror image:
 * a hint shown to every user, all session, from a platform that never knew.
 * Disagreement is treated as evidence of lying, not of a sign error.
 *
 * Module-level because it is a property of the platform, not of one field.
 */
let _capsProbe: 'unknown' | 'trusted' | 'untrusted' = 'unknown';

/** Agreeing samples required before the platform's own claim is read. */
const CAPS_PROBE_QUORUM = 2;
let _capsProbeAgreed = 0;

/**
 * Clears the platform calibration.
 *
 * Test hook. The calibration describes the platform and so is deliberately
 * session-lived; a test file that plays several different fake platforms inside
 * one process has to reset it between them or the second one inherits the
 * first's verdict.
 */
export function resetCapsProbe(): void {
  _capsProbe = 'unknown';
  _capsProbeAgreed = 0;
}

/**
 * What the event says about Caps Lock, or null when the event cannot say.
 *
 * `getModifierState` is missing on synthetic events and on old engines, and it
 * is called on every keystroke in a password field, so this must never throw.
 */
function reportedCaps(e: KeyboardEvent | MouseEvent): boolean | null {
  const fn = (e as { getModifierState?: (k: string) => boolean }).getModifierState;
  return typeof fn === 'function' ? !!fn.call(e, 'CapsLock') : null;
}

/** Caps Lock per the platform, or null while the platform is not believed. */
function capsFromProbe(e: KeyboardEvent | MouseEvent): boolean | null {
  if (_capsProbe !== 'trusted') return null;
  return reportedCaps(e);
}

/** Scores the platform's claim against a reading derived from a real character. */
function calibrateCapsProbe(e: KeyboardEvent, derived: boolean): void {
  if (_capsProbe === 'untrusted') return;
  const reported = reportedCaps(e);
  if (reported === null) return;
  if (reported !== derived) {
    // One contradiction is enough, and it is permanent: the observed character
    // is ground truth, and a platform that disagreed with it once has nothing
    // left to offer that could be checked any harder.
    _capsProbe = 'untrusted';
    _capsProbeAgreed = 0;
    return;
  }
  if (++_capsProbeAgreed >= CAPS_PROBE_QUORUM) _capsProbe = 'trusted';
}

export function wireCapsLockHint(inputId: string, hintId: string): void {
  const input = document.getElementById(inputId) as HTMLInputElement | null;
  const hint = document.getElementById(hintId);
  if (!input || !hint) return;

  // null = no evidence yet. Distinct from false: only evidence may show the
  // hint, and only evidence may hide it once shown.
  let known: boolean | null = null;

  const paint = () => {
    hint.style.display = known === true ? 'flex' : 'none';
  };

  /**
   * Caps Lock state implied by a key event, or null when the event carries no
   * evidence (a modifier, an editing key, a digit, a chorded shortcut).
   */
  const evidence = (e: KeyboardEvent): boolean | null => {
    const k = e.key;
    if (typeof k !== 'string' || Array.from(k).length !== 1) return null;
    // Ctrl/Alt/Meta chords do not produce the character they name.
    if (e.ctrlKey || e.altKey || e.metaKey) return null;
    const lower = k.toLowerCase();
    const upper = k.toUpperCase();
    if (lower === upper) return null; // digits, punctuation, uncased scripts
    return e.shiftKey ? k === lower : k === upper;
  };

  const update = (e: KeyboardEvent) => {
    const seen = evidence(e);
    if (seen === null) {
      // No character to derive from. The platform may still be able to answer,
      // but only if it has already proved it tells the truth.
      const probed = capsFromProbe(e);
      if (probed === null) return; // keep whatever we last knew
      known = probed;
      paint();
      return;
    }
    calibrateCapsProbe(e, seen);
    known = seen;
    paint();
  };

  // keydown carries the character. Binding keyup for characters as well doubled
  // every update, and was how the two events' disagreeing modifier masks became
  // a visible flicker — so keyup is bound for exactly one key.
  input.onkeydown = update;
  input.onkeyup = (e) => {
    // The Caps Lock key itself produces no character, so it is the one press
    // that can change the answer without any evidence following it. On keyup the
    // lock has already toggled, unlike on keydown.
    if (e.key !== 'CapsLock') return;
    const probed = capsFromProbe(e);
    if (probed !== null) known = probed;
    else if (known !== null) known = !known; // no belief in the API, but we knew
    paint();
  };
  // Clicking in is the one moment a hint can appear before a single keystroke —
  // a MouseEvent carries the modifier state too, and by now the platform may
  // have earned being believed.
  input.onmousedown = (e) => {
    const probed = capsFromProbe(e);
    if (probed === null) return;
    known = probed;
    paint();
  };
  input.onblur = () => {
    // Caps Lock can be toggled while the field is unfocused, so the old reading
    // is not merely hidden, it is void.
    known = null;
    paint();
  };
  paint();
}

// ── Modal focus management ────────────────────────────────────────────────────

/**
 * Every overlay in this app is a `div` that gains a class, not a `<dialog>`.
 *
 * That means the browser does nothing for us: focus stays wherever it was, Tab
 * walks straight out of the modal into the grid behind it, and closing the
 * modal leaves focus on an element that is now hidden — at which point a
 * keyboard user is somewhere with no visible cursor and no way to tell where.
 *
 * These are the three things a `<dialog>` would have done.
 */
const MODAL_SELECTOR = '.modal-overlay.open, .shortcuts-overlay.open, .onboard-backdrop';

/**
 * Whether an element is actually on screen.
 *
 * Not `offsetParent !== null`, which is the usual shorthand and wrong twice
 * over: it is null for *every* `position: fixed` element even when visible —
 * and every overlay in this app is fixed — and jsdom does no layout, so it is
 * null for everything under test as well. Walking computed styles is correct in
 * both, and also catches `visibility: hidden`, which offsetParent misses.
 */
function isVisible(el: HTMLElement): boolean {
  if (el.hasAttribute('hidden')) return false;
  for (let node: HTMLElement | null = el; node; node = node.parentElement) {
    if (node.hasAttribute('hidden')) return false;
    const style = node.ownerDocument.defaultView?.getComputedStyle(node);
    if (!style) break;
    if (style.display === 'none' || style.visibility === 'hidden') return false;
  }
  return true;
}

/** Elements that can hold focus, in DOM order, excluding anything hidden. */
function focusablesIn(root: Element): HTMLElement[] {
  const sel =
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), ' +
    'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  return Array.from(root.querySelectorAll<HTMLElement>(sel)).filter(
    // This app hides the halves of a modal it is not using with `display:none`
    // (the confirm field on the unlock screen, for one). Tabbing into an
    // invisible field is worse than not trapping focus at all.
    (el) => isVisible(el) || el === document.activeElement,
  );
}

/** The open overlay nearest the top of the stack, or null. */
function topmostModal(): HTMLElement | null {
  // The observer below is asynchronous, so it can still fire after the document
  // it was watching has gone — on teardown in the test environment, and on
  // navigation in the app. Both surfaced as an unhandled ReferenceError with a
  // stack that named this function and nothing that called it.
  if (typeof document === 'undefined') return null;
  const open = Array.from(document.querySelectorAll<HTMLElement>(MODAL_SELECTOR));
  return open.length ? open[open.length - 1] : null;
}

let _returnFocusTo: HTMLElement | null = null;
let _modalFocusWired = false;

/**
 * Installs focus trapping and restoration for every overlay.
 *
 * Idempotent by flag, because `init()` is not the only thing that has ever
 * called a `wire*` helper twice — see invariant 9.
 */
export function wireModalFocus(): void {
  if (_modalFocusWired) return;
  _modalFocusWired = true;

  // Watching classes rather than patching every open/close site: there are
  // thirteen overlays and at least four modules that open one, and a rule that
  // has to be remembered at each of them is a rule that will be missed at one.
  const observer = new MutationObserver(() => {
    if (typeof document === 'undefined') return;
    const modal = topmostModal();
    if (modal) {
      if (!modal.contains(document.activeElement)) {
        _returnFocusTo = (document.activeElement as HTMLElement | null) ?? _returnFocusTo;
        // Deferred: several open paths call `.focus()` themselves a tick or two
        // later, and theirs is the better choice — a password field rather than
        // whatever happens to be first in the markup.
        setTimeout(() => {
          if (typeof document === 'undefined') return;
          const still = topmostModal();
          if (still && !still.contains(document.activeElement)) focusablesIn(still)[0]?.focus();
        }, 0);
      }
    } else if (_returnFocusTo) {
      // Restore only if the element is still in the document and visible: a
      // modal that replaced the thing that opened it (deleting the card whose
      // Edit button you pressed) must not throw focus at a detached node.
      const target = _returnFocusTo;
      _returnFocusTo = null;
      if (document.contains(target) && isVisible(target)) target.focus();
    }
  });
  observer.observe(document.body, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ['class'],
  });

  document.addEventListener(
    'keydown',
    (e) => {
      if (e.key !== 'Tab') return;
      const modal = topmostModal();
      if (!modal) return;
      const items = focusablesIn(modal);
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement as HTMLElement | null;
      // Focus outside the modal entirely (it was never moved in, or something
      // stole it) is pulled back rather than left where it is.
      if (!active || !modal.contains(active)) {
        e.preventDefault();
        (e.shiftKey ? last : first).focus();
        return;
      }
      if (e.shiftKey && active === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    },
    // Capture: the app binds its own Escape/Enter handlers on document, and the
    // trap has to run before anything can stop propagation.
    true,
  );
}

// ── Password strength ─────────────────────────────────────────────────────────

export interface PasswordStrength {
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
  color: string;
}

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
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  if (classes >= 3) bits++;
  if (new Set(pw).size < Math.min(6, pw.length)) bits--; // "aaaaaaaaaaaa" is not strong

  const score = Math.max(0, Math.min(4, bits)) as 0 | 1 | 2 | 3 | 4;
  const table: Record<number, [string, string]> = {
    0: ['Weak', 'var(--danger, #e05)'],
    1: ['Weak', 'var(--danger, #e05)'],
    2: ['Fair', 'var(--warn, #e8a33d)'],
    3: ['Good', 'var(--accent)'],
    4: ['Strong', 'var(--ok, #3ec98a)'],
  };
  const [label, color] = table[score];
  return { score, label, color };
}

/** Live-updates the strength meter beside a new-password field. */
export function wirePasswordStrength(inputId: string, wrapId: string): void {
  const input = document.getElementById(inputId) as HTMLInputElement | null;
  const wrap = document.getElementById(wrapId);
  const fill = document.getElementById(`${wrapId}-fill`);
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
  if (!items.length) {
    panel.style.display = 'none';
    return false;
  }

  // Search strings are user input that has been round-tripped through
  // localStorage — a vault imported from elsewhere never touches this, but the
  // settings blob is still plain JSON on disk, so escape it like any other
  // untrusted field (invariant 4).
  panel.innerHTML =
    `<div class="search-history-head">Recent searches` +
    `<button type="button" class="search-history-clear" data-clear-history>Clear</button></div>` +
    items
      .map(
        (q) =>
          `<button type="button" class="search-history-item" data-recent="${esc(q)}">` +
          `${CLOCK_SVG}<span>${esc(q)}</span></button>`,
      )
      .join('');
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

  input.addEventListener('focus', () => {
    if (!input.value.trim()) openSearchHistory(onPick);
  });
  input.addEventListener('input', () => {
    if (input.value) closeSearchHistory();
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      pushRecentSearch(input.value);
      closeSearchHistory();
    }
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
  if (secs < 60) return 'just now';
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'} ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  const days = Math.round(hours / 24);
  if (days === 1) return 'yesterday';
  if (days < 30) return `${days} days ago`;
  const months = Math.round(days / 30);
  if (months < 12) return `${months} month${months === 1 ? '' : 's'} ago`;
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
