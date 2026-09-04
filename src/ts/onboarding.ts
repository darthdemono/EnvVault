/**
 * @file
 * First-run onboarding wizard.
 *
 * Four steps, shown once after a vault is created, and re-openable from
 * Settings. It is deliberately **not** a tutorial: every step either writes a
 * setting the user would otherwise never find, or performs the one action that
 * turns an empty vault into a useful one.
 *
 * Two structural decisions worth knowing before editing this file.
 *
 * **The overlay is built and destroyed per showing, not hidden.** Every handler
 * is therefore bound to a node that exists for exactly one wizard run, which
 * makes invariant 9 (handlers assigned, never accumulated) hold by construction
 * rather than by discipline — and it sidesteps the WebKitGTK ghost widgets that
 * static hidden markup produces.
 *
 * **Nothing here is a gate.** Skipping the wizard must leave a working vault, so
 * every step's effect is either a setting with a sane default already in place
 * or an action the user can take later from the normal UI. A wizard that has to
 * be completed is a wizard that gets completed wrongly at speed.
 */

import { Settings, st } from './state';
import { esc, showToast } from './utils';

/** Steps, in order. `render` returns the body; `commit` runs on "Next". */
interface Step {
  id: string;
  title: string;
  /** One line under the title. Sets expectations for what this step asks for. */
  blurb: string;
  render: () => string;
  /** Applied when the user leaves the step forwards. Never on Back or Skip. */
  commit?: () => void | Promise<void>;
}

let _overlay: HTMLDivElement | null = null;
/**
 * Detaches the wizard's document-level Escape handler.
 *
 * Module-level because the wizard has two exits — the footer buttons and the
 * action buttons on the last step — and only one of them lives in the closure
 * that created the listener. The same shape as `_ddCleanup` in `modals.ts`, and
 * for the same reason: a listener whose remover is unreachable is a listener
 * that stays.
 */
let _detachKeys: (() => void) | null = null;

/**
 * Whether the wizard should run on this launch.
 *
 * Keyed on the setting alone, not on "the vault is empty": a user who deleted
 * every entry is not a new user, and showing them the welcome screen again reads
 * as the app having forgotten them.
 */
export function shouldShowOnboarding(): boolean {
  return !Settings.get('onboardingCompleted');
}

/**
 * What the last step's buttons do.
 *
 * Passed in rather than imported: `modals` and `import-export` both reach back
 * into this module's neighbours, and importing them at module scope makes a
 * cycle that Vite resolves by handing back a half-initialised module.
 */
export interface OnboardingActions {
  onAdd: () => void;
  onImport: () => void;
}

/**
 * Opens the wizard. Safe to call twice — the second call is ignored.
 *
 * Synchronous: it builds DOM and returns. It was `async` first, which made
 * every call site look as though it were waiting for the user to finish.
 */
export function showOnboarding(actions: OnboardingActions): void {
  if (_overlay) return;

  const steps = buildSteps();
  let index = 0;

  const overlay = document.createElement('div');
  _overlay = overlay;
  overlay.className = 'onboard-backdrop';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.setAttribute('aria-labelledby', 'onboard-title');
  overlay.innerHTML = `
    <div class="onboard-card">
      <div class="onboard-progress" id="onboard-progress" aria-hidden="true"></div>
      <div class="onboard-head">
        <h2 class="onboard-title" id="onboard-title"></h2>
        <p class="onboard-blurb" id="onboard-blurb"></p>
      </div>
      <div class="onboard-body" id="onboard-body"></div>
      <div class="onboard-foot">
        <button class="btn btn-sm btn-ghost" id="onboard-skip">Skip setup</button>
        <div class="onboard-foot-right">
          <button class="btn btn-sm btn-ghost" id="onboard-back">Back</button>
          <button class="btn btn-sm btn-accent" id="onboard-next">Next</button>
        </div>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  // The header carries a backdrop-filter, which creates a compositing layer that
  // wins over z-index against any overlay — the same collision the unlock modal
  // hits. Hiding it is the established fix in this codebase.
  const header = document.getElementById('header');
  const headerDisplay = header?.style.display ?? '';
  if (header) header.style.display = 'none';

  const $ = (id: string) => overlay.querySelector<HTMLElement>(`#${id}`)!;

  const paint = () => {
    const step = steps[index];
    $('onboard-title').textContent = step.title;
    $('onboard-blurb').textContent = step.blurb;
    $('onboard-body').innerHTML = step.render();
    $('onboard-progress').innerHTML = steps
      .map(
        (_, i) =>
          `<span class="onboard-dot${i === index ? ' active' : i < index ? ' done' : ''}"></span>`,
      )
      .join('');
    ($('onboard-back') as HTMLButtonElement).disabled = index === 0;
    $('onboard-next').textContent = index === steps.length - 1 ? 'Finish' : 'Next';
    // Assignment, not addEventListener: `paint` replaces the body on every step
    // change, and the last step is reachable more than once via Back.
    const add = overlay.querySelector<HTMLButtonElement>('#onboard-add');
    if (add)
      add.onclick = () => {
        closeForAction();
        actions.onAdd();
      };
    const imp = overlay.querySelector<HTMLButtonElement>('#onboard-import');
    if (imp)
      imp.onclick = () => {
        closeForAction();
        actions.onImport();
      };

    // Focus the first control in the step, so the wizard is usable without a
    // mouse and a screen reader announces where it landed.
    overlay.querySelector<HTMLElement>('.onboard-body input, .onboard-body button')?.focus();
  };

  const close = (completed: boolean) => {
    _detachKeys?.();
    if (header) header.style.display = headerDisplay;
    if (document.body.contains(overlay)) document.body.removeChild(overlay);
    _overlay = null;
    // Marked done on skip as well as on finish. Re-showing a wizard somebody
    // deliberately dismissed is the single most reliable way to make it
    // annoying; Settings has a button to run it again on purpose.
    Settings.set('onboardingCompleted', true);
    if (completed) showToast('Setup complete', 'ok', 1800);
  };

  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape') close(false);
  };
  document.addEventListener('keydown', onKey);
  _detachKeys = () => {
    document.removeEventListener('keydown', onKey);
    _detachKeys = null;
  };

  ($('onboard-skip') as HTMLButtonElement).onclick = () => close(false);
  ($('onboard-back') as HTMLButtonElement).onclick = () => {
    if (index > 0) index--;
    paint();
  };
  ($('onboard-next') as HTMLButtonElement).onclick = async () => {
    try {
      await steps[index].commit?.();
    } catch (e: any) {
      showToast('Could not save that step: ' + (e?.message ?? e), 'err');
      return;
    }
    if (index === steps.length - 1) {
      close(true);
      return;
    }
    index++;
    paint();
  };

  paint();
}

// ── Steps ─────────────────────────────────────────────────────────────────────

function buildSteps(): Step[] {
  return [
    {
      id: 'welcome',
      title: 'Welcome to EnvVault',
      blurb: 'Four short steps. You can skip them and change everything later.',
      render: () => `
        <ul class="onboard-facts">
          <li><strong>Your key never leaves this machine.</strong> The master password derives the
              database key with Argon2id; the key is held in memory and zeroized on lock.</li>
          <li><strong>Nothing is sent anywhere.</strong> No telemetry, no account, no sync — unless
              you deliberately run a server and connect to it.</li>
          <li><strong>Lose the master password and the vault is gone.</strong> There is no reset,
              because a reset would be a second way in. Keep a written copy somewhere safe.</li>
        </ul>`,
    },
    {
      id: 'locking',
      title: 'When should the vault lock?',
      blurb: 'The default is 60 minutes of inactivity. Zero disables the timer entirely.',
      render: () => {
        const mins = Settings.get('autoLockMinutes');
        const hide = Settings.get('lockOnHide');
        return `
        <label class="onboard-field">
          <span class="onboard-field-label" id="onboard-autolock-label">Auto-lock after (minutes)</span>
          <input id="onboard-autolock" class="tool-input" type="number" min="0" max="1440"
                 value="${esc(String(mins))}" aria-labelledby="onboard-autolock-label">
        </label>
        <label class="onboard-check">
          <input type="checkbox" id="onboard-lockhide"${hide ? ' checked' : ''}>
          <span>Also lock the moment the window is hidden</span>
        </label>
        <p class="onboard-note">Locking on hide is off by default: it used to be unconditional, and
        alt-tabbing away ended your session. The inactivity timer already covers walking away.</p>`;
      },
      commit: () => {
        const el = document.getElementById('onboard-autolock') as HTMLInputElement | null;
        // A number input hands back "" for text it refused, so "unparseable" and
        // "blank" are the same case here — `??` would let both through as NaN,
        // and NaN minutes is a timer that never fires.
        const raw = parseInt(el?.value ?? '', 10);
        const mins = Number.isFinite(raw) ? Math.min(1440, Math.max(0, raw)) : 60;
        Settings.set('autoLockMinutes', mins);
        Settings.set(
          'lockOnHide',
          !!(document.getElementById('onboard-lockhide') as HTMLInputElement | null)?.checked,
        );
      },
    },
    {
      id: 'masking',
      title: 'How should values appear?',
      blurb: 'Masked by default keeps secrets off screen until you ask for them.',
      render: () => {
        const mask = Settings.get('maskKeysByDefault');
        return `
        <label class="onboard-check">
          <input type="checkbox" id="onboard-mask"${mask ? ' checked' : ''}>
          <span>Mask secret values until revealed</span>
        </label>
        <p class="onboard-note">This is a display default, not a security boundary — the values are
        in the vault either way. It exists because a screen share, a photo or someone walking past
        should not be enough.</p>`;
      },
      commit: () => {
        Settings.set(
          'maskKeysByDefault',
          !!(document.getElementById('onboard-mask') as HTMLInputElement | null)?.checked,
        );
      },
    },
    {
      id: 'first-secret',
      title: 'Add your first secret',
      blurb: 'Or close this and use the + button whenever you are ready.',
      render: () => {
        const n = st.vault.api_keys.length;
        return `
        ${
          n
            ? `<p class="onboard-note">This vault already holds ${n} ${n === 1 ? 'entry' : 'entries'}.</p>`
            : ''
        }
        <div class="onboard-actions">
          <button class="btn btn-sm" id="onboard-add">Add a secret manually</button>
          <button class="btn btn-sm" id="onboard-import">Import a .env file</button>
        </div>
        <p class="onboard-note">Everything here is also on the command line —
        <code>envv entry add</code> and <code>envv import</code>. The two halves are kept at
        deliberate parity, so anything you can do in one you can script in the other.</p>`;
      },
    },
  ];
}

/** Dismisses the wizard because the user chose an action that replaces it. */
function closeForAction(): void {
  if (!_overlay) return;
  _detachKeys?.();
  const header = document.getElementById('header');
  if (header) header.style.display = '';
  if (document.body.contains(_overlay)) document.body.removeChild(_overlay);
  _overlay = null;
  Settings.set('onboardingCompleted', true);
}

/** True while the wizard is on screen. Used by tests and by the Settings button. */
export function onboardingIsOpen(): boolean {
  return _overlay !== null;
}
