/**
 * @file Accessibility contract (Phase 19.3).
 *
 * These are not style checks. Each one asserts a property that, when it breaks,
 * makes some part of the app unusable to somebody: a control with no name is a
 * button announced as "button", a `for=` pointing at nothing is a form field
 * with no label at all, and a focus trap that leaks puts a keyboard user behind
 * an open modal with no way back.
 *
 * They run against the real `index.html` for the same reason every other suite
 * here does — a hand-written fixture cannot catch an attribute a formatter drops.
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { loadRealIndexHtml } from './helpers';
import { wireModalFocus } from '../src/ts/ui-qol';

beforeAll(() => loadRealIndexHtml());
beforeEach(() => loadRealIndexHtml());

/** The accessible name of an element, by the rules that actually apply here. */
function accName(el: Element): string {
  const labelled = el.getAttribute('aria-labelledby');
  if (labelled) {
    const targets = labelled.split(/\s+/).map((id) => document.getElementById(id));
    // A resolvable reference counts as named even when the target is empty in
    // static markup: `#prompt-message` is filled by `showPrompt` at open time.
    // The dangling-reference test is what catches an unresolvable one.
    if (targets.some(Boolean)) {
      const text = targets
        .map((t) => t?.textContent?.trim() ?? '')
        .join(' ')
        .trim();
      return text || '(named by reference)';
    }
  }
  const aria = el.getAttribute('aria-label');
  if (aria?.trim()) return aria.trim();
  const id = el.getAttribute('id');
  if (id) {
    const lbl = document.querySelector(`label[for="${CSS.escape(id)}"]`);
    if (lbl?.textContent?.trim()) return lbl.textContent.trim();
  }
  if (el.closest('label')) return el.closest('label')!.textContent?.trim() ?? '';
  const text = (el.textContent ?? '').trim();
  if (text) return text;
  return el.getAttribute('title')?.trim() ?? '';
}

describe('landmarks and page structure', () => {
  it('has a skip link that points at a real, focusable target', () => {
    // Without it a keyboard user crosses the header, the activity bar and the
    // whole sidebar before reaching a single secret.
    const link = document.querySelector<HTMLAnchorElement>('.skip-link');
    expect(link, 'no .skip-link in index.html').toBeTruthy();
    const target = document.querySelector(link!.getAttribute('href')!);
    expect(target, 'skip link points at a missing element').toBeTruthy();
    // -1 rather than 0: programmatically focusable, not a tab stop of its own.
    expect(target!.getAttribute('tabindex')).toBe('-1');
  });

  it('exposes the header, sidebar and main region as landmarks', () => {
    expect(document.querySelector('header#header')?.getAttribute('role')).toBe('banner');
    expect(document.querySelector('aside#sidebar')?.getAttribute('aria-label')).toBeTruthy();
    expect(document.querySelector('main#content')).toBeTruthy();
  });

  it('announces the search box and its filter syntax', () => {
    const search = document.getElementById('search')!;
    expect(accName(search)).toBeTruthy();
    // The placeholder documents the filter syntax and disappears the moment
    // anything is typed — exactly when the syntax is being used.
    const describedBy = search.getAttribute('aria-describedby');
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy!)?.textContent).toMatch(/price|cat|env/);
  });

  it('marks the result count and the toast as live regions', () => {
    // A filter that empties the grid is otherwise a silent change of everything.
    expect(document.getElementById('result-count')?.getAttribute('aria-live')).toBe('polite');
    const toast = document.getElementById('toast')!;
    expect(toast.getAttribute('aria-live')).toBe('polite');
    // Not assertive: a toast reports what happened and must not interrupt
    // whatever the user is reading or typing.
    expect(toast.getAttribute('aria-live')).not.toBe('assertive');
  });
});

describe('the activity bar is a real tablist', () => {
  it('declares the roles, and every tab points at panels that exist', () => {
    const bar = document.getElementById('activity-bar')!;
    expect(bar.getAttribute('role')).toBe('tablist');
    const tabs = Array.from(bar.querySelectorAll('.activity-btn'));
    expect(tabs.length).toBeGreaterThan(0);
    for (const tab of tabs) {
      expect(tab.getAttribute('role'), 'a tab without role=tab').toBe('tab');
      expect(tab.getAttribute('aria-selected')).toMatch(/^(true|false)$/);
      for (const id of tab.getAttribute('aria-controls')!.split(/\s+/)) {
        expect(document.getElementById(id), `aria-controls names a missing #${id}`).toBeTruthy();
      }
    }
  });

  it('has exactly one tab stop, so the tablist costs one Tab press, not four', () => {
    const tabs = Array.from(document.querySelectorAll('.activity-btn'));
    const tabbable = tabs.filter((t) => t.getAttribute('tabindex') === '0');
    expect(tabbable.length).toBe(1);
    const selected = tabs.filter((t) => t.getAttribute('aria-selected') === 'true');
    expect(selected.length).toBe(1);
    // The tabbable one must be the selected one, or focus lands on a tab that
    // is not the one being shown.
    expect(tabbable[0]).toBe(selected[0]);
  });

  it('labels each sidebar panel by the tab that controls it', () => {
    for (const panel of Array.from(document.querySelectorAll('.sidebar-panel'))) {
      expect(panel.getAttribute('role')).toBe('tabpanel');
      const by = panel.getAttribute('aria-labelledby')!;
      expect(document.getElementById(by), `missing tab #${by}`).toBeTruthy();
    }
  });
});

describe('every control can be announced', () => {
  it('names every button in index.html', () => {
    const unnamed = Array.from(document.querySelectorAll('button'))
      .filter((b) => b.offsetParent !== null || true)
      .filter((b) => !accName(b))
      .map((b) => b.id || b.className || b.outerHTML.slice(0, 60));
    expect(unnamed, `buttons with no accessible name: ${unnamed.join(', ')}`).toEqual([]);
  });

  it('names every form control', () => {
    const unnamed = Array.from(document.querySelectorAll<HTMLElement>('input, select, textarea'))
      // A hidden bookkeeping field carries no meaning for anyone.
      .filter((el) => el.getAttribute('type') !== 'hidden')
      .filter((el) => !accName(el) && !el.getAttribute('placeholder'))
      .map((el) => el.id || el.outerHTML.slice(0, 70));
    expect(unnamed, `unlabelled controls: ${unnamed.join(', ')}`).toEqual([]);
  });

  it('has no <label for> pointing at a missing element', () => {
    // A dangling `for` is worse than no label: the field is unlabelled and the
    // markup claims otherwise, so no audit tool flags it either.
    const dangling = Array.from(document.querySelectorAll<HTMLLabelElement>('label[for]'))
      .filter((l) => !document.getElementById(l.htmlFor))
      .map((l) => `${l.htmlFor} (${l.textContent?.trim().slice(0, 30)})`);
    expect(dangling, `label[for] naming missing ids: ${dangling.join(', ')}`).toEqual([]);
  });

  it('has no aria-labelledby or aria-controls pointing at a missing element', () => {
    const broken: string[] = [];
    for (const attr of ['aria-labelledby', 'aria-controls', 'aria-describedby']) {
      for (const el of Array.from(document.querySelectorAll(`[${attr}]`))) {
        for (const id of el.getAttribute(attr)!.split(/\s+/).filter(Boolean)) {
          if (!document.getElementById(id)) broken.push(`${attr}="${id}"`);
        }
      }
    }
    expect(broken, `dangling references: ${broken.join(', ')}`).toEqual([]);
  });
});

describe('overlays are dialogs', () => {
  it('gives every overlay a dialog role, modal flag and a name or description', () => {
    const overlays = Array.from(document.querySelectorAll('.modal-overlay, .shortcuts-overlay'));
    expect(overlays.length).toBeGreaterThan(5);
    for (const ov of overlays) {
      const id = ov.id || ov.className;
      expect(ov.getAttribute('role'), `${id} is not a dialog`).toBe('dialog');
      expect(ov.getAttribute('aria-modal'), `${id} is not aria-modal`).toBe('true');
      const named =
        ov.getAttribute('aria-label') ||
        ov.getAttribute('aria-labelledby') ||
        ov.getAttribute('aria-describedby');
      expect(named, `${id} has nothing to announce`).toBeTruthy();
    }
  });
});

describe('div-based widgets declare what they replaced', () => {
  it('gives the project picker listbox semantics', () => {
    // It exists because WebKitGTK renders a ghost native listbox for
    // `<select multiple>` regardless of CSS hiding (Phase 3). The native
    // control it replaced was announced and keyboard-operable.
    const el = document.getElementById('f-project')!;
    expect(el.getAttribute('role')).toBe('listbox');
    expect(el.getAttribute('aria-multiselectable')).toBe('true');
    expect(accName(el)).toBeTruthy();
  });

  it('gives the project-type picker radiogroup semantics', () => {
    const el = document.querySelector('.project-type-picker')!;
    expect(el.getAttribute('role')).toBe('radiogroup');
    expect(accName(el)).toBeTruthy();
  });

  it('makes the sidebar resizer reachable and adjustable without a mouse', () => {
    // Sidebar width persists across restarts, so a mouse-only handle leaves a
    // keyboard user stuck with whatever width they inherited.
    const r = document.getElementById('sidebar-resizer')!;
    expect(r.getAttribute('role')).toBe('separator');
    expect(r.getAttribute('tabindex')).toBe('0');
    expect(accName(r)).toBeTruthy();
    expect(r.getAttribute('aria-valuenow')).toBeTruthy();
  });
});

describe('modal focus management', () => {
  // Every overlay here is a div that gains a class, not a <dialog>, so the
  // browser does none of this for us.
  const tab = (shift = false) =>
    document.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Tab', shiftKey: shift, bubbles: true }),
    );

  beforeEach(() => {
    loadRealIndexHtml();
    wireModalFocus();
  });

  const open = (id: string) => document.getElementById(id)!.classList.add('open');
  const close = (id: string) => document.getElementById(id)!.classList.remove('open');
  /**
   * The focus move is deliberately deferred by a `setTimeout(0)` so that an
   * overlay's own `.focus()` call wins over the generic "first focusable". Two
   * nested macrotasks, because a single `setTimeout(5)` is not reliably ordered
   * after a `setTimeout(0)` registered a microtask later — that raced.
   */
  const settle = async () => {
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 10));
  };

  it('moves focus into an overlay that opens', async () => {
    open('confirm-overlay');
    await settle();
    const overlay = document.getElementById('confirm-overlay')!;
    expect(overlay.contains(document.activeElement)).toBe(true);
  });

  it('keeps Tab inside the open overlay instead of walking into the grid behind it', async () => {
    open('confirm-overlay');
    await settle();
    const overlay = document.getElementById('confirm-overlay')!;
    // Cycle well past the number of controls the dialog has.
    for (let i = 0; i < 8; i++) {
      tab();
      expect(overlay.contains(document.activeElement)).toBe(true);
    }
    for (let i = 0; i < 8; i++) {
      tab(true);
      expect(overlay.contains(document.activeElement)).toBe(true);
    }
  });

  it('pulls focus back when something outside the overlay has it', async () => {
    open('confirm-overlay');
    await settle();
    document.getElementById('add-btn')!.focus();
    tab();
    expect(document.getElementById('confirm-overlay')!.contains(document.activeElement)).toBe(true);
  });

  it('returns focus to whatever opened the overlay', async () => {
    // Otherwise closing a dialog leaves focus on a hidden element, and a
    // keyboard user is somewhere with no visible cursor.
    const opener = document.getElementById('add-btn') as HTMLButtonElement;
    opener.focus();
    open('confirm-overlay');
    await settle();
    expect(document.activeElement).not.toBe(opener);
    close('confirm-overlay');
    await settle();
    expect(document.activeElement).toBe(opener);
  });

  it('traps in the topmost overlay when two are open', async () => {
    // The unlock screen can sit under a confirm; the trap must follow the one on
    // top rather than the first in document order.
    open('confirm-overlay');
    await settle();
    open('prompt-overlay');
    await settle();
    const top = document.getElementById('prompt-overlay')!;
    for (let i = 0; i < 5; i++) {
      tab();
      expect(top.contains(document.activeElement)).toBe(true);
    }
  });

  it('does nothing at all when no overlay is open', () => {
    const btn = document.getElementById('add-btn') as HTMLButtonElement;
    btn.focus();
    tab();
    // No preventDefault, no forced move — the browser's own tab order applies.
    expect(document.activeElement).toBe(btn);
  });
});
