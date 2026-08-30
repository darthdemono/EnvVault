/**
 * "→ Inject" in the Tools panel.
 *
 * Reported as "the secret generator's inject button does nothing". It did
 * something — it just did it invisibly. `injectIntoForm` guarded on
 * `document.getElementById('f-key')` being non-null, and `#f-key` is static
 * markup in `index.html`, so it is present whether or not the Add/Edit modal is
 * open. With the modal closed the button wrote the generated secret into a
 * hidden input, showed a green "Injected into form" toast, and the value was
 * then discarded: `openModal` never reads that field back and `closeModal`
 * clears the draft.
 *
 * This is invariant 8 in the other direction. That invariant says hiding a
 * control is not the same as preventing the action; this is the same confusion
 * read backwards — presence in the DOM is not the same as being on screen.
 *
 * All four generator panes (secret, password, API key, hash) route through this
 * one function, so all four were affected.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { injectIntoForm, openModal, closeModal } from '../src/ts/modals';
import { loadRealIndexHtml } from './helpers';

const keyField = () => document.getElementById('f-key') as HTMLInputElement;
const overlay = () => document.getElementById('modal-overlay')!;

beforeEach(() => {
  loadRealIndexHtml();
});

describe('with the Add/Edit form closed', () => {
  it('does not write the value anywhere', () => {
    expect(overlay().classList.contains('open')).toBe(false);
    // The field exists regardless — that is the whole bug.
    expect(keyField()).not.toBeNull();
    injectIntoForm('super-secret-value');
    expect(keyField().value).toBe('');
  });

  it('says what to do instead of claiming success', () => {
    injectIntoForm('super-secret-value');
    const toast = document.getElementById('toast')!;
    expect(toast.textContent).toMatch(/Open the Add\/Edit form first/);
    expect(toast.className).toContain('err');
  });
});

describe('with the Add/Edit form open', () => {
  it('fills the secret field, focuses it, and confirms', () => {
    openModal('Add', -1);
    injectIntoForm('super-secret-value');
    expect(keyField().value).toBe('super-secret-value');
    expect(document.activeElement).toBe(keyField());
    const toast = document.getElementById('toast')!;
    expect(toast.textContent).toBe('Injected into form');
    expect(toast.className).toContain('ok');
  });

  it('stops working again once the form is closed', () => {
    openModal('Add', -1);
    closeModal();
    injectIntoForm('later-value');
    expect(keyField().value).not.toBe('later-value');
  });
});
