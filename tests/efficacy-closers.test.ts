/**
 * Phase 32.1: the closers `efficacy.test.ts` can only mark "dialog not open".
 * For each, open its dialog (the `.open` class every overlay in this app uses),
 * press the control, and assert the dialog is no longer open.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadRealIndexHtml } from './helpers';

const silent: Record<string, string> = JSON.parse(
  readFileSync(join(process.cwd(), 'tests', 'efficacy-silent.json'), 'utf8'),
);
const closerIds = Object.entries(silent)
  .filter(([, why]) => why.startsWith('Closes a dialog'))
  .map(([id]) => id);

// Some closers are bound by the function that opens their dialog, not at start-up
// (assigned handlers, invariant 9), so adding `.open` is not enough for them.
const openers: Record<string, () => Promise<void>> = {
  'settings-cancel': async () => (await import('../src/ts/settings-panel')).openSettings(),
};

describe('every closer closes its dialog', () => {
  let nodes: ChildNode[] = [];
  beforeAll(async () => {
    loadRealIndexHtml();
    (await import('../src/ts/tools-markup')).mountToolsPanes();
    await import('../src/ts/vault');
    await new Promise((r) => setTimeout(r, 50));
    nodes = Array.from(document.body.childNodes);
  });

  it('knows its closers', () => {
    expect(closerIds.length).toBeGreaterThan(10);
  });

  it.each(closerIds)('%s', async (id) => {
    document.body.innerHTML = '';
    for (const n of nodes) document.body.appendChild(n);
    document.querySelectorAll('.open').forEach((el) => el.classList.remove('open'));
    const btn = document.getElementById(id)!;
    const dialog = btn.closest<HTMLElement>('[role="dialog"], [aria-modal="true"], .modal-overlay');
    expect(dialog, `${id} is inside a dialog`).not.toBeNull();
    if (openers[id]) await openers[id]();
    else dialog!.classList.add('open');
    expect(dialog!.classList.contains('open')).toBe(true);
    btn.click();
    await new Promise((r) => setTimeout(r, 40));
    expect(dialog!.classList.contains('open')).toBe(false);
  });
});
