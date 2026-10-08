/**
 * Phase 32b, the mechanical half of "does this control do anything?".
 *
 * Boots the real shell (index.html + tools panes + vault.ts init), seeds a small
 * vault, then clicks every `button[id]` once and records whether *anything a
 * user could see* changed: the document, the toast, an open dialog. A click with
 * no visible effect is a control that is silent, dead, or decoration.
 *
 * The set of silent controls is pinned in `tests/efficacy-silent.json`, each with
 * the reason it is allowed to be. A new silent control fails this test: either
 * it is broken or it needs a written reason. This is the Phase 26 lesson
 * (Handoff-23): a test that calls the function proves nothing, so this drives
 * the control.
 */
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { st, resetViewState } from '../src/ts/state';
import { clearTransient, hadEffect } from './probe';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, saveFile: vi.fn(async () => '/tmp/x') };
});

type Allow = Record<string, string>;
const allowed: Allow = JSON.parse(
  readFileSync(join(process.cwd(), 'tests', 'efficacy-silent.json'), 'utf8'),
);

describe('every button with an id does something visible', () => {
  let nodes: ChildNode[] = [];
  const errors: string[] = [];

  beforeAll(async () => {
    loadRealIndexHtml();
    (await import('../src/ts/tools-markup')).mountToolsPanes();
    await import('../src/ts/vault');
    await new Promise((r) => setTimeout(r, 50));
    nodes = Array.from(document.body.childNodes);
    window.addEventListener('error', (e) => errors.push(String(e.message)));
    window.addEventListener('unhandledrejection', (e) => errors.push(String(e.reason)));
  });

  it('has no unexplained silent control', async () => {
    const silent: string[] = [];
    const threw: string[] = [];
    let clicked = 0;
    document.body.innerHTML = '';
    for (const n of nodes) document.body.appendChild(n);
    const ids = Array.from(document.querySelectorAll('button[id]')).map((b) => b.id);
    for (const id of ids) {
      if (process.env.EFFICACY_ONLY && !process.env.EFFICACY_ONLY.split(',').includes(id)) continue;
      document.body.innerHTML = '';
      for (const n of nodes) document.body.appendChild(n);
      resetState(st);
      resetViewState();
      st.vault = makeVault({
        api_keys: [
          makeEntry({ id: 'a', provider: 'Alpha' }),
          makeEntry({ id: 'b', provider: 'Bravo' }),
        ],
      });
      clearTransient();
      const btn = document.getElementById(id) as HTMLButtonElement | null;
      if (!btn || btn.disabled) continue;
      const nerr = errors.length;
      const effect = await hadEffect(() => btn.click());
      if (errors.length > nerr) threw.push(`${id}: ${errors[errors.length - 1]}`);
      clicked++;
      if (!effect) silent.push(id);
    }
    if (process.env.EFFICACY_REPORT) {
      writeFileSync(
        process.env.EFFICACY_REPORT,
        JSON.stringify({ total: ids.length, clicked, silent, threw }, null, 2),
      );
    }
    const unexplained = silent.filter((id) => !(id in allowed));
    const stale = Object.keys(allowed).filter((id) => !silent.includes(id));
    expect({ unexplained, threw, stale }).toEqual({ unexplained: [], threw: [], stale: [] });
  }, 120_000);
});
