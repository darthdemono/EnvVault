/**
 * Phase 32.2(b): `<select>`, checkbox and number controls in Settings. They apply
 * on Save, not on change, so the question is not "did the screen move" but "does
 * changing this control and pressing Save change a stored setting". A control
 * wired to nothing (or whose Save reads a different id) fails here. Controls that
 * are actions rather than settings are listed, with a reason, in
 * `efficacy-settings-silent.json`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Settings } from '../src/ts/state';
import { loadRealIndexHtml } from './helpers';

const allowed: Record<string, string> = JSON.parse(
  readFileSync(join(process.cwd(), 'tests', 'efficacy-settings-silent.json'), 'utf8'),
);

describe('every Settings control is wired to a stored setting', () => {
  let nodes: ChildNode[] = [];
  beforeAll(async () => {
    loadRealIndexHtml();
    (await import('../src/ts/tools-markup')).mountToolsPanes();
    await import('../src/ts/vault');
    await new Promise((r) => setTimeout(r, 50));
    nodes = Array.from(document.body.childNodes);
  });

  it('has no control that Save ignores', async () => {
    const { openSettings } = await import('../src/ts/settings-panel');
    const reset = () => {
      document.body.innerHTML = '';
      for (const n of nodes) document.body.appendChild(n);
      openSettings();
    };
    reset();
    const ids = Array.from(
      document.querySelectorAll<HTMLElement>(
        '#settings-overlay input[id], #settings-overlay select[id], #settings-overlay textarea[id]',
      ),
    )
      .filter((el) => (el as HTMLInputElement).type !== 'file')
      .map((el) => el.id);
    const silent: string[] = [];
    for (const id of ids) {
      reset();
      const el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement;
      const before = JSON.stringify(Settings.getAll());
      if (el instanceof HTMLSelectElement) {
        const next = Array.from(el.options).find((o) => o.value !== el.value);
        if (!next) continue;
        el.value = next.value;
      } else if (el.type === 'checkbox' || el.type === 'radio') {
        el.checked = !el.checked;
      } else if (el.type === 'number') {
        el.value = String(Number(el.value || 0) + 1);
      } else if (el.type === 'color') {
        el.value = el.value === '#123456' ? '#654321' : '#123456';
      } else if (el.type === 'range') {
        el.value = el.value === el.max ? el.min : el.max;
      } else {
        el.value = `${el.value}x`;
      }
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      document.getElementById('settings-save')!.click();
      await new Promise((r) => setTimeout(r, 30));
      if (JSON.stringify(Settings.getAll()) === before) silent.push(id);
    }
    // Segmented groups (`<div id><button data-val>`) and the theme swatches are
    // buttons, not inputs, and apply on Save the same way.
    const groups = Array.from(
      new Set(
        Array.from(
          document.querySelectorAll<HTMLElement>('#settings-overlay button[data-val]'),
        ).map((b) => b.parentElement?.id ?? ''),
      ),
    ).filter(Boolean);
    for (const id of [...groups, 'theme-swatches']) {
      reset();
      const group = document.getElementById(id)!;
      const candidates = Array.from(group.querySelectorAll<HTMLElement>('button, .theme-swatch'));
      const next = candidates.find((b) => !b.classList.contains('active'));
      if (!next) continue;
      const before = JSON.stringify(Settings.getAll());
      next.click();
      document.getElementById('settings-save')!.click();
      await new Promise((r) => setTimeout(r, 30));
      if (JSON.stringify(Settings.getAll()) === before) silent.push(id);
      ids.push(id);
    }
    if (process.env.EFFICACY_REPORT) {
      writeFileSync(
        process.env.EFFICACY_REPORT,
        JSON.stringify({ total: ids.length, silent }, null, 2),
      );
    }
    expect({
      unexplained: silent.filter((i) => !(i in allowed)),
      stale: Object.keys(allowed).filter((i) => !silent.includes(i)),
    }).toEqual({ unexplained: [], stale: [] });
  }, 300_000);
});
