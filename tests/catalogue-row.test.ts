import { describe, it, expect, beforeEach, vi } from 'vitest';
import { loadRealIndexHtml } from './helpers';

// The Settings "Provider catalogue" row (Phase 31.1). jsdom has no Tauri, so the
// browser branch is the default and the IPC branch is reached by installing a
// bridge before a fresh import (the module-scope `inTauri` const, see AGENTS.md).
describe('provider catalogue settings row', () => {
  beforeEach(() => {
    loadRealIndexHtml();
    vi.resetModules();
    delete (window as unknown as { __TAURI__?: unknown }).__TAURI__;
  });

  it('exists in the real markup', () => {
    expect(document.getElementById('s-catalogue-update')).not.toBeNull();
    expect(document.getElementById('s-catalogue-status')).not.toBeNull();
  });

  it('is disabled with an explanation in a plain browser', async () => {
    const m = await import('../src/ts/settings-panel');
    m.openSettings();
    const btn = document.getElementById('s-catalogue-update') as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(document.getElementById('s-catalogue-status')!.textContent).toMatch(/desktop app/i);
  });

  it('shows the Rust refusal verbatim when the update fails', async () => {
    const invoke = vi.fn(async (cmd: string) => {
      if (cmd === 'catalogue_status') return { source: 'bundled' };
      throw new Error('signature does not match the pinned key');
    });
    (window as unknown as { __TAURI__: unknown }).__TAURI__ = { core: { invoke } };
    const m = await import('../src/ts/settings-panel');
    m.openSettings();
    await Promise.resolve();
    const btn = document.getElementById('s-catalogue-update') as HTMLButtonElement;
    btn.click();
    await new Promise((r) => setTimeout(r, 0));
    expect(document.getElementById('s-catalogue-status')!.textContent).toContain('pinned key');
    expect(invoke).toHaveBeenCalledWith('catalogue_update', {});
  });
});
