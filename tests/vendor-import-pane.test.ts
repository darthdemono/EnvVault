/**
 * Import from another password manager (Phase 33.3). The parsing and merging is
 * Rust and is tested there; this drives the pane with a stub bridge and a faked
 * file picker.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

const $ = (id: string) => document.getElementById(id)!;
const flush = () => new Promise((r) => setTimeout(r, 40));

const plan = {
  entries: [{ id: 'new', provider: 'Imported', api_key: 'x' }],
  created: 1,
  updated: 0,
  unchanged: 2,
  skipped: 3,
  preview: [
    {
      provider: 'Imported',
      secret_type: 'password',
      fingerprint: 'sha256:abc',
      username: 'me',
      folder: null,
    },
  ],
};

function pickFile(text: string) {
  vi.spyOn(HTMLInputElement.prototype, 'click').mockImplementation(function (
    this: HTMLInputElement,
  ) {
    if (this.type !== 'file') return;
    Object.defineProperty(this, 'files', { value: [new File([text], 'export.json')] });
    this.onchange?.(new Event('change'));
  });
}

async function boot(invoke?: (cmd: string, args?: unknown) => Promise<unknown>) {
  loadRealIndexHtml();
  vi.resetModules();
  delete (window as unknown as { __TAURI__?: unknown }).__TAURI__;
  if (invoke) (window as unknown as { __TAURI__: unknown }).__TAURI__ = { core: { invoke } };
  (await import('../src/ts/tools-markup')).mountToolsPanes();
  const { st } = await import('../src/ts/state');
  resetState(st);
  st.vault = makeVault({ api_keys: [makeEntry({ id: 'a', provider: 'Alpha' })] });
  (await import('../src/ts/vendor-import-pane')).initVendorImportPane();
  return st;
}

beforeEach(() => vi.restoreAllMocks());

describe('vendor import pane', () => {
  it('needs the desktop app and says so', async () => {
    await boot();
    expect(($('vi-file-btn') as HTMLButtonElement).disabled).toBe(true);
    expect($('vi-status').textContent).toMatch(/unv import-vault/);
  });

  it('previews counts and fingerprints, then replaces the entries once on Import', async () => {
    const invoke = vi.fn(async (cmd: string) => (cmd === 'import_vault_plan' ? plan : null));
    const st = await boot(invoke);
    pickFile('{"items":[]}');
    $('vi-file-btn').click();
    await flush();
    expect($('vi-status').textContent).toContain('1 to create');
    expect($('vi-preview').textContent).toContain('sha256:abc');
    $('vi-apply-btn').click();
    await flush();
    expect(st.vault.api_keys.map((e) => e.provider)).toEqual(['Imported']);
  });

  it('shows the refusal when the file is not a usable export', async () => {
    const st = await boot(vi.fn(async () => Promise.reject(new Error('Not JSON: nope'))));
    pickFile('garbage');
    $('vi-file-btn').click();
    await flush();
    expect($('vi-status').textContent).toContain('Not JSON');
    expect(($('vi-apply-btn') as HTMLButtonElement).disabled).toBe(true);
    expect(st.vault.api_keys).toHaveLength(1);
  });
});
