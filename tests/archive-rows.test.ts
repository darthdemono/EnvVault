/**
 * Settings -> Full-fidelity archive (Phase 33.3). The cryptography is Rust
 * (`archive_tests` in envv-cli); this drives the two buttons.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { loadRealIndexHtml } from './helpers';

const saved: { name: string }[] = [];
let password: string | null = 'a long archive password';
vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return {
    ...real,
    showPasswordPrompt: async () => password,
    showConfirm: async () => true,
    saveFile: async (_c: string, name: string) => {
      saved.push({ name });
      return { ok: true as const, path: '/tmp/x.vaultarc' };
    },
  };
});

const $ = (id: string) => document.getElementById(id)!;
const flush = () => new Promise((r) => setTimeout(r, 40));

async function boot(invoke?: (cmd: string, args?: unknown) => Promise<unknown>) {
  loadRealIndexHtml();
  vi.resetModules();
  delete (window as unknown as { __TAURI__?: unknown }).__TAURI__;
  if (invoke) (window as unknown as { __TAURI__: unknown }).__TAURI__ = { core: { invoke } };
  (await import('../src/ts/settings-panel')).openSettings();
}

beforeEach(() => {
  saved.length = 0;
  password = 'a long archive password';
});

describe('archive rows', () => {
  it('are disabled with an explanation in a plain browser', async () => {
    await boot();
    expect(($('s-archive-btn') as HTMLButtonElement).disabled).toBe(true);
    expect($('s-archive-btn').title).toMatch(/envv backup archive/);
  });

  it('create asks Rust to build the archive and saves it through saveFile', async () => {
    const invoke = vi.fn(async (cmd: string) =>
      cmd === 'backup_archive_build' ? '{"magic":"x"}' : [],
    );
    await boot(invoke);
    $('s-archive-btn').click();
    await flush();
    expect(invoke).toHaveBeenCalledWith('backup_archive_build', { password });
    expect(saved[0].name).toBe('envvault.vaultarc');
    expect($('toast').textContent).toContain('Archive written');
  });

  it('create does nothing when the password prompt is cancelled', async () => {
    const invoke = vi.fn(async () => []);
    await boot(invoke);
    password = null;
    $('s-archive-btn').click();
    await flush();
    expect(invoke).not.toHaveBeenCalledWith('backup_archive_build', expect.anything());
    expect(saved).toHaveLength(0);
  });
});
