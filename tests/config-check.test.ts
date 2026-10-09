/**
 * The config-view panel for cross-chunk checks (Phase 29). Rust owns the rules
 * (`vault-core/src/config_check.rs`); what is asserted here is what the app does
 * around them: the IPC contract, silence when clean or outside Tauri, escaping of
 * names that come from the vault, and that clicking a finding finds its card.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

type Call = { cmd: string; args: any };
let calls: Call[] = [];

async function load(answer: unknown) {
  vi.resetModules();
  (window as any).__TAURI__ = {
    core: {
      invoke: (cmd: string, args: any) => {
        calls.push({ cmd, args });
        return Promise.resolve(answer);
      },
    },
  };
  const mod = await import('../src/ts/config-check');
  const { st } = await import('../src/ts/state');
  st.vault = {
    api_keys: [{ id: 'e', provider: 'GitHub', key_id: 'prod', api_key: 'x' }],
    user_categories: [],
    projects: [],
  } as any;
  return mod;
}

const project = { id: 'p', name: 'P', chunks: [] } as any;
const finding = (over: object = {}) => ({
  rule: 'wireguard-allowed-ips-duplicate',
  severity: 'error',
  chunk_id: 'c1',
  chunk: 'peer b',
  chunk_type: 'wg_peer',
  field: 'AllowedIPs',
  message: 'AllowedIPs `10.0.0.2` is also claimed by peer `a`',
  related: ['a'],
  ...over,
});

beforeEach(() => {
  calls = [];
  document.body.innerHTML = '';
});
afterEach(() => {
  delete (window as any).__TAURI__;
});

describe('config check panel', () => {
  it('sends the project and the vault entry names, camelCased', async () => {
    const { checkProject } = await load([]);
    await checkProject(project);
    expect(calls).toHaveLength(1);
    expect(calls[0].cmd).toBe('config_check_project');
    expect(calls[0].args.project).toBe(project);
    expect(calls[0].args.vaultNames).toEqual(['GitHub_prod', 'GitHub']);
  });

  it('sends the services of every project only when the wide scope is on', async () => {
    const { checkProject, elsewhereServices } = await load([]);
    const { st, Settings } = await import('../src/ts/state');
    st.vault.projects = [
      {
        id: 'b',
        name: 'Backend',
        chunks: [
          {
            id: '1',
            name: 'My API',
            chunk_type: 'docker_service',
            fields: [{ key: 'container_name', value: 'Api-1' }],
          },
          { id: '2', name: 'off', chunk_type: 'docker_service', fields: [], disabled: true },
          { id: '3', name: 'site', chunk_type: 'nginx_location', fields: [] },
        ],
      },
    ] as any;
    expect(elsewhereServices().sort()).toEqual(['api-1', 'my_api']);
    await checkProject(project);
    expect(calls[0].args.elsewhere).toEqual([]);
    Settings.set('configCheckAll', true);
    await checkProject(project);
    expect(calls[1].args.elsewhere.sort()).toEqual(['api-1', 'my_api']);
    Settings.set('configCheckAll', false);
  });

  it('stays hidden when the project is clean', async () => {
    const { mountConfigCheck } = await load([]);
    const host = document.createElement('section');
    host.hidden = true;
    document.body.appendChild(host);
    await mountConfigCheck(project, host);
    expect(host.hidden).toBe(true);
    expect(host.innerHTML).toBe('');
  });

  it('does nothing and does not call IPC outside the desktop app', async () => {
    const { mountConfigCheck } = await load([finding()]);
    delete (window as any).__TAURI__;
    calls = [];
    const host = document.createElement('section');
    host.hidden = true;
    document.body.appendChild(host);
    await mountConfigCheck(project, host);
    expect(calls).toHaveLength(0);
    expect(host.hidden).toBe(true);
  });

  it('shows findings, counts errors and warnings, and escapes names from the vault', async () => {
    const evil = '<img src=x onerror=alert(1)>';
    const { mountConfigCheck } = await load([
      finding({ chunk: evil, message: evil }),
      finding({ severity: 'warning', rule: 'x', chunk_id: 'c2' }),
    ]);
    const host = document.createElement('section');
    host.hidden = true;
    document.body.appendChild(host);
    await mountConfigCheck(project, host);
    expect(host.hidden).toBe(false);
    expect(host.querySelector('img')).toBeNull();
    expect(host.textContent).toContain(evil);
    expect(host.querySelector('.config-check-head')!.textContent).toMatch(/1 error, 1\s+warning/);
    expect(host.querySelectorAll('.config-check-item')).toHaveLength(2);
  });

  it('a finding that arrives after the view was replaced paints nothing', async () => {
    const { mountConfigCheck } = await load([finding()]);
    const host = document.createElement('section'); // never attached
    await mountConfigCheck(project, host);
    expect(host.innerHTML).toBe('');
  });

  it('clicking a finding flashes the matching chunk card, found by id not by selector', async () => {
    const { mountConfigCheck } = await load([finding({ chunk_id: 'weird"]id' })]);
    document.body.innerHTML = `<div class="chunk-card" id="target"><button data-chunk-id="weird&quot;]id"></button></div><div class="chunk-card" id="other"><button data-chunk-id="c2"></button></div>`;
    const host = document.createElement('section');
    document.body.appendChild(host);
    (Element.prototype as any).scrollIntoView = () => {};
    await mountConfigCheck(project, host);
    host.querySelector<HTMLElement>('[data-check-chunk]')!.click();
    expect(document.getElementById('target')!.classList.contains('flash')).toBe(true);
    expect(document.getElementById('other')!.classList.contains('flash')).toBe(false);
  });
});
