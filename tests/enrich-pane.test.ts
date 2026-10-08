/**
 * Tools -> Enrich (Phase 33.1). jsdom has no Tauri, so the browser branch is the
 * default and the IPC branch is reached by installing a bridge before a fresh
 * import. The planner itself is Rust and is tested there (`enrich.rs`).
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

let confirmAnswer = true;
const confirmed: string[] = [];
vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return {
    ...real,
    showConfirm: async (m: string) => {
      confirmed.push(m);
      return confirmAnswer;
    },
  };
});

const $ = (id: string) => document.getElementById(id)!;
const flush = () => new Promise((r) => setTimeout(r, 30));

const plan = [
  {
    id: 'a',
    provider: 'Alpha',
    fingerprint: 'sha256:abc',
    proposals: [
      { field: 'custom_icon', value: 'github', reason: 'prefix ghp_' },
      { field: 'tags', value: ['github'], reason: 'issuer recognised' },
    ],
  },
];

beforeEach(() => {
  loadRealIndexHtml();
  vi.resetModules();
  delete (window as unknown as { __TAURI__?: unknown }).__TAURI__;
});

async function boot(invoke?: (cmd: string, args?: unknown) => Promise<unknown>) {
  if (invoke) (window as unknown as { __TAURI__: unknown }).__TAURI__ = { core: { invoke } };
  (await import('../src/ts/tools-markup')).mountToolsPanes();
  const { st } = await import('../src/ts/state');
  resetState(st);
  st.vault = makeVault({ api_keys: [makeEntry({ id: 'a', provider: 'Alpha' })] });
  const { initEnrichPane } = await import('../src/ts/enrich-pane');
  initEnrichPane();
  return st;
}

describe('Enrich pane', () => {
  it('says it needs the desktop app in a plain browser', async () => {
    await boot();
    expect(($('enrich-preview-btn') as HTMLButtonElement).disabled).toBe(true);
    expect($('enrich-status').textContent).toMatch(/desktop app/i);
  });

  it('previews proposals with reasons and writes only the ticked ones', async () => {
    const invoke = vi.fn(async (cmd: string) => {
      if (cmd === 'enrich_plan') return plan;
      return null; // persist() saves through the store; the local store tolerates this stub
    });
    const st = await boot(invoke);
    $('enrich-preview-btn').click();
    await flush();
    expect($('enrich-results').textContent).toContain('prefix ghp_');
    expect(invoke).toHaveBeenCalledWith('enrich_plan', expect.objectContaining({ force: false }));
    const boxes = document.querySelectorAll<HTMLInputElement>('#enrich-results input[data-enrich]');
    expect(boxes).toHaveLength(2);
    boxes[1].checked = false;
    $('enrich-apply-btn').click();
    await flush();
    const entry = st.vault.api_keys[0] as unknown as Record<string, unknown>;
    expect(entry.custom_icon).toBe('github');
    expect(entry.tags).toBeUndefined();
  });

  it('refuses to apply with nothing ticked', async () => {
    const invoke = vi.fn(async () => plan);
    await boot(invoke);
    $('enrich-preview-btn').click();
    await flush();
    document
      .querySelectorAll<HTMLInputElement>('#enrich-results input[data-enrich]')
      .forEach((b) => (b.checked = false));
    $('enrich-apply-btn').click();
    await flush();
    expect($('toast').textContent).toMatch(/Tick at least one/);
  });

  it('reports a planner failure instead of staying silent', async () => {
    await boot(vi.fn(async () => Promise.reject(new Error('boom'))));
    $('enrich-preview-btn').click();
    await flush();
    expect($('enrich-status').textContent).toContain('boom');
  });
});

describe('Diagnose (envv doctor: document and file checks)', () => {
  it('lists document and file findings together', async () => {
    const invoke = vi.fn(async (cmd: string) =>
      cmd === 'doctor_document'
        ? [
            {
              check: 'entry-ids',
              level: 'warn',
              message: '2 entries have no id',
              remedy: 'run envv doctor --fix',
            },
          ]
        : cmd === 'doctor_file'
          ? [
              {
                check: 'integrity',
                level: 'ok',
                message: 'Database structure is intact',
                remedy: '',
              },
            ]
          : null,
    );
    await boot(invoke);
    const { initDoctorPane } = await import('../src/ts/enrich-pane');
    initDoctorPane();
    $('doctor-run-btn').click();
    await flush();
    expect($('doctor-results').textContent).toContain('2 entries have no id');
    expect($('doctor-status').textContent).toMatch(/1 thing/);
    expect($('doctor-results').textContent).toContain('Database structure is intact');
    expect(invoke.mock.calls.some((c) => c[0] === 'doctor_file')).toBe(true);
  });

  it('is disabled with an explanation in a plain browser', async () => {
    await boot();
    const { initDoctorPane } = await import('../src/ts/enrich-pane');
    initDoctorPane();
    expect(($('doctor-run-btn') as HTMLButtonElement).disabled).toBe(true);
  });
});

describe('Enrich --online (Phase 33.1b)', () => {
  const targets = [{ id: 'a', provider: 'Alpha', issuer: 'GitHub' }];
  const live = [
    {
      id: 'a',
      provider: 'Alpha',
      issuer: 'GitHub',
      status: 'ok',
      detail: '',
      proposals: [{ field: 'account_name', value: 'octocat', reason: 'GitHub says so' }],
    },
  ];

  beforeEach(() => {
    confirmed.length = 0;
    confirmAnswer = true;
  });

  it('names the recipients, then asks the issuers and merges the answer', async () => {
    const invoke = vi.fn(async (cmd: string) =>
      cmd === 'enrich_plan' ? [] : cmd === 'enrich_online_targets' ? targets : live,
    );
    await boot(invoke);
    ($('enrich-online') as HTMLInputElement).checked = true;
    $('enrich-preview-btn').click();
    await flush();
    expect(confirmed[0]).toContain('GitHub (1)');
    expect(invoke.mock.calls.some((c) => c[0] === 'enrich_online')).toBe(true);
    expect($('enrich-results').textContent).toContain('GitHub: ok');
    expect($('enrich-results').textContent).toContain('octocat');
  });

  it('sends nothing when the consent is declined', async () => {
    confirmAnswer = false;
    const invoke = vi.fn(async (cmd: string) =>
      cmd === 'enrich_plan' ? [] : cmd === 'enrich_online_targets' ? targets : live,
    );
    await boot(invoke);
    ($('enrich-online') as HTMLInputElement).checked = true;
    $('enrich-preview-btn').click();
    await flush();
    expect(invoke.mock.calls.some((c) => c[0] === 'enrich_online')).toBe(false);
    expect($('enrich-status').textContent).toMatch(/nothing was sent|0 entr/i);
  });

  it('never contacts anyone when the box is not ticked', async () => {
    const invoke = vi.fn(async (_cmd: string) => []);
    await boot(invoke);
    $('enrich-preview-btn').click();
    await flush();
    expect(invoke.mock.calls.some((c) => String(c[0]).startsWith('enrich_online'))).toBe(false);
  });
});
