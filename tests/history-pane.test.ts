/**
 * Tools -> Config history (Phase 35). The dispatcher is tested in Rust, over real
 * HTTP in unv-server; this drives the pane: that it asks the right backend, what
 * it shows by default, and that the real values need a confirmed Reveal.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { loadRealIndexHtml, resetState } from './helpers';

const confirms: string[] = [];
let confirmAnswer = true;
const saved: { content: string; name: string }[] = [];
vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return {
    ...real,
    showConfirm: async (m: string) => {
      confirms.push(m);
      return confirmAnswer;
    },
    saveFile: async (content: string, name: string) => {
      saved.push({ content, name });
      return { ok: true as const, path: `/downloads/${name}` };
    },
  };
});

const tauriCalls: [string, unknown][] = [];
let tauriAnswer: (op: string, args: Record<string, unknown>) => unknown = () => ({});
let inTauri = false;
vi.mock('../src/ts/tauri', () => ({
  isTauri: () => inTauri,
  inTauri: false,
  invokeTauri: async (cmd: string, args: { op: string; args: Record<string, unknown> }) => {
    tauriCalls.push([cmd, args]);
    return tauriAnswer(args.op, args.args);
  },
}));

const $ = (id: string) => document.getElementById(id)!;
const flush = (ms = 20) => new Promise((r) => setTimeout(r, ms));

const snap = (seq: number, over: Record<string, unknown> = {}) => ({
  seq,
  project: 'p1',
  project_name: 'edge',
  exporter: 'nginx',
  at: '2026-10-09T00:00:00Z',
  sha256: 'ab'.repeat(32),
  bytes: 120,
  cause: 'save',
  ...over,
});

async function boot(
  opts: { remote?: (op: string, args: unknown) => { status: number; body: unknown } } = {},
) {
  loadRealIndexHtml();
  const { RemoteVaultStore, st } = await import('../src/ts/state');
  (await import('../src/ts/tools-markup')).mountToolsPanes();
  resetState(st);
  st.vault = { api_keys: [], user_categories: [], projects: [{ id: 'p1', name: 'edge' }] } as never;
  const remoteCalls: [string, string, unknown][] = [];
  if (opts.remote) {
    const remote = new RemoteVaultStore('http://localhost:1');
    remote.nodesRequest = async (m, p, b) => {
      remoteCalls.push([m, p, b]);
      const { op, args } = b as { op: string; args: unknown };
      return opts.remote!(op, args);
    };
    st.store = remote;
  }
  (await import('../src/ts/history-pane')).initHistoryPane();
  return remoteCalls;
}

beforeEach(() => {
  vi.resetModules();
  confirms.length = 0;
  saved.length = 0;
  tauriCalls.length = 0;
  confirmAnswer = true;
  inTauri = false;
  tauriAnswer = () => ({});
});

describe('Config history pane', () => {
  it('explains that the history needs the desktop app or a remote vault in a plain browser', async () => {
    await boot();
    $('history-list-btn').click();
    await flush();
    expect($('history-status').textContent).toMatch(/desktop app, or connect to a remote vault/);
  });

  it('lists snapshots from a remote vault over /api/history and shows the project names', async () => {
    const calls = await boot({
      remote: () => ({ status: 200, body: { snapshots: [snap(2), snap(1)] } }),
    });
    ($('history-project') as HTMLSelectElement).innerHTML = '<option value="edge">edge</option>';
    $('history-list-btn').click();
    await flush();
    expect(calls[0][1]).toBe('/api/history');
    expect(calls[0][2]).toMatchObject({ op: 'list' });
    expect($('history-list').textContent).toContain('#2');
    expect($('history-list').textContent).toContain('nginx');
    expect($('history-status').textContent).toBe('2 snapshots');
  });

  it('a local vault in the desktop app goes through the history_call command', async () => {
    inTauri = true;
    tauriAnswer = () => ({ snapshots: [snap(7)] });
    await boot();
    $('history-list-btn').click();
    await flush();
    expect(tauriCalls[0][0]).toBe('history_call');
    expect($('history-list').textContent).toContain('#7');
  });

  it('escapes a hostile project name in the list', async () => {
    await boot({
      remote: () => ({
        status: 200,
        body: { snapshots: [snap(1, { project_name: '<img src=x onerror=alert(1)>' })] },
      }),
    });
    $('history-list-btn').click();
    await flush();
    expect($('history-list').querySelector('img')).toBeNull();
    expect($('history-list').textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('shows fingerprinted text by default and asks before the real values', async () => {
    const asked: unknown[] = [];
    await boot({
      remote: (op, args) => {
        asked.push(args);
        return op === 'list'
          ? { status: 200, body: { snapshots: [snap(3)] } }
          : {
              status: 200,
              body: { text: (args as { reveal: boolean }).reveal ? 'KEY=real' : 'KEY=sha256:abc' },
            };
      },
    });
    $('history-list-btn').click();
    await flush();
    ($('history-list').querySelector('[data-history-act="show"]') as HTMLElement).click();
    await flush();
    expect($('history-output').textContent).toBe('KEY=sha256:abc');
    expect(confirms).toHaveLength(0);

    ($('history-reveal') as HTMLInputElement).checked = true;
    confirmAnswer = false;
    ($('history-list').querySelector('[data-history-act="show"]') as HTMLElement).click();
    await flush();
    expect(confirms).toHaveLength(1);
    // Declined: the request goes out as a masked one, never as a revealed one.
    expect(asked[asked.length - 1]).toMatchObject({ seq: 3, reveal: false });
    expect($('history-output').textContent).toBe('KEY=sha256:abc');

    confirmAnswer = true;
    ($('history-list').querySelector('[data-history-act="show"]') as HTMLElement).click();
    await flush();
    expect($('history-output').textContent).toBe('KEY=real');
  });

  it('"Diff with previous" asks for that stream with the row as the end point', async () => {
    const asked: unknown[] = [];
    await boot({
      remote: (op, args) => {
        asked.push([op, args]);
        return op === 'list'
          ? { status: 200, body: { snapshots: [snap(5)] } }
          : { status: 200, body: { diff: '-a\n+b\n', from: 4, to: 5, added: 1, removed: 1 } };
      },
    });
    $('history-list-btn').click();
    await flush();
    ($('history-list').querySelector('[data-history-act="diff"]') as HTMLElement).click();
    await flush();
    expect(asked[asked.length - 1]).toEqual([
      'diff',
      { project: 'p1', exporter: 'nginx', to: 5, reveal: false },
    ]);
    expect($('history-output').textContent).toBe('-a\n+b\n');
    expect($('history-status').textContent).toBe('#4 to #5: +1 -1');
  });

  it('"Compare with a file" sends the chosen file and shows only what the answer says', async () => {
    const asked: [string, Record<string, unknown>][] = [];
    await boot({
      remote: (op, args) => {
        asked.push([op, args as Record<string, unknown>]);
        return op === 'diff_text'
          ? {
              status: 200,
              body: {
                seq: 7,
                diff: '- line 2: TOKEN (value hidden)\n',
                added: 1,
                removed: 1,
                identical: false,
              },
            }
          : { status: 200, body: { snapshots: [] } };
      },
    });
    ($('history-project') as HTMLSelectElement).innerHTML = '<option value="p1">edge</option>';
    ($('history-project') as HTMLSelectElement).value = 'p1';
    // The picker is created per use; answer it with a file.
    const spy = vi.spyOn(HTMLInputElement.prototype, 'click').mockImplementation(function (
      this: HTMLInputElement,
    ) {
      Object.defineProperty(this, 'files', {
        value: [{ text: () => Promise.resolve('TOKEN=live\n') }],
      });
      this.onchange?.(new Event('change'));
    });
    try {
      $('history-diff-file-btn').click();
      await flush(40);
    } finally {
      spy.mockRestore();
    }
    const call = asked.find(([op]) => op === 'diff_text')!;
    expect(call[1]).toMatchObject({ project: 'p1', text: 'TOKEN=live\n', reveal: false });
    expect($('history-output').textContent).toContain('value hidden');
    expect($('history-status').textContent).toContain('values hidden');
    expect(document.querySelector('input[type=file]')).toBeNull();
  });

  it('"Compare with a file" needs a project before it asks for a file', async () => {
    const asked: string[] = [];
    await boot({
      remote: (op) => {
        asked.push(op);
        return { status: 200, body: {} };
      },
    });
    $('history-diff-file-btn').click();
    await flush();
    expect(asked).toEqual([]);
    expect($('history-status').textContent).toMatch(/Pick a project/);
  });

  it('Save file writes the real text to a file and never puts it on the page', async () => {
    await boot({
      remote: (op) =>
        op === 'list'
          ? { status: 200, body: { snapshots: [snap(9)] } }
          : { status: 200, body: { text: 'PrivateKey = abc' } },
    });
    $('history-list-btn').click();
    await flush();
    ($('history-list').querySelector('[data-history-act="save"]') as HTMLElement).click();
    await flush();
    expect(saved).toEqual([{ content: 'PrivateKey = abc', name: 'p1-nginx-9' }]);
    expect(document.body.textContent).not.toContain('PrivateKey = abc');
  });

  it('prune counts first, asks, and only then deletes', async () => {
    const ops: unknown[] = [];
    await boot({
      remote: (op, args) => {
        ops.push([op, args]);
        return { status: 200, body: { would_delete: 4, bytes_freed: 900, deleted: 4 } };
      },
    });
    $('history-prune-btn').click();
    await flush();
    expect(confirms[0]).toMatch(/Delete 4 old snapshot/);
    expect(ops.map((o) => (o as [string, { dry_run: boolean }])[1].dry_run)).toEqual([true, false]);

    ops.length = 0;
    confirmAnswer = false;
    $('history-prune-btn').click();
    await flush();
    expect(ops).toHaveLength(1);
    expect($('history-status').textContent).toBe('Cancelled.');
  });

  it('says the history is not intact when verify finds problems', async () => {
    await boot({
      remote: () => ({
        status: 200,
        body: { snapshots: 3, problems: ['edge/nginx: #2 breaks the chain'] },
      }),
    });
    $('history-verify-btn').click();
    await flush();
    expect($('history-status').textContent).toMatch(/1 problem/);
    expect($('history-status').className).toContain('err');
    expect($('history-output').textContent).toContain('#2 breaks the chain');
  });

  it('refuses a diff with no project picked before calling anything', async () => {
    const calls = await boot({ remote: () => ({ status: 200, body: {} }) });
    $('history-diff-btn').click();
    await flush();
    expect($('history-status').textContent).toMatch(/Pick a project/);
    expect(calls).toHaveLength(0);
  });

  it('a non-owner on a remote vault is told so', async () => {
    await boot({ remote: () => ({ status: 403, body: null }) });
    $('history-list-btn').click();
    await flush();
    expect($('history-status').textContent).toMatch(/Only the vault owner/);
  });
});
