/**
 * Tools -> Nodes (Phase 34). The hub routes are tested over real HTTP in
 * unv-server; this drives the pane: what a user sees for each answer, that a
 * hostile name cannot become markup, and that a pulled file goes to a file.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { loadRealIndexHtml, resetState } from './helpers';

const saved: { content: string; name: string }[] = [];
const confirms: string[] = [];
let confirmAnswer = true;
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

const $ = (id: string) => document.getElementById(id)!;
const flush = (ms = 20) => new Promise((r) => setTimeout(r, ms));

type Call = [string, string, unknown];
type Answer = { status: number; body: unknown };

async function boot(answer?: (m: string, p: string, b: unknown) => Answer) {
  loadRealIndexHtml();
  const { RemoteVaultStore, st } = await import('../src/ts/state');
  (await import('../src/ts/tools-markup')).mountToolsPanes();
  resetState(st);
  const calls: Call[] = [];
  if (answer) {
    const remote = new RemoteVaultStore('http://localhost:1');
    remote.nodesRequest = async (m, p, b) => {
      calls.push([m, p, b]);
      return answer(m, p, b);
    };
    st.store = remote;
  }
  (await import('../src/ts/nodes-pane')).initNodesPane();
  return calls;
}

const node = (over: Record<string, unknown> = {}) => ({
  id: 'n1',
  name: 'vps-01',
  fingerprint: 'ab'.repeat(32),
  projects: ['edge'],
  last_seen: '2026-10-09T00:00:00Z',
  revoked_at: null,
  host: { hostname: 'vps', os: 'linux', arch: 'x86_64', version: '0.34.0' },
  targets: [
    { id: 'nginx', mode: 'push', apply: true, status: 'drift', refusal: null, error: null },
    { id: 'wg', mode: 'pull', apply: false, status: 'unreviewed', refusal: null, error: null },
  ],
  ...over,
});

beforeEach(() => {
  vi.resetModules();
  saved.length = 0;
  confirms.length = 0;
  confirmAnswer = true;
});

describe('Nodes pane', () => {
  it('loads enrolled nodes on opening the tool without pressing Refresh', async () => {
    const calls = await boot(() => ({ status: 200, body: { nodes: [node()] } }));
    const { switchTool } = await import('../src/ts/state');
    switchTool('nodes');
    await vi.waitFor(() => expect($('nodes-list').textContent).toContain('vps-01'));
    expect(calls).toEqual([['GET', '/api/nodes', undefined]]);
    switchTool('secret-gen');
    switchTool('nodes');
    await vi.waitFor(() => expect(calls).toHaveLength(2));
  });

  it('clears nodes from the previous vault when the current vault is local', async () => {
    await boot(() => ({ status: 200, body: { nodes: [node()] } }));
    const { switchTool, st, LocalVaultStore } = await import('../src/ts/state');
    switchTool('nodes');
    await vi.waitFor(() => expect($('nodes-list').textContent).toContain('vps-01'));
    st.store = new LocalVaultStore();
    switchTool('nodes');
    await vi.waitFor(() =>
      expect($('nodes-status').textContent).toMatch(/Connect to a remote vault/),
    );
    expect($('nodes-list').textContent).not.toContain('vps-01');
  });

  it('ignores a response from a vault that was switched away while loading nodes', async () => {
    await boot(() => ({ status: 200, body: { nodes: [] } }));
    const { switchTool, st, LocalVaultStore, RemoteVaultStore } = await import('../src/ts/state');
    let finish!: (answer: Answer) => void;
    const pending = new Promise<Answer>((resolve) => {
      finish = resolve;
    });
    const request = vi.fn(() => pending);
    const remote = st.store;
    if (!(remote instanceof RemoteVaultStore)) throw new Error('Expected a remote vault');
    remote.nodesRequest = request;
    switchTool('nodes');
    await vi.waitFor(() => expect(request).toHaveBeenCalled());
    st.store = new LocalVaultStore();
    finish({ status: 200, body: { nodes: [node()] } });
    await flush();
    expect($('nodes-list').textContent).not.toContain('vps-01');
  });

  it('explains that nodes need a server when the vault is local', async () => {
    await boot();
    $('nodes-refresh-btn').click();
    await flush();
    expect($('nodes-status').textContent).toMatch(/Connect to a remote vault/);
  });

  it('lists nodes with each target, its status and its apply flag', async () => {
    await boot(() => ({ status: 200, body: { nodes: [node()] } }));
    $('nodes-refresh-btn').click();
    await flush();
    const text = $('nodes-list').textContent ?? '';
    expect(text).toContain('vps-01');
    expect(text).toContain('drift');
    expect(text).toContain('unreviewed');
    expect($('nodes-status').textContent).toBe('1 node');
  });

  it('says when the hub dials a node, where, and when it last did', async () => {
    await boot(() => ({
      status: 200,
      body: {
        nodes: [
          node({
            listen: { endpoint: 'https://node.example:9443', cert_sha256: 'cd'.repeat(32) },
            last_polled: '2026-10-09T01:02:03Z',
          }),
          node({ id: 'n2', name: 'dialer' }),
        ],
      },
    }));
    $('nodes-refresh-btn').click();
    await flush();
    const text = $('nodes-list').textContent ?? '';
    expect(text).toContain('hub dials https://node.example:9443');
    expect(text).toContain('cdcdcdcdcdcd');
    expect(text).toContain('2026-10-09T01:02:03Z');
    expect(text.match(/hub dials/g)).toHaveLength(1);
  });

  it('says which history snapshot a drifted target still matches', async () => {
    await boot(() => ({
      status: 200,
      body: {
        nodes: [
          node({
            targets: [
              {
                id: 'nginx',
                mode: 'push',
                apply: false,
                status: 'drift',
                snapshot: { seq: 12, at: '2026-10-03T08:00:00Z' },
              },
            ],
          }),
        ],
      },
    }));
    $('nodes-refresh-btn').click();
    await flush();
    expect($('nodes-list').textContent).toContain('file matches history #12');
  });

  it('blast radius asks the hub for that node since the chosen date and prints the one command', async () => {
    const calls = await boot((m) =>
      m === 'GET'
        ? { status: 200, body: { nodes: [node()] } }
        : {
            status: 200,
            body: {
              host: 'vps-01',
              since: '2026-10-01',
              deployments: 2,
              unaccounted: [{ at: '2026-10-02T00:00:00Z', via: 'nginx', sha256: 'ab'.repeat(32) }],
              entries: [
                {
                  provider: 'Stripe',
                  key_id: '',
                  fields: ['api_key'],
                  first_seen: '2026-10-01T00:00:00Z',
                  last_seen: '2026-10-03T00:00:00Z',
                  times: 2,
                  still_current: true,
                  removed: false,
                  short: false,
                  console_url: 'https://dash.example/keys',
                },
                {
                  provider: 'GitHub',
                  key_id: 'ci',
                  fields: ['api_key'],
                  first_seen: '2026-10-01T00:00:00Z',
                  last_seen: '2026-10-01T00:00:00Z',
                  times: 1,
                  still_current: false,
                  removed: false,
                  short: false,
                },
              ],
              command: "unv entry rotate 'Stripe' --generate",
            },
          },
    );
    $('nodes-refresh-btn').click();
    await flush();
    ($('nodes-since') as HTMLInputElement).value = '2026-10-01';
    ($('nodes-list').querySelector('[data-node-act="blast"]') as HTMLElement).click();
    await flush();
    const post = calls.find(([m]) => m === 'POST')!;
    expect(post[1]).toBe('/api/history');
    expect(post[2]).toEqual({ op: 'blast', args: { host: 'vps-01', since: '2026-10-01' } });
    const out = $('nodes-output').textContent ?? '';
    expect(out).toContain('ROTATE  Stripe (api_key)');
    expect(out).toContain('rotated GitHub:ci');
    expect(out).toContain('revoke at https://dash.example/keys');
    expect(out).toContain("unv entry rotate 'Stripe' --generate");
    expect(out).toContain('1 deployment(s) have no recorded contents');
  });

  const held = (over: Record<string, unknown> = {}) => ({
    id: 'ap1',
    target: 'nginx',
    sha256: 'ab'.repeat(32),
    status: 'pending',
    requested_at: '2026-10-09T01:00:00Z',
    from_seq: 4,
    to_seq: 5,
    ...over,
  });

  it('shows a held push with Review, Approve and Reject, and toggles the policy', async () => {
    const calls = await boot((m) => ({
      status: 200,
      body: m === 'GET' ? { nodes: [node({ approval: 'required', approvals: [held()] })] } : {},
    }));
    $('nodes-refresh-btn').click();
    await flush();
    const text = $('nodes-list').textContent ?? '';
    expect(text).toContain('Every push to this node is held for your approval');
    expect(text).toContain('Held: nginx');
    expect(text).toContain('Stop requiring approval');
    ($('nodes-list').querySelector('[data-node-act="policy"]') as HTMLElement).click();
    await flush();
    const post = calls.find(([m, p]) => m === 'POST' && p.endsWith('/policy'))!;
    expect(post[2]).toEqual({ approval: 'none' });
  });

  it('Review shows the diff with fingerprints, never asking for real values', async () => {
    const calls = await boot((m, p) =>
      m === 'GET'
        ? { status: 200, body: { nodes: [node({ approval: 'required', approvals: [held()] })] } }
        : p === '/api/history'
          ? { status: 200, body: { diff: '-KEY=sha256:aaa\n+KEY=sha256:bbb\n' } }
          : { status: 200, body: {} },
    );
    $('nodes-refresh-btn').click();
    await flush();
    ($('nodes-list').querySelector('[data-node-act="review"]') as HTMLElement).click();
    await flush();
    const hist = calls.find(([, p]) => p === '/api/history')!;
    expect(hist[2]).toEqual({ op: 'diff', args: { from: 4, to: 5, reveal: false } });
    expect($('nodes-output').textContent).toContain('+KEY=sha256:bbb');
  });

  it('with no earlier snapshot, Review shows the whole proposed file as additions', async () => {
    await boot((m, p) =>
      m === 'GET'
        ? { status: 200, body: { nodes: [node({ approvals: [held({ from_seq: null })] })] } }
        : p === '/api/history'
          ? { status: 200, body: { text: 'A=1\nB=2' } }
          : { status: 200, body: {} },
    );
    $('nodes-refresh-btn').click();
    await flush();
    ($('nodes-list').querySelector('[data-node-act="review"]') as HTMLElement).click();
    await flush();
    expect($('nodes-output').textContent).toContain('+A=1\n+B=2');
    expect($('nodes-output').textContent).toContain('not in the history');
  });

  it('Approve names the hash in the question, and only a yes sends it', async () => {
    const calls = await boot((m) => ({
      status: 200,
      body: m === 'GET' ? { nodes: [node({ approval: 'required', approvals: [held()] })] } : {},
    }));
    $('nodes-refresh-btn').click();
    await flush();
    const click = () =>
      ($('nodes-list').querySelector('[data-node-act="approve"]') as HTMLElement).click();
    confirmAnswer = false;
    click();
    await flush();
    expect(confirms[0]).toContain('abababababab');
    expect(calls.some(([, p]) => p.includes('/api/node-approvals/'))).toBe(false);
    confirmAnswer = true;
    click();
    await flush();
    expect(calls.some(([m, p]) => m === 'POST' && p === '/api/node-approvals/ap1/approve')).toBe(
      true,
    );
  });

  describe('approval signed on the owner device', () => {
    const bridge = (answer: unknown) => {
      const seen: [string, unknown][] = [];
      (window as unknown as Record<string, unknown>).__TAURI__ = {
        core: {
          invoke: (cmd: string, args: unknown) => {
            seen.push([cmd, args]);
            return Promise.resolve(answer);
          },
        },
      };
      return seen;
    };
    afterEach(() => {
      delete (window as unknown as Record<string, unknown>).__TAURI__;
    });

    it('Approve signs here and sends only the signature, never an unsigned yes', async () => {
      const seen = bridge({ token: '{"v":1}', sig: 'ff' });
      const calls = await boot((m) => ({
        status: 200,
        body: m === 'GET' ? { nodes: [node({ approval: 'device', approvals: [held()] })] } : {},
      }));
      $('nodes-refresh-btn').click();
      await flush();
      expect($('nodes-list').textContent).toContain('signed on your own device');
      ($('nodes-list').querySelector('[data-node-act="approve"]') as HTMLElement).click();
      await flush();
      expect(seen).toEqual([
        [
          'approver_sign',
          { nodeId: 'n1', target: 'nginx', sha256: 'ab'.repeat(32), approvalId: 'ap1' },
        ],
      ]);
      const post = calls.find(([m, p]) => m === 'POST' && p === '/api/node-approvals/ap1/approve')!;
      expect(post[2]).toEqual({ signed: { token: '{"v":1}', sig: 'ff' } });
    });

    it('in a browser it says where to sign instead of sending an unsigned approval', async () => {
      const calls = await boot((m) => ({
        status: 200,
        body: m === 'GET' ? { nodes: [node({ approval: 'device', approvals: [held()] })] } : {},
      }));
      $('nodes-refresh-btn').click();
      await flush();
      ($('nodes-list').querySelector('[data-node-act="approve"]') as HTMLElement).click();
      await flush();
      expect(calls.some(([, p]) => p.includes('/api/node-approvals/'))).toBe(false);
      expect($('nodes-status').textContent).toMatch(/desktop app|unv node approve/);
    });

    it('offers the device policy, and registering this device sends its public key', async () => {
      const seen = bridge({ public_key: 'cd'.repeat(32), fingerprint: 'ef'.repeat(32) });
      const calls = await boot((m) => ({
        status: 200,
        body: m === 'GET' ? { nodes: [node()] } : {},
      }));
      $('nodes-refresh-btn').click();
      await flush();
      const device = $('nodes-list').querySelector('[data-policy="device"]') as HTMLElement;
      device.click();
      await flush();
      expect(calls.find(([, p]) => p.endsWith('/policy'))![2]).toEqual({ approval: 'device' });
      $('nodes-approver-btn').click();
      await flush();
      expect(seen[0][0]).toBe('approver_public');
      expect(calls.find(([, p]) => p === '/api/node-approvers')![2]).toEqual({
        pubkey: 'cd'.repeat(32),
        label: 'Desktop app',
      });
    });
  });

  it('reads a pulled .env back into a chunk with the Rust plan, after a yes, keeping references', async () => {
    const seen: [string, Record<string, unknown>][] = [];
    (window as unknown as Record<string, unknown>).__TAURI__ = {
      core: {
        invoke: (cmd: string, args: Record<string, unknown>) => {
          seen.push([cmd, args]);
          return Promise.resolve({
            fields: [{ key: 'A', value: '2', field_type: 'var' }],
            added: [],
            changed: ['A'],
            removed: ['B'],
            kept_references: ['T'],
          });
        },
      },
    };
    try {
      const calls = await boot((m, p) => {
        if (m === 'GET' && p === '/api/nodes') {
          return {
            status: 200,
            body: {
              nodes: [
                node({
                  targets: [
                    {
                      id: 'envf',
                      mode: 'pull',
                      apply: false,
                      status: 'changed',
                      project: 'edge',
                      exporter: 'env',
                    },
                    {
                      id: 'ngx',
                      mode: 'pull',
                      apply: false,
                      status: 'changed',
                      project: 'edge',
                      exporter: 'nginx',
                    },
                  ],
                }),
              ],
            },
          };
        }
        if (m === 'GET') return { status: 200, body: { content_b64: btoa('A=2\n') } };
        return { status: 202, body: {} };
      });
      const { st } = await import('../src/ts/state');
      const chunk = {
        id: 'c',
        name: '.env',
        chunk_type: 'env_file',
        fields: [{ key: 'A', value: '1' }],
      };
      st.vault = {
        api_keys: [],
        user_categories: [],
        projects: [{ id: 'edge', name: 'edge', chunks: [chunk] }],
      } as never;
      $('nodes-refresh-btn').click();
      await flush();
      // An .env target and a format with an app-side reader (nginx) offer it.
      expect($('nodes-list').querySelectorAll('[data-node-act="into-chunk"]')).toHaveLength(2);
      confirmAnswer = false;
      ($('nodes-list').querySelector('[data-node-act="into-chunk"]') as HTMLElement).click();
      await flush(1600);
      expect(seen[0][0]).toBe('env_import_plan');
      expect(seen[0][1]).toEqual({ fields: [{ key: 'A', value: '1' }], text: 'A=2\n' });
      expect(confirms[confirms.length - 1]).toMatch(
        /Changed: A[\s\S]*Removed: B[\s\S]*references: T/,
      );
      expect(chunk.fields).toEqual([{ key: 'A', value: '1' }]); // declined: untouched
      confirmAnswer = true;
      ($('nodes-list').querySelector('[data-node-act="into-chunk"]') as HTMLElement).click();
      await flush(1600);
      expect(chunk.fields).toEqual([{ key: 'A', value: '2', field_type: 'var' }]);
      expect(calls.filter(([, p]) => p.endsWith('/pull'))).toHaveLength(2);
    } finally {
      delete (window as unknown as Record<string, unknown>).__TAURI__;
    }
  });

  it('Reject needs no confirmation and sends the rejection', async () => {
    const calls = await boot((m) => ({
      status: 200,
      body: m === 'GET' ? { nodes: [node({ approvals: [held()] })] } : {},
    }));
    $('nodes-refresh-btn').click();
    await flush();
    ($('nodes-list').querySelector('[data-node-act="reject"]') as HTMLElement).click();
    await flush();
    expect(calls.some(([m, p]) => m === 'POST' && p === '/api/node-approvals/ap1/reject')).toBe(
      true,
    );
    expect(confirms).toHaveLength(0);
  });

  it('a hostile target name in a held push stays text', async () => {
    await boot(() => ({
      status: 200,
      body: { nodes: [node({ approvals: [held({ target: '<img src=x onerror=alert(1)>' })] })] },
    }));
    $('nodes-refresh-btn').click();
    await flush();
    expect($('nodes-list').querySelector('img')).toBeNull();
  });

  it('escapes a hostile node name and target note', async () => {
    await boot(() => ({
      status: 200,
      body: {
        nodes: [
          node({
            name: '<img src=x onerror=alert(1)>',
            targets: [
              {
                id: '<b>t</b>',
                mode: 'push',
                apply: false,
                status: 'refused',
                refusal: '<script>x</script>',
              },
            ],
          }),
        ],
      },
    }));
    $('nodes-refresh-btn').click();
    await flush();
    expect($('nodes-list').querySelector('img, script, b')).toBeNull();
    expect($('nodes-list').textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('mints a token with the typed name, projects and lifetime, and shows it once', async () => {
    const calls = await boot(() => ({ status: 200, body: { token: 'envn_abc' } }));
    ($('nodes-name') as HTMLInputElement).value = 'vps-01';
    ($('nodes-projects') as HTMLInputElement).value = 'edge, mail';
    ($('nodes-ttl') as HTMLInputElement).value = '5';
    $('nodes-token-btn').click();
    await flush();
    expect(calls[0]).toEqual([
      'POST',
      '/api/nodes/tokens',
      { name: 'vps-01', projects: ['edge', 'mail'], ttl_secs: 300 },
    ]);
    expect($('nodes-output').textContent).toBe('envn_abc');
  });

  it('refuses a token request with no name or no project before calling the server', async () => {
    const calls = await boot(() => ({ status: 200, body: {} }));
    $('nodes-token-btn').click();
    await flush();
    expect($('nodes-status').textContent).toMatch(/name/);
    ($('nodes-name') as HTMLInputElement).value = 'x';
    $('nodes-token-btn').click();
    await flush();
    expect($('nodes-status').textContent).toMatch(/project/);
    expect(calls).toHaveLength(0);
  });

  it('says what a missing --nodes, a non-owner and a rate limit mean', async () => {
    for (const [status, re] of [
      [404, /--nodes/],
      [403, /Only the vault owner/],
      [429, /Rate limited/],
    ] as const) {
      vi.resetModules();
      await boot(() => ({ status, body: null }));
      $('nodes-refresh-btn').click();
      await flush();
      expect($('nodes-status').textContent).toMatch(re);
      expect($('nodes-status').className).toContain('err');
    }
  });

  it('revoke asks first, then revokes and refreshes', async () => {
    let revoked = false;
    const calls = await boot((m) => {
      if (m === 'DELETE') revoked = true;
      return {
        status: m === 'DELETE' ? 204 : 200,
        body: { nodes: [node({ revoked_at: revoked ? 't' : null })] },
      };
    });
    $('nodes-refresh-btn').click();
    await flush();
    ($('nodes-list').querySelector('[data-node-act="revoke"]') as HTMLElement).click();
    await flush();
    expect(calls.some(([m, p]) => m === 'DELETE' && p === '/api/nodes/n1')).toBe(true);
    expect($('nodes-list').textContent).toContain('(revoked)');
  });

  it('a pulled file goes to a file, never into the page', async () => {
    let polls = 0;
    await boot((m, p) => {
      if (m === 'GET' && p === '/api/nodes') return { status: 200, body: { nodes: [node()] } };
      if (m === 'POST') return { status: 202, body: null };
      polls += 1;
      return polls < 2
        ? { status: 204, body: null }
        : { status: 200, body: { content_b64: btoa('PrivateKey = abc') } };
    });
    $('nodes-refresh-btn').click();
    await flush();
    ($('nodes-list').querySelector('[data-node-act="pull"]') as HTMLElement).click();
    await flush(2500);
    expect(saved).toEqual([{ content: 'PrivateKey = abc', name: 'wg.pulled' }]);
    expect(document.body.textContent).not.toContain('PrivateKey = abc');
    expect($('nodes-status').textContent).toMatch(/saved to \/downloads\/wg.pulled/);
  });
});
