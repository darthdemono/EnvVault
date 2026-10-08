/**
 * Hostile-value tests for the renderers migrated to the `html` tag (Phase 28).
 *
 * `tests/render-escaping.test.ts` covers the card grid. This file covers the
 * rest: the timeline, key pools, authenticator, remote panel, chunk cards,
 * Docker services card and nginx certificate card. Each is rendered with a value
 * that would break out of an attribute or inject an element if it were
 * interpolated raw, and the assertion is on the resulting DOM, not on the string.
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { st, Settings } from '../src/ts/state';
import { renderTimeline, initTimelinePane } from '../src/ts/timeline';
import { renderPoolsPane } from '../src/ts/pools';
import { renderAuthPanel } from '../src/ts/auth-panel';
import { renderRemotePanel } from '../src/ts/remote-panel';
import {
  renderChunkCard,
  renderDockerServicesCard,
  renderNginxCertCard,
  makeConfigViewHeaderBtns,
} from '../src/ts/chunk-ops';
import { setHtml } from '../src/ts/html';
import { mountToolsPanes } from '../src/ts/tools-markup';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';
import type { ChunkType, SecretChunk } from '../src/ts/types';

const BREAKOUT = '" onmouseover="steal()" x="';
const TAG = '<img src=x onerror=alert(1)>';

/** Nothing under `root` may have gained a scripting attribute or a live element. */
function clean(root: ParentNode, label = '') {
  for (const sel of ['img', 'script', 'iframe', '[onmouseover]', '[onerror]', '[onclick]']) {
    expect(root.querySelector(sel), `${label}: ${sel} became live`).toBeNull();
  }
}

let panes: ChildNode[] = [];

beforeAll(() => {
  loadRealIndexHtml();
  mountToolsPanes();
  initTimelinePane();
  panes = [...document.body.childNodes];
});

beforeEach(() => {
  document.body.innerHTML = '';
  panes.forEach((n) => document.body.appendChild(n));
  resetState(st);
});

describe('timeline', () => {
  it('escapes provider and account in the table', () => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({
          provider: TAG,
          account_name: BREAKOUT,
          created_at: '2026-01-01T00:00:00Z',
        } as never),
      ],
    });
    renderTimeline();
    clean(document.body, 'timeline');
    expect(document.body.textContent).toContain(TAG);
  });
});

describe('key pools', () => {
  it('escapes pool names and member labels', async () => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: '1', provider: TAG, key_id: BREAKOUT, pool: BREAKOUT } as never),
        makeEntry({ id: '2', provider: TAG, key_id: 'b', pool: BREAKOUT } as never),
      ],
    });
    await renderPoolsPane();
    clean(document.getElementById('pools-body')!, 'pools');
  });
});

describe('authenticator panel', () => {
  it('escapes provider, account and id on the cards', () => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({
          id: BREAKOUT,
          provider: TAG,
          account_name: BREAKOUT,
          totp_secret: 'JBSWY3DPEHPK3PXP',
        } as never),
      ],
    });
    renderAuthPanel();
    clean(document.body, 'auth');
  });
});

describe('remote panel', () => {
  it('escapes saved remote names, urls and usernames', () => {
    Settings.set('remoteSaved', [
      { id: BREAKOUT, name: TAG, url: `http://x/${BREAKOUT}`, username: BREAKOUT },
    ] as never);
    renderRemotePanel();
    clean(document.body, 'remote');
  });
});

describe('chunk cards', () => {
  const types: ChunkType[] = [
    'wg_interface',
    'wg_peer',
    'docker_service',
    'docker_network',
    'docker_volume',
    'env_file',
    'nginx_server',
    'nginx_upstream',
    'nginx_location',
    'nginx_key',
    'generic',
  ];

  it.each(types)('%s: hostile name, ids and field values stay inert', (chunk_type) => {
    const project = makeProject({ id: BREAKOUT, name: TAG });
    const c: SecretChunk = {
      id: BREAKOUT,
      name: TAG,
      chunk_type,
      notes: TAG,
      fields: [
        'name',
        'listen',
        'server_name',
        'image',
        'ports',
        'volumes',
        'networks',
        'content',
        'allowed_ips',
        'address',
        'key',
        'value',
        'return',
        'proxy_pass',
        'environment',
        'cap_add',
        'devices',
        'user',
      ].map((key) => ({
        key,
        value: `${TAG}\n${BREAKOUT}`,
        label: TAG,
        description: BREAKOUT,
      })),
    } as never;
    project.chunks = [c];
    st.vault = makeVault({ projects: [project] });
    const card = renderChunkCard(c, project);
    clean(card, chunk_type);
  });

  it('docker services card is inert', () => {
    const project = makeProject({ id: BREAKOUT, name: TAG });
    project.chunks = [
      {
        id: BREAKOUT,
        name: TAG,
        chunk_type: 'docker_service',
        fields: [
          { key: 'image', value: TAG },
          { key: 'container_name', value: BREAKOUT },
          { key: 'environment', value: `${TAG}=${BREAKOUT}\nPLAIN=${TAG}`, description: 'env' },
          { key: 'ports', value: `${TAG}:80\n${BREAKOUT}` },
          { key: 'volumes', value: `${TAG}:${BREAKOUT}` },
          { key: 'networks', value: TAG },
        ],
      } as never,
    ];
    clean(renderDockerServicesCard(project), 'docker');
  });

  it('nginx certificate card is inert', () => {
    st.vault = makeVault({
      api_keys: [makeEntry({ provider: TAG, certificate_data: TAG } as never)],
    });
    const host = document.createElement('div');
    setHtml(host, renderNginxCertCard(`${TAG}${BREAKOUT}`));
    clean(host, 'cert');
  });

  it('config header buttons are inert for every project type', () => {
    const host = document.createElement('div');
    for (const t of [
      'generic',
      'wireguard',
      'docker',
      'nginx',
      'apache',
      'haproxy',
      'ansible',
      'postgres',
      'kubernetes',
      'ssh_config',
      'traefik',
    ]) {
      setHtml(
        host,
        makeConfigViewHeaderBtns(makeProject({ id: BREAKOUT, project_type: t } as never)),
      );
      clean(host, t);
    }
  });
});
