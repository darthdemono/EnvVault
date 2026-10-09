/**
 * Phase 32.1: the structured-project config view. Every project type renders a
 * chunk tree whose buttons (`export-*`, `import-*`, `add-*`, `edit-chunk`,
 * `chunk-copy`...) are `data-action` controls that no static probe reaches, and
 * `render.ts` / `chunk-ops.ts` are the largest untested regions in the app. One
 * project per type, seeded with that type's starter chunks; each control kind is
 * clicked on a fresh page. Silent kinds are named `<project type>:<action>` in
 * `efficacy-config-silent.json`, with a reason.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { st, resetViewState } from '../src/ts/state';
import { render } from '../src/ts/render';
import * as starters from '../src/ts/chunks/starters';
import { stackAdapter, stackStarterChunks } from '../src/ts/stack';
import type { ProjectType, SecretChunk } from '../src/ts/types';
import { clearTransient, judge, probeKinds, type KindReport } from './probe';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

const allowed: Record<string, string> = JSON.parse(
  readFileSync(join(process.cwd(), 'tests', 'efficacy-config-silent.json'), 'utf8'),
);

const factories: Record<string, () => SecretChunk[]> = {
  wireguard: starters.makeWgStarterChunks,
  docker: starters.makeDockerStarterChunks,
  nginx: starters.makeNginxStarterChunks,
  kubernetes: starters.makeK8sStarterChunks,
  ssh_config: starters.makeSshStarterChunks,
  traefik: starters.makeTraefikStarterChunks,
  apache: starters.makeApacheStarterChunks,
  haproxy: starters.makeHaproxyStarterChunks,
  ansible: starters.makeAnsibleStarterChunks,
  postgres: starters.makePostgresStarterChunks,
  // Stack integrations (Phase 38): starters come from their descriptors.
  prometheus: () => stackStarterChunks(stackAdapter('prometheus')!),
  grafana: () => stackStarterChunks(stackAdapter('grafana')!),
  homepage: () => stackStarterChunks(stackAdapter('homepage')!),
};

/**
 * Extra chunks that switch on controls the starter set leaves out: an `.env`
 * chunk (Link / Export / Copy resolved), a field holding a vault reference (the
 * jump-to-entry badge), an nginx key chunk (Import file) and a certificate
 * entry matching a domain (Edit certificate).
 */
function extras(type: string): SecretChunk[] {
  const f = (key: string, value: string, field_type = 'var') => ({ key, value, field_type });
  const out: SecretChunk[] = [];
  if (type === 'docker') {
    out.push({
      id: crypto.randomUUID(),
      name: '.env',
      chunk_type: 'env_file',
      fields: [f('API_KEY', '${Alpha}'), f('PLAIN', 'x')],
    } as SecretChunk);
  }
  if (type === 'docker') {
    // A docker_service whose environment field holds a vault reference: this is
    // what switches on "Copy (resolved)".
    out.push({
      id: crypto.randomUUID(),
      name: 'app',
      chunk_type: 'docker_service',
      fields: [
        { key: 'image', value: 'nginx', field_type: 'var' },
        { key: 'API_KEY', value: '${Alpha}', field_type: 'env_var', description: 'env' },
      ],
    } as SecretChunk);
  }
  if (type === 'wireguard') {
    out.push({
      id: crypto.randomUUID(),
      name: 'Refd peer',
      chunk_type: 'wg_peer',
      fields: [f('PublicKey', '${Alpha}', 'secret'), f('AllowedIPs', '10.0.0.2/32', 'subnet')],
    } as SecretChunk);
  }
  if (type === 'nginx') {
    out.push(
      {
        id: crypto.randomUUID(),
        name: 'example.com key',
        chunk_type: 'nginx_key',
        fields: [f('key_type', 'fullchain'), f('pem', '')],
      } as SecretChunk,
      {
        id: crypto.randomUUID(),
        name: 'site',
        chunk_type: 'nginx_server',
        fields: [
          f('server_name', 'example.com'),
          f('ssl_certificate', '/etc/ssl/example.com/fullchain.pem'),
        ],
      } as SecretChunk,
    );
  }
  return out;
}

describe('every config-view control does something visible', () => {
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
    const merged: KindReport = {
      targets: 0,
      kinds: 0,
      reached: [],
      silent: [],
      partial: [],
      threw: [],
    };
    for (const [type, make] of Object.entries(factories)) {
      const report = await probeKinds({
        reset: () => {
          document.body.innerHTML = '';
          for (const n of nodes) document.body.appendChild(n);
          resetState(st);
          resetViewState();
          const project = makeProject({
            id: `proj-${type}`,
            name: `Project ${type}`,
            project_type: type as ProjectType,
            chunks: [...make(), ...extras(type)],
          });
          st.vault = makeVault({
            projects: [project],
            api_keys: [
              makeEntry({ id: 'e1', provider: 'Alpha', projectIds: [project.id] }),
              makeEntry({
                id: 'cert',
                provider: 'example.com',
                secretType: 'certificate',
                certificate_data: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
              } as never),
            ],
          });
          st.currentSelectedProjectIds = [project.id];
          render();
          clearTransient();
        },
        selector: '#card-grid [data-action]',
        errors,
      });
      merged.targets += report.targets;
      merged.kinds += report.kinds;
      merged.reached.push(...report.reached);
      merged.silent.push(...report.silent.map((k) => `${type}:${k}`));
      merged.partial.push(...report.partial.map((k) => `${type}:${k}`));
      merged.threw.push(...report.threw.map((k) => `${type}:${k}`));
    }
    if (process.env.EFFICACY_REPORT) {
      writeFileSync(process.env.EFFICACY_REPORT, JSON.stringify(merged, null, 2));
    }
    expect(judge(merged, allowed)).toEqual({ unexplained: [], threw: [], stale: [] });
  }, 600_000);
});
