/**
 * Cross-implementation parity for the config exporters.
 *
 * These formats now exist twice: once in `src/ts/chunk-ops.ts` for the desktop
 * app, once in `envv-cli/src/exporters.rs` for the CLI. Two implementations of
 * one file format drift silently — the app writes a working wg0.conf and the CLI
 * writes a subtly different one, and nobody notices until a deploy breaks.
 *
 * So both sides assert against the *same* golden files in
 * `tests/fixtures/parity/`. This suite pins the TypeScript output; the Rust test
 * at `envv-cli/tests/parity.rs` pins the Rust output against the identical
 * bytes. Change either exporter and one of the two fails.
 *
 * Regenerate deliberately with `PARITY_UPDATE=1 npx vitest run tests/cli-parity.test.ts`,
 * then re-run the Rust test to see what the change did to the CLI.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { st } from '../src/ts/state';
import {
  exportWireGuard,
  exportDockerCompose,
  exportNginx,
  exportK8s,
  exportSshConfig,
  exportTraefik,
  exportApache,
  exportHaproxy,
  exportAnsible,
  exportPostgres,
  chunkToString,
} from '../src/ts/chunk-ops';
import { loadRealIndexHtml, resetState } from './helpers';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, 'fixtures', 'parity');
const vaultFixture = JSON.parse(readFileSync(join(FIXTURES, 'vault.json'), 'utf8'));

function project(id: string) {
  const p = st.vault.projects.find((x: any) => x.id === id);
  if (!p) throw new Error(`fixture has no project ${id}`);
  return p;
}

/** Compare against the golden file, or write it when PARITY_UPDATE is set. */
function golden(name: string, actual: string) {
  const path = join(FIXTURES, name);
  if (process.env.PARITY_UPDATE || !existsSync(path)) {
    writeFileSync(path, actual);
    return;
  }
  expect(actual).toBe(readFileSync(path, 'utf8'));
}

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  st.vault = JSON.parse(JSON.stringify(vaultFixture));
});

describe('exporter parity fixtures', () => {
  it('wireguard', () => {
    golden('wireguard.conf', exportWireGuard(project('vpn') as any));
  });

  it('docker compose', () => {
    const { yaml, envFile } = exportDockerCompose(project('stack') as any);
    golden('compose.yaml', yaml);
    golden('compose.env', envFile);
  });

  it('nginx', () => {
    golden('nginx.conf', exportNginx(project('edge') as any));
  });

  // ── The seven experimental types ───────────────────────────────────────────
  //
  // These had no fixture until Phase 18, which is exactly why six of them
  // shipped `${ref}` placeholders straight into generated config — the bug that
  // a fixture caught in `exportNginx` back in Phase 13. Every project below
  // contains at least one reference and at least one disabled chunk, because
  // those are the two properties that broke.

  it('kubernetes', () => {
    golden('k8s.yaml', exportK8s(project('k8s') as any));
  });

  it('ssh config', () => {
    golden('ssh_config', exportSshConfig(project('ssh') as any));
  });

  it('traefik', () => {
    golden('traefik.yaml', exportTraefik(project('traefik') as any));
  });

  it('apache', () => {
    golden('apache.conf', exportApache(project('apache') as any));
  });

  it('haproxy', () => {
    golden('haproxy.cfg', exportHaproxy(project('haproxy') as any));
  });

  it('ansible', () => {
    golden('ansible.yml', exportAnsible(project('ansible') as any));
  });

  it('postgres', () => {
    golden('pgpass', exportPostgres(project('pg') as any));
  });

  // Two properties asserted directly rather than only through the golden files,
  // so a regenerated fixture cannot quietly bless a regression.
  describe('properties every exporter must hold', () => {
    const cases: [string, () => string][] = [
      ['k8s', () => exportK8s(project('k8s') as any)],
      ['ssh', () => exportSshConfig(project('ssh') as any)],
      ['traefik', () => exportTraefik(project('traefik') as any)],
      ['apache', () => exportApache(project('apache') as any)],
      ['ansible', () => exportAnsible(project('ansible') as any)],
      ['postgres', () => exportPostgres(project('pg') as any)],
    ];

    it.each(cases)('%s resolves every ${ref}', (_name, run) => {
      // Invariant 5. A `${…}` reaching a real config file is a broken deploy:
      // a .pgpass whose password is the literal string `${PgProd/password}`
      // fails to authenticate and names nothing useful in the error.
      expect(run()).not.toMatch(/\$\{[^}]+\}/);
    });

    it.each([
      ['k8s', () => exportK8s(project('k8s') as any), 'must-not-appear'],
      ['ssh', () => exportSshConfig(project('ssh') as any), 'gone.example.com'],
      ['postgres', () => exportPostgres(project('pg') as any), 'old.internal'],
    ] as [string, () => string, string][])(
      '%s excludes disabled chunks',
      (_name, run, needle) => {
        // Disabling a chunk greys the card out. Exporting it anyway means the
        // deployed file still lists something the user believes they removed.
        expect(run()).not.toContain(needle);
      },
    );
  });

  it('env_file chunk', () => {
    const chunk = (project('stack') as any).chunks.find((c: any) => c.chunk_type === 'env_file');
    golden('chunk-env.txt', chunkToString(chunk));
  });

  it('wg_interface chunk', () => {
    const chunk = (project('vpn') as any).chunks.find((c: any) => c.chunk_type === 'wg_interface');
    golden('chunk-wg-interface.txt', chunkToString(chunk));
  });

  it('docker_service chunk', () => {
    const chunk = (project('stack') as any).chunks.find(
      (c: any) => c.chunk_type === 'docker_service',
    );
    golden('chunk-docker-service.txt', chunkToString(chunk));
  });

  it('nginx_upstream chunk', () => {
    const chunk = (project('edge') as any).chunks.find(
      (c: any) => c.chunk_type === 'nginx_upstream',
    );
    golden('chunk-nginx-upstream.txt', chunkToString(chunk));
  });
});
