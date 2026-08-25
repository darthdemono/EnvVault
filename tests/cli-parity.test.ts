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
