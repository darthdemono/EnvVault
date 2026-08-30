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
  resolveFieldRef,
} from '../src/ts/chunk-ops';
import { buildIcs } from '../src/ts/calendar';
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
    ] as [string, () => string, string][])('%s excludes disabled chunks', (_name, run, needle) => {
      // Disabling a chunk greys the card out. Exporting it anyway means the
      // deployed file still lists something the user believes they removed.
      expect(run()).not.toContain(needle);
    });
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

  /**
   * The calendar is the fourth format written twice — `src/ts/calendar.ts` and
   * `envv-cli/src/calendar.rs` — so it gets the same treatment as the config
   * exporters: one golden file, asserted from both sides.
   *
   * `now` is pinned. A DTSTAMP taken from the wall clock makes the fixture fail
   * one second after it is written, and means the two implementations can never
   * produce identical bytes even when they agree perfectly.
   */
  it('icalendar feed', () => {
    golden(
      'calendar.ics',
      buildIcs(st.vault.api_keys as any, {
        now: '2026-08-26T12:00:00Z',
        calendarName: 'EnvVault',
      }),
    );
  });

  it('the calendar carries no secret value from the fixture vault', () => {
    // The guarantee, asserted against the real fixture rather than a toy entry:
    // an .ics is handed to a third-party calendar service.
    const ics = buildIcs(st.vault.api_keys as any, { now: '2026-08-26T12:00:00Z' });
    for (const e of st.vault.api_keys as any[]) {
      if (e.api_key) expect(ics).not.toContain(e.api_key);
      if (e.api_secret) expect(ics).not.toContain(e.api_secret);
    }
  });

  /**
   * The `${Provider/field}` alias table — a fourth twin pair, and one that had
   * already drifted silently before it was pinned. `PASSWORD`, `PASS` and `PWD`
   * were in this file's `FIELD_ALIASES` and missing from `canonical_field` in
   * `envv-cli/src/refs.rs`, so `${PgProd/password}` resolved here and reached
   * `.pgpass`, `envv render`, `envv exec` and every CLI export as the literal
   * text `${PgProd/password}`.
   *
   * Asserted through `resolveFieldRef` rather than by importing the table, so it
   * tests the resolution path the exporters actually take.
   */
  it('field aliases', () => {
    const doc = JSON.parse(readFileSync(join(FIXTURES, 'field-aliases.json'), 'utf8'));
    // Every field holds its own name, so a resolved reference reports which
    // field it landed on.
    st.vault.api_keys = [
      {
        provider: 'E',
        api_key: 'api_key',
        api_secret: 'api_secret',
        username: 'username',
        api_url: 'api_url',
        email: 'email',
        key_id: 'key_id',
      },
    ] as any;
    st.vault.projects = [];
    for (const [alias, expected] of Object.entries(doc.aliases as Record<string, string>)) {
      expect(resolveFieldRef(`\${E/${alias}}`, true).resolved, `\${E/${alias}}`).toBe(expected);
    }
  });

  it('nginx_upstream chunk', () => {
    const chunk = (project('edge') as any).chunks.find(
      (c: any) => c.chunk_type === 'nginx_upstream',
    );
    golden('chunk-nginx-upstream.txt', chunkToString(chunk));
  });
});
