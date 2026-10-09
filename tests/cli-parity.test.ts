/**
 * Cross-implementation parity for the config exporters.
 *
 * These formats now exist twice: once in `src/ts/chunk-ops.ts` for the desktop
 * app, once in `unv-cli/src/exporters.rs` for the CLI. Two implementations of
 * one file format drift silently — the app writes a working wg0.conf and the CLI
 * writes a subtly different one, and nobody notices until a deploy breaks.
 *
 * So both sides assert against the *same* golden files in
 * `tests/fixtures/parity/`. This suite pins the TypeScript output; the Rust test
 * at `unv-cli/tests/parity.rs` pins the Rust output against the identical
 * bytes. Change either exporter and one of the two fails.
 *
 * Regenerate deliberately with `PARITY_UPDATE=1 npx vitest run tests/cli-parity.test.ts`,
 * then re-run the Rust test to see what the change did to the CLI.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  st,
  envName,
  primaryEnvName,
  secretEnvName,
  quoteEnvValue,
  unquoteEnvValue,
  type EnvNameCase,
} from '../src/ts/state';
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
  findEntryByRef,
} from '../src/ts/chunk-ops';
import { buildCopyText } from '../src/ts/copy-profile';
import {
  parseCookieHeader,
  parseCookiesTxt,
  parseCookieJson,
  toCookieHeader,
  toCookiesTxt,
  missingTxtAttributes,
} from '../src/ts/cookies';
import {
  authHeaderFor,
  authQueryFor,
  authUrlFor,
  curlFor,
  shellQuote,
} from '../src/ts/auth-request';
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

  // The iCalendar feed used to be a fourth format written twice here and in
  // `unv-cli/src/calendar.rs`, pinned by this same `calendar.ics` fixture from
  // both sides. Phase 24.3 deleted the TypeScript builder — the format is now
  // built in exactly one place, `vault-core/src/calendar.rs`, reached by the
  // app over IPC (`calendar_build_ics`) and by the CLI and `unv-server`
  // directly. The fixture still exists and still pins the Rust output; see
  // `calendar_ics` and `calendar_carries_no_secret_value` in
  // `unv-cli/tests/parity.rs`.

  /**
   * The `${Provider/field}` alias table — a fourth twin pair, and one that had
   * already drifted silently before it was pinned. `PASSWORD`, `PASS` and `PWD`
   * were in this file's `FIELD_ALIASES` and missing from `canonical_field` in
   * `unv-cli/src/refs.rs`, so `${PgProd/password}` resolved here and reached
   * `.pgpass`, `unv render`, `unv exec` and every CLI export as the literal
   * text `${PgProd/password}`.
   *
   * Asserted through `resolveFieldRef` rather than by importing the table, so it
   * tests the resolution path the exporters actually take.
   */
  it('bundle references', () => {
    const doc = JSON.parse(readFileSync(join(FIXTURES, 'bundle-refs.json'), 'utf8'));
    st.vault.api_keys = doc.entries;
    st.vault.projects = [];
    for (const c of doc.cases as { ref: string; expect: string | null; why: string }[]) {
      expect(resolveFieldRef(`\${${c.ref}}`, true).resolved, c.why).toBe(c.expect);
    }
  });

  it('field aliases', () => {
    const doc = JSON.parse(readFileSync(join(FIXTURES, 'field-aliases.json'), 'utf8'));
    // Every field holds its own name, so a resolved reference reports which
    // field it landed on. The metadata fields carry values too, so the
    // deny-list below is exercised rather than satisfied by their absence.
    st.vault.api_keys = [
      {
        provider: 'E',
        api_key: 'api_key',
        api_secret: 'api_secret',
        username: 'username',
        api_url: 'api_url',
        email: 'email',
        key_id: 'key_id',
        mount_path: 'mount_path',
        id: 'b3f1c0de-0000-4000-8000-000000000001',
        categories: ['categories'],
        projectIds: ['Universal'],
        version_history: [{ value: 'old', saved_at: '2026-01-01T00:00:00Z' }],
      },
      {
        provider: doc.extra_var_fallback.provider,
        api_key: 'api_key',
        id: 'b3f1c0de-0000-4000-8000-000000000002',
        categories: [],
        projectIds: ['Universal'],
        extra_vars: [{ key: doc.extra_var_fallback.var_key, value: doc.extra_var_fallback.value }],
      },
    ] as any;
    st.vault.projects = [];
    for (const [alias, expected] of Object.entries(doc.aliases as Record<string, string>)) {
      expect(resolveFieldRef(`\${E/${alias}}`, true).resolved, `\${E/${alias}}`).toBe(expected);
    }
    // Phase 21: entry metadata is not addressable. Before the deny-list the CLI
    // answered `${E/id}` with the entry's UUID and wrote it into a config.
    for (const field of doc.unresolvable as string[]) {
      const r = resolveFieldRef(`\${E/${field}}`, true);
      expect(r.resolved, `\${E/${field}} must not resolve`).toBeNull();
      expect(r.unresolved, `\${E/${field}} must report unresolved`).toBe(true);
    }
    // ...and an empty built-in falls through to extra_vars, as the CLI does.
    const fb = doc.extra_var_fallback;
    expect(resolveFieldRef(`\${${fb.provider}/${fb.field}}`, true).resolved).toBe(fb.value);

    // Phase 23: a role declared on the entry beats the alias table.
    st.vault.api_keys = [
      { ...doc.role_aware.entry, id: 'r-1', projectIds: ['Universal'] },
      { ...doc.role_aware_id.entry, id: 'r-2', projectIds: ['Universal'] },
    ] as any;
    for (const c of doc.role_aware.cases as any[]) {
      expect(resolveFieldRef(`\${R/${c.field}}`, true).resolved, c.why).toBe(c.expect);
    }
    const ri = doc.role_aware_id;
    expect(resolveFieldRef(`\${S/${ri.field}}`, true).resolved, ri._why).toBe(ri.expect);
  });

  /**
   * The env-name template and `.env` quoting — Phase 23, step 1.
   *
   * A fifth twin pair, and the third one in this project that existed as two
   * implementations before anybody wrote a fixture for it. There were in fact
   * *three* name builders before this: `dotenvKey` (provider + key_id),
   * `envKey` in `import-export.ts` (provider only) and `data::env_key` in the
   * CLI (provider only). The same entry exported under two different names
   * depending on which button you pressed.
   *
   * The quoting half asserts the **round trip** rather than only the bytes:
   * `parse(write(v)) === v` is the property a `.env` has to have, and it is the
   * one that was false for every value containing a space, a `#`, a quote or a
   * newline.
   */
  it('env names and .env quoting', () => {
    const doc = JSON.parse(readFileSync(join(FIXTURES, 'env-names.json'), 'utf8'));

    for (const c of doc.names as any[]) {
      expect(
        envName(c.entry, {
          role: c.role,
          case: c.case as EnvNameCase | undefined,
          includePrefix: !!c.includePrefix,
        }),
        c.why,
      ).toBe(c.expect);
    }

    for (const c of doc.roles as any[]) {
      expect(primaryEnvName(c.entry), `primary: ${c.why}`).toBe(c.primary);
      expect(secretEnvName(c.entry), `secret: ${c.why}`).toBe(c.secret);
    }

    // E9 — the reference grammar and the template share a syntactic position.
    const savedKeys = st.vault.api_keys;
    const savedProjects = st.vault.projects;
    st.vault.api_keys = doc.reference_lookup.entries as any;
    st.vault.projects = [];
    for (const c of doc.reference_lookup.cases as any[]) {
      const found = findEntryByRef(c.ref);
      expect(found?.account_name ?? null, c.why).toBe(c.expect);
    }
    st.vault.api_keys = savedKeys;
    st.vault.projects = savedProjects;

    for (const c of doc.quoting as any[]) {
      expect(quoteEnvValue(c.value), `write: ${c.why}`).toBe(c.written);
      // The property, not the spelling: a value that survives a write and a
      // parse is one a deploy can rely on.
      expect(unquoteEnvValue(quoteEnvValue(c.value)), `round trip: ${c.why}`).toBe(c.value);
    }

    for (const c of doc.unquoting as any[]) {
      expect(unquoteEnvValue(c.raw), c.why).toBe(c.expect);
    }
  });

  /**
   * Copy profiles — Phase 23, step 3. A sixth twin pair.
   *
   * It exists twice because the app's Copy button puts the text on the
   * clipboard with no Rust in the loop, and `unv get --profile` writes the same
   * text from the terminal. A copy that differs between the two is a `.env`
   * whose contents depend on which half of the product the user reached for.
   */
  it('copy profiles', () => {
    const doc = JSON.parse(readFileSync(join(FIXTURES, 'copy-profiles.json'), 'utf8'));
    for (const c of doc.cases as any[]) {
      expect(
        buildCopyText(doc.entry, { profile: c.profile, metadataStyle: c.metadataStyle }),
        c.why,
      ).toBe((c.expect as string[]).join('\n'));
    }
    const col = doc.collision;
    expect(
      buildCopyText(col.entry, { profile: col.profile, metadataStyle: col.metadataStyle }),
      'a name collision inside one entry is disambiguated, never dropped',
    ).toBe((col.expect as string[]).join('\n'));

    const sp = doc.sparse;
    expect(
      buildCopyText(sp.entry, { profile: sp.profile, metadataStyle: sp.metadataStyle }),
      'an entry with no primary value emits no empty primary line',
    ).toBe((sp.expect as string[]).join('\n'));
  });

  /**
   * How a credential is sent — Phase 23, E16. A seventh twin pair.
   *
   * The app's "Copy as request header" builds the header with no Rust in the
   * loop and `unv curl` builds the same one from the terminal; a header that
   * differs between them is a request that works from one half of the product
   * and 401s from the other, with the API explaining neither.
   */
  it('auth schemes and shell quoting', () => {
    const doc = JSON.parse(readFileSync(join(FIXTURES, 'auth-request.json'), 'utf8'));
    for (const c of doc.cases as any[]) {
      const h = authHeaderFor(c.entry);
      expect(h ? [h.name, h.value] : null, `header: ${c.why}`).toEqual(c.header);
      expect(authQueryFor(c.entry), `query: ${c.why}`).toBe(c.query);
      if (c.url_in) expect(authUrlFor(c.entry, c.url_in), `url: ${c.why}`).toBe(c.url_out);
      expect(curlFor(c.entry, c.url_in || undefined), `curl: ${c.why}`).toBe(c.curl);
    }
    for (const c of doc.shell_quote as any[]) {
      expect(shellQuote(c.value), c.why).toBe(c.expect);
    }
  });

  /**
   * Session cookies — Phase 23, step 5. An eighth twin pair.
   *
   * The form splits a pasted `document.cookie` as it is typed, so an IPC round
   * trip per keystroke is not an option — the same reason the TOTP seed parser
   * exists twice.
   */
  it('cookie parsing and writing', () => {
    const doc = JSON.parse(readFileSync(join(FIXTURES, 'cookies.json'), 'utf8'));
    const norm = (c: any) => ({
      name: c.name,
      value: c.value,
      domain: c.domain ?? null,
      path: c.path ?? null,
      secure: !!c.secure,
      http_only: !!c.http_only,
      expires: c.expires ?? 0,
    });

    for (const c of doc.parse_header as any[]) {
      expect(parseCookieHeader(c.raw).map(norm), c.why).toEqual(
        (c.expect as any[]).map((e) => norm({ ...e })),
      );
    }
    for (const c of doc.parse_txt as any[]) {
      expect(parseCookiesTxt(c.raw).map(norm), c.why).toEqual((c.expect as any[]).map(norm));
    }
    for (const c of doc.parse_json as any[]) {
      expect(parseCookieJson(c.raw).map(norm), c.why).toEqual((c.expect as any[]).map(norm));
    }
    for (const c of doc.to_header as any[]) {
      expect(toCookieHeader(c.cookies), c.why).toBe(c.expect);
    }
    for (const c of doc.to_txt as any[]) {
      expect(toCookiesTxt(c.cookies), c.why).toBe(c.expect);
    }
    for (const c of doc.to_txt_refused as any[]) {
      expect(missingTxtAttributes(c.cookies), c.why).toEqual(c.missing);
      expect(() => toCookiesTxt(c.cookies), c.why).toThrow();
    }
  });

  it('nginx_upstream chunk', () => {
    const chunk = (project('edge') as any).chunks.find(
      (c: any) => c.chunk_type === 'nginx_upstream',
    );
    golden('chunk-nginx-upstream.txt', chunkToString(chunk));
  });
});
