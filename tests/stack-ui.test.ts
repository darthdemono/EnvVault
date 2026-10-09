/**
 * Stack integrations in the app (Phase 38): creating a Prometheus, Grafana or
 * Homepage project, its header controls, adding a chunk from the descriptor, and
 * exporting the file. The interpreter itself is pinned against golden files in
 * `tests/stack.test.ts`.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { st, Settings } from '../src/ts/state';
import { render } from '../src/ts/render';
import { isExperimentalProjectType } from '../src/ts/types';
import {
  openProjectCreateModal,
  saveProjectCreate,
  setProjectCreateType,
} from '../src/ts/projects';
import { exportStack, getProjectTypeLabel, makeConfigViewHeaderBtns } from '../src/ts/chunk-ops';
import { stackAdapters, stackChunkTypes } from '../src/ts/stack';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

const toasts: string[] = [];
vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return {
    ...real,
    showToast: (m: string) => {
      toasts.push(m);
    },
    showConfirm: async () => true,
  };
});

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  toasts.length = 0;
  st.vault = makeVault({ projects: [makeProject({ id: 'Universal', name: 'Universal' })] });
  Settings.set('experimentalProjectTypes', true);
});

function create(type: string, name: string) {
  openProjectCreateModal();
  setProjectCreateType(type as never);
  $<HTMLInputElement>('project-create-name').value = name;
  saveProjectCreate();
  return st.vault.projects.find((p) => p.name === name)!;
}

describe('the types are known to the type system', () => {
  it('lists every descriptor chunk type and project type in types.ts', () => {
    // The unions in types.ts are hand-written; this fails when they and the
    // descriptor file disagree, which a compiler cannot see.
    const src = readFileSync(join(process.cwd(), 'src', 'ts', 'types.ts'), 'utf8');
    for (const t of stackChunkTypes()) expect(src, t).toContain(`'${t}'`);
    for (const a of stackAdapters()) expect(src, a.id).toContain(`'${a.id}'`);
  });

  it('keeps them experimental until their output has been accepted by the real software in CI', () => {
    for (const a of stackAdapters())
      expect(isExperimentalProjectType(a.id as never), a.id).toBe(true);
  });

  it('labels them', () => {
    expect(getProjectTypeLabel('prometheus')).toBe('Prometheus');
    expect(getProjectTypeLabel('homepage')).toBe('Homepage');
  });
});

describe('creating a stack project', () => {
  it.each(stackAdapters().map((a) => [a.id, a.starter.map((s) => s.type)] as const))(
    '%s starts with the descriptors starter chunks and their defaults',
    (id, types) => {
      const p = create(id, `my-${id}`);
      expect(p.project_type).toBe(id);
      expect((p.chunks ?? []).map((c) => c.chunk_type)).toEqual(types);
    },
  );

  it('is refused while experimental types are off, at the write as well as the paint', () => {
    Settings.set('experimentalProjectTypes', false);
    const p = create('prometheus', 'gated');
    expect(p.project_type).toBeUndefined();
  });

  it('has a creation button for each', () => {
    for (const id of ['prometheus', 'grafana', 'homepage']) {
      expect(document.querySelector(`.project-type-btn[data-ptype="${id}"]`), id).not.toBeNull();
    }
  });
});

describe('the config view of a stack project', () => {
  function open(type: string) {
    const p = create(type, `v-${type}`);
    st.vault.api_keys = [makeEntry({ id: 'e1', provider: 'PromPw', api_key: 'pw-from-vault' })];
    st.currentSelectedProjectIds = [p.id];
    render();
    return p;
  }

  it('has an add button per chunk type and an export button naming the file', () => {
    const p = makeProject({ id: 'x', name: 'x', project_type: 'prometheus' as never });
    const html = String(makeConfigViewHeaderBtns(p));
    expect(html).toContain('data-chunk-type="prom_scrape"');
    expect(html).toContain('+ Scrape job');
    expect(html).toContain('+ Remote write');
    expect(html).toContain('Export prometheus.yml');
  });

  it('adds a scrape job with its defaults from the descriptor', () => {
    const p = open('prometheus');
    const before = p.chunks!.length;
    document
      .querySelector<HTMLElement>('[data-action="add-stack-chunk"][data-chunk-type="prom_scrape"]')!
      .click();
    expect(p.chunks!.length).toBe(before + 1);
    const added = p.chunks![before];
    expect(added.chunk_type).toBe('prom_scrape');
    expect(added.fields.find((f) => f.key === 'targets')!.value).toBe('localhost:9090');
    expect(added.name).toBe('scrape-2');
  });

  it('refuses a second singleton section', () => {
    const p = open('prometheus');
    const before = p.chunks!.length;
    document
      .querySelector<HTMLElement>('[data-action="add-stack-chunk"][data-chunk-type="prom_global"]')!
      .click();
    expect(p.chunks!.length).toBe(before);
    expect(toasts.join()).toContain('already has its global section');
  });

  it('exports the file with references resolved, for the clipboard or a download', () => {
    const p = open('prometheus');
    const scrape = p.chunks!.find((c) => c.chunk_type === 'prom_scrape')!;
    scrape.fields.find((f) => f.key === 'username')!.value = 'scraper';
    scrape.fields.find((f) => f.key === 'password')!.value = '${PromPw}';
    const out = exportStack(p);
    expect(out).toContain('username: scraper');
    expect(out).toContain('password: pw-from-vault');
    expect(out).not.toContain('${');
  });
});
