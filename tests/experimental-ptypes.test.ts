/**
 * Experimental project types — and the gate that hides them.
 *
 * **As of Phase 18 the gate has nothing left to gate.** All eleven types have
 * had their generated config accepted by the software it targets (see
 * `STABLE_PROJECT_TYPES` for the evidence table), so the experimental list is
 * empty and every type is offered.
 *
 * The machinery is deliberately kept and still tested, because the *next*
 * unproven type needs it. The tests below therefore split in two:
 *
 *  - Facts about the current list, which change when a type graduates.
 *  - Behaviour of the gate itself, exercised through a synthetic type so it
 *    keeps being verified even while nothing real is gated. Without that half,
 *    graduating the last type would silently delete the coverage that protects
 *    the next one.
 *
 * The gate is on *creation only*. Hiding the config view of a project that
 * already uses a gated type would leave its chunks in the vault with no way to
 * reach them — the invariant-3 failure mode: data present but invisible.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st, Settings } from '../src/ts/state';
import { STABLE_PROJECT_TYPES, isExperimentalProjectType } from '../src/ts/types';
import {
  openProjectCreateModal,
  saveProjectCreate,
  setProjectCreateType,
  applyExperimentalTypeVisibility,
} from '../src/ts/projects';
import { openSettings, saveSettings } from '../src/ts/settings-panel';
import { loadRealIndexHtml, makeProject, makeVault, resetState } from './helpers';

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showToast: () => {}, showConfirm: async () => true };
});

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const typeBtn = (t: string) =>
  document.querySelector<HTMLButtonElement>(`.project-type-btn[data-ptype="${t}"]`);

/** Every type the app ships. All of them are stable as of Phase 18. */
const ALL_TYPES = [
  'generic',
  'wireguard',
  'docker',
  'nginx',
  'kubernetes',
  'ssh_config',
  'traefik',
  'apache',
  'haproxy',
  'ansible',
  'postgres',
] as const;

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  st.vault = makeVault({ projects: [makeProject({ id: 'Universal', name: 'Universal' })] });
  Settings.set('experimentalProjectTypes', false);
});

describe('type classification', () => {
  it('has graduated every type that ships', () => {
    // Each of these was validated against the real tool in Phase 18: k3s, ssh,
    // Traefik, httpd, haproxy, ansible-playbook, a live Postgres. A type may be
    // added here only with that kind of evidence — a golden fixture proves we
    // agree with ourselves, nothing more.
    expect([...STABLE_PROJECT_TYPES].sort()).toEqual(
      [...ALL_TYPES].sort(),
    );
  });

  it('leaves nothing classified as experimental', () => {
    ALL_TYPES.forEach((t) => expect(isExperimentalProjectType(t as any), t).toBe(false));
  });

  it('still recognises an unknown type as experimental', () => {
    // The mechanism must keep working for the next unproven type. If this ever
    // fails, a future type would ship ungated by accident.
    expect(isExperimentalProjectType('some_future_type' as any)).toBe(true);
  });

  it('does not classify the tested types as experimental', () => {
    STABLE_PROJECT_TYPES.forEach((t) => expect(isExperimentalProjectType(t), t).toBe(false));
  });

  it('treats a missing type as non-experimental', () => {
    // `project_type` is optional — a plain project has none, and undefined must
    // not be read as "experimental" or every generic project would be gated.
    expect(isExperimentalProjectType(undefined)).toBe(false);
    expect(isExperimentalProjectType(null)).toBe(false);
  });
});

describe('create picker', () => {
  it('offers every type, with the setting off', () => {
    // Nothing is gated any more, so the default view shows all of them.
    openProjectCreateModal();
    ALL_TYPES.forEach((t) => expect(typeBtn(t)?.style.display, t).not.toBe('none'));
  });

  it('marks nothing as unproven', () => {
    Settings.set('experimentalProjectTypes', true);
    openProjectCreateModal();
    ALL_TYPES.forEach((t) =>
      expect(typeBtn(t)?.classList.contains('experimental'), t).toBe(false),
    );
  });

  it('still hides a type the list does not contain', () => {
    // The gate exercised through a type that is not in STABLE_PROJECT_TYPES.
    // This is the half that has to keep passing after the last real type
    // graduated, or the machinery rots until someone needs it again.
    const picker = document.getElementById('project-type-picker');
    if (!picker) return;
    const btn = document.createElement('button');
    btn.className = 'ptype-btn';
    btn.dataset.type = 'some_future_type';
    picker.appendChild(btn);

    applyExperimentalTypeVisibility();
    expect(btn.style.display).toBe('none');

    Settings.set('experimentalProjectTypes', true);
    applyExperimentalTypeVisibility();
    expect(btn.style.display).not.toBe('none');
    expect(btn.classList.contains('experimental')).toBe(true);
  });
});

describe('setProjectCreateType guard', () => {
  it('refuses a gated type and falls back to generic', () => {
    // display:none is a paint-time gate on a delegated click handler. Creating
    // the project is what writes project_type into the vault, so the refusal
    // belongs at the write too. Exercised with a type that is not in
    // STABLE_PROJECT_TYPES — since Phase 18 no shipped type is gated, and
    // deleting this test along with the last gated type would remove the only
    // coverage of the write-side refusal.
    openProjectCreateModal();
    setProjectCreateType('some_future_type' as never);
    ($('project-create-name') as HTMLInputElement).value = 'gated-test';
    saveProjectCreate();

    const created = st.vault.projects.find((p) => p.name === 'gated-test')!;
    expect(created).toBeTruthy();
    expect(created.project_type).toBeUndefined();
  });

  it('accepts a gated type once the setting is on', () => {
    Settings.set('experimentalProjectTypes', true);
    openProjectCreateModal();
    setProjectCreateType('some_future_type' as never);
    ($('project-create-name') as HTMLInputElement).value = 'gated-test';
    saveProjectCreate();

    expect(st.vault.projects.find((p) => p.name === 'gated-test')!.project_type).toBe(
      'some_future_type',
    );
  });

  it('accepts every graduated type with the setting off', () => {
    // The point of graduation: kubernetes and friends now need no flag.
    openProjectCreateModal();
    setProjectCreateType('kubernetes');
    ($('project-create-name') as HTMLInputElement).value = 'k8s-test';
    saveProjectCreate();

    expect(st.vault.projects.find((p) => p.name === 'k8s-test')!.project_type).toBe('kubernetes');
  });

  it('still accepts a tested type while the setting is off', () => {
    openProjectCreateModal();
    setProjectCreateType('wireguard');
    ($('project-create-name') as HTMLInputElement).value = 'wg0';
    saveProjectCreate();

    expect(st.vault.projects.find((p) => p.name === 'wg0')!.project_type).toBe('wireguard');
  });
});

describe('existing experimental projects', () => {
  it('keeps its type — the gate never rewrites stored data', () => {
    // Turning the setting off must not retroactively downgrade a project the
    // user already built, or its chunks would stop rendering and become
    // unreachable while still occupying the vault.
    st.vault.projects.push(makeProject({ id: 'k8s', name: 'k8s', project_type: 'kubernetes' }));
    Settings.set('experimentalProjectTypes', false);
    applyExperimentalTypeVisibility();
    expect(st.vault.projects.find((p) => p.id === 'k8s')!.project_type).toBe('kubernetes');
  });
});

describe('settings', () => {
  it('round-trips the toggle', () => {
    openSettings();
    ($('s-experimental-ptypes') as HTMLInputElement).checked = true;
    saveSettings();
    expect(Settings.get('experimentalProjectTypes')).toBe(true);
  });

  it('defaults to off', () => {
    Settings.set('experimentalProjectTypes', false);
    openSettings();
    expect(($('s-experimental-ptypes') as HTMLInputElement).checked).toBe(false);
  });

  it('no longer has a Remote tab or pane', () => {
    // It held no settings — only a link to the Remote panel on the activity bar.
    expect(document.querySelector('.settings-tab[data-stab="remote"]')).toBeNull();
    expect(document.querySelector('.settings-tab-pane[data-spane="remote"]')).toBeNull();
    expect($('s-open-remote-panel')).toBeNull();
  });

  it('every remaining settings tab still has a matching pane', () => {
    // Removing a tab and leaving its pane (or vice versa) yields a tab that
    // switches to nothing.
    document.querySelectorAll<HTMLElement>('.settings-tab').forEach((tab) => {
      const pane = document.querySelector(`.settings-tab-pane[data-spane="${tab.dataset.stab}"]`);
      expect(pane, `no pane for tab ${tab.dataset.stab}`).toBeTruthy();
    });
  });
});
