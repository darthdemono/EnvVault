/**
 * Experimental project types.
 *
 * Only Generic, WireGuard, Docker and Nginx have been exercised end to end. The
 * other seven have config views, starter chunks and exporters, but nothing has
 * been checked against a real deployment — and a config this app writes wrong
 * is a broken deploy, not a cosmetic bug. So they are off by default.
 *
 * The gate is on *creation only*. Hiding the config view of a project that
 * already uses one of these types would leave its chunks in the vault with no
 * way to reach them, which is the invariant-3 failure mode: data present but
 * invisible.
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

const EXPERIMENTAL = [
  'kubernetes',
  'ssh_config',
  'traefik',
  'apache',
  'haproxy',
  'ansible',
  'postgres',
];

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  st.vault = makeVault({ projects: [makeProject({ id: 'Universal', name: 'Universal' })] });
  Settings.set('experimentalProjectTypes', false);
});

describe('type classification', () => {
  it('treats exactly the four tested types as stable', () => {
    expect([...STABLE_PROJECT_TYPES].sort()).toEqual(['docker', 'generic', 'nginx', 'wireguard']);
  });

  it('classifies every untested type as experimental', () => {
    EXPERIMENTAL.forEach((t) => expect(isExperimentalProjectType(t as any), t).toBe(true));
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
  it('hides every experimental type by default', () => {
    openProjectCreateModal();
    EXPERIMENTAL.forEach((t) => expect(typeBtn(t)!.style.display, t).toBe('none'));
  });

  it('always offers the four tested types', () => {
    openProjectCreateModal();
    STABLE_PROJECT_TYPES.forEach((t) => expect(typeBtn(t)!.style.display, t).not.toBe('none'));
  });

  it('reveals the experimental types once the setting is on', () => {
    Settings.set('experimentalProjectTypes', true);
    openProjectCreateModal();
    EXPERIMENTAL.forEach((t) => expect(typeBtn(t)!.style.display, t).not.toBe('none'));
  });

  it('marks the revealed types so they do not look proven', () => {
    Settings.set('experimentalProjectTypes', true);
    openProjectCreateModal();
    expect(typeBtn('kubernetes')!.classList.contains('experimental')).toBe(true);
    expect(typeBtn('docker')!.classList.contains('experimental')).toBe(false);
  });

  it('re-applies visibility when the setting changes mid-session', () => {
    // The picker is static markup that nothing else repaints, so a toggle with
    // the app already running has to be picked up on the next open.
    Settings.set('experimentalProjectTypes', true);
    openProjectCreateModal();
    expect(typeBtn('traefik')!.style.display).not.toBe('none');

    Settings.set('experimentalProjectTypes', false);
    openProjectCreateModal();
    expect(typeBtn('traefik')!.style.display).toBe('none');
  });
});

describe('setProjectCreateType guard', () => {
  it('refuses a gated type and falls back to generic', () => {
    // display:none is a paint-time gate on a delegated click handler. Creating
    // the project is what writes project_type into the vault, so the refusal
    // belongs at the write too.
    openProjectCreateModal();
    setProjectCreateType('kubernetes');
    ($('project-create-name') as HTMLInputElement).value = 'k8s-test';
    saveProjectCreate();

    const created = st.vault.projects.find((p) => p.name === 'k8s-test')!;
    expect(created).toBeTruthy();
    expect(created.project_type).toBeUndefined();
  });

  it('accepts a gated type once the setting is on', () => {
    Settings.set('experimentalProjectTypes', true);
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
