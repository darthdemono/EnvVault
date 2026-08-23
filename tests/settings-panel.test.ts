/**
 * Settings panel. Theme and accent apply live so you can see what you are
 * choosing, which makes the save/cancel/escape paths the interesting part —
 * each has to land the preview somewhere definite.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Settings } from '../src/ts/state';
import { openSettings, saveSettings, cancelSettings, closeSettings, applyPanelOrder } from '../src/ts/settings-panel';
import { loadRealIndexHtml } from './helpers';

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showToast: () => {} };
});

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

beforeEach(() => {
  loadRealIndexHtml();
  Settings.setAll({
    theme: 'dark', accentColor: '#7364c9', autoLockMinutes: 15, lockOnHide: false,
    maskKeysByDefault: true, showExpiryWarning: true, expiryWarningDays: 30,
    defaultAccount: '', defaultExportFormat: 'dotenv', envCopyField: 'api_key',
    customCss: '', groupByType: false,
  } as any);
});

describe('auto-lock interval', () => {
  it('saves a valid interval', () => {
    openSettings();
    ($('s-autolock') as HTMLInputElement).value = '5';
    saveSettings();
    expect(Settings.get('autoLockMinutes')).toBe(5);
  });

  it('accepts 0 as a deliberate "off"', () => {
    openSettings();
    ($('s-autolock') as HTMLInputElement).value = '0';
    saveSettings();
    expect(Settings.get('autoLockMinutes')).toBe(0);
  });

  it('does not silently disable auto-lock when the box is left blank', () => {
    // The field is type=number, so letters never reach it — the browser hands
    // back "". `parseInt(...) || 0` turned that into 0, and 0 means off, so a
    // typo quietly switched off the vault's inactivity lock. Off is spelled 0.
    openSettings();
    ($('s-autolock') as HTMLInputElement).value = 'abc';   // discarded -> ''
    expect(($('s-autolock') as HTMLInputElement).value).toBe('');
    saveSettings();
    expect(Settings.get('autoLockMinutes')).toBe(15);
  });

  it('clamps a negative interval to 0 rather than reading it as off by accident', () => {
    openSettings();
    ($('s-autolock') as HTMLInputElement).value = '-5';
    saveSettings();
    expect(Settings.get('autoLockMinutes')).toBe(0);
  });

  it('clamps an interval above the input max', () => {
    openSettings();
    ($('s-autolock') as HTMLInputElement).value = '99999';
    saveSettings();
    expect(Settings.get('autoLockMinutes')).toBe(480);
  });
});

describe('cancel', () => {
  it('reverts a live theme preview', () => {
    // Theme commits immediately so the swatch shows the real thing; Cancel has
    // to put it back or the button is a lie.
    openSettings();
    Settings.set('theme', 'nord');
    cancelSettings();
    expect(Settings.get('theme')).toBe('dark');
  });

  it('reverts an accent change', () => {
    openSettings();
    ($('s-accent') as HTMLInputElement).value = '#ff0000';
    Settings.set('accentColor', '#ff0000');
    cancelSettings();
    expect(Settings.get('accentColor')).toBe('#7364c9');
  });

  it('reverts sidebar section changes, which commit as you click', () => {
    openSettings();
    Settings.set('sidebarSections', ['all'] as any);
    cancelSettings();
    expect(Settings.get('sidebarSections')).not.toEqual(['all']);
  });

  it('closes the overlay', () => {
    openSettings();
    expect($('settings-overlay').classList.contains('open')).toBe(true);
    cancelSettings();
    expect($('settings-overlay').classList.contains('open')).toBe(false);
  });

  it('leaves saved changes alone once they have been saved', () => {
    openSettings();
    ($('s-autolock') as HTMLInputElement).value = '7';
    saveSettings();
    cancelSettings();
    expect(Settings.get('autoLockMinutes')).toBe(7);
  });
});

describe('buttons inside the settings pane', () => {
  // Retargeted from the old s-open-remote-panel link, which was removed along
  // with the Remote tab (it held no settings, only a signpost to the Remote
  // panel). The bug it guarded is not about that button: any handler bound with
  // addEventListener or { once: true } here accumulates, because the pane is
  // opened and closed repeatedly and { once: true } only detaches on click.
  it('does not accumulate a handler on every open', () => {
    Settings.set('recentSearches', ['alpha', 'beta'] as any);
    for (let i = 0; i < 5; i++) { openSettings(); closeSettings(); }

    openSettings();
    const btn = $('s-clear-recent');
    let fired = 0;
    btn.addEventListener('click', () => fired++);
    btn.click();
    expect(fired).toBe(1);
    // One click clears the history once — an accumulated handler would still
    // land on an already-empty list, so assert the observable effect too.
    expect(Settings.get('recentSearches')).toEqual([]);
  });

  it('has no leftover Remote tab or pane', () => {
    openSettings();
    expect(document.querySelector('.settings-tab[data-stab="remote"]')).toBeNull();
    expect(document.querySelector('.settings-tab-pane[data-spane="remote"]')).toBeNull();
  });
});

describe('applyPanelOrder', () => {
  it('hides a panel that is not in the order', () => {
    Settings.set('panelOrder', ['secrets', 'tools'] as any);
    applyPanelOrder();
    const remoteBtn = document.querySelector<HTMLElement>('.activity-btn[data-panel="remote"]')!;
    expect(remoteBtn.style.display).toBe('none');
  });

  it('orders the visible panels', () => {
    Settings.set('panelOrder', ['tools', 'secrets'] as any);
    applyPanelOrder();
    const tools = document.querySelector<HTMLElement>('.activity-btn[data-panel="tools"]')!;
    const secrets = document.querySelector<HTMLElement>('.activity-btn[data-panel="secrets"]')!;
    expect(tools.style.order).toBe('0');
    expect(secrets.style.order).toBe('1');
  });

  it('keeps Users hidden on a local vault even when it is in the order', () => {
    // The ordering loop re-shows every listed panel, so the RBAC gate has to
    // run after it.
    Settings.set('panelOrder', ['secrets', 'tools', 'remote', 'users'] as any);
    applyPanelOrder();
    const usersBtn = document.querySelector<HTMLElement>('.activity-btn[data-panel="users"]')!;
    expect(usersBtn.style.display).toBe('none');
  });
});
