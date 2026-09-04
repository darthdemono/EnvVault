/**
 * Persistence of UI state across sessions, plus the QOL affordances added
 * alongside it.
 *
 * The interesting cases are all "the persisted thing points at something that
 * changed" — a project id that the vault no longer has, a sort mode a later
 * build removed, a sidebar width written by a different screen size. Every one
 * of those has to degrade to the default rather than leave the user staring at
 * a grid that filters everything out.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  st,
  Settings,
  applySidebarLayout,
  saveViewState,
  restoreViewState,
  clearAllFilters,
  pushRecentSearch,
  resetViewState,
  RECENT_SEARCH_MAX,
  SIDEBAR_MIN_W,
  SIDEBAR_MAX_W,
} from '../src/ts/state';
import {
  passwordStrength,
  relativeTime,
  openSearchHistory,
  closeSearchHistory,
  wireRevealButtons,
  resetReveal,
  wireCapsLockHint,
} from '../src/ts/ui-qol';
import { updateActiveFilterBar, activeFilterLabels } from '../src/ts/render';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault } from './helpers';

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

beforeEach(() => {
  loadRealIndexHtml();
  Settings.setAll({
    rememberFilters: true,
    lastView: null,
    recentSearches: [],
    sidebarWidth: 0,
    sidebarCollapsed: false,
  } as any);
  resetViewState();
});

// ── Sidebar layout ──────────────────────────────────────────────────────────

describe('sidebar width persistence', () => {
  it('applies a stored width', () => {
    Settings.set('sidebarWidth', 300);
    applySidebarLayout();
    expect($('sidebar').style.width).toBe('300px');
  });

  it('uses the stylesheet default when the width is 0', () => {
    Settings.set('sidebarWidth', 0);
    applySidebarLayout();
    expect($('sidebar').style.width).toBe('');
  });

  it('clamps a stored width that is below the drag minimum', () => {
    // The width survives in localStorage, so a value written by an older build
    // or a hand-edited settings file outlives the drag handler's own clamp.
    // Unclamped, a 3px sidebar leaves no visible handle to drag back out.
    Settings.set('sidebarWidth', 3);
    applySidebarLayout();
    expect($('sidebar').style.width).toBe(`${SIDEBAR_MIN_W}px`);
  });

  it('clamps a stored width above the maximum', () => {
    Settings.set('sidebarWidth', 9999);
    applySidebarLayout();
    expect($('sidebar').style.width).toBe(`${SIDEBAR_MAX_W}px`);
  });

  it('ignores a non-numeric stored width instead of writing it into style.width', () => {
    // Guards against a corrupt settings blob injecting a CSS value.
    Settings.set('sidebarWidth', 'calc(100% - 3px)' as any);
    applySidebarLayout();
    expect($('sidebar').style.width).toBe('');
  });

  it('restores the collapsed state', () => {
    Settings.set('sidebarCollapsed', true);
    applySidebarLayout();
    expect($('sidebar').classList.contains('collapsed')).toBe(true);

    Settings.set('sidebarCollapsed', false);
    applySidebarLayout();
    expect($('sidebar').classList.contains('collapsed')).toBe(false);
  });
});

// ── View persistence ────────────────────────────────────────────────────────

describe('view persistence', () => {
  beforeEach(() => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({
          provider: 'Stripe',
          environment: 'production',
          tags: ['billing'],
          price_type: 'paid',
          projectIds: ['Universal', 'p-web'],
        }),
      ],
      user_categories: ['payments'],
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'p-web', name: 'Web' }),
      ],
    });
  });

  it('round-trips a filter selection', () => {
    st.filter = { type: 'category', value: 'payments' };
    st.currentEnvFilter = 'production';
    st.activeTagFilter = 'billing';
    st.currentSelectedProjectIds = ['p-web'];
    saveViewState();

    clearAllFilters();
    expect(restoreViewState()).toBe(true);
    expect(st.filter).toEqual({ type: 'category', value: 'payments' });
    expect(st.currentEnvFilter).toBe('production');
    expect(st.activeTagFilter).toBe('billing');
    expect(st.currentSelectedProjectIds).toEqual(['p-web']);
  });

  it('drops a project id the vault no longer has', () => {
    // The bug this prevents: a stale project id matches nothing in
    // getFiltered(), so the app opens to an empty grid with every secret
    // present but invisible — and the filter that hid them is not one the user
    // set this session, so there is no obvious control to undo.
    Settings.set('lastView', {
      filterType: 'all',
      filterValue: '',
      envFilter: '',
      tagFilter: null,
      prefixFilter: null,
      projectIds: ['p-deleted'],
    });
    restoreViewState();
    expect(st.currentSelectedProjectIds).toEqual(['Universal']);
  });

  it('drops a category no longer in the vault', () => {
    Settings.set('lastView', {
      filterType: 'category',
      filterValue: 'gone',
      envFilter: '',
      tagFilter: null,
      prefixFilter: null,
      projectIds: [],
    });
    restoreViewState();
    expect(st.filter.type).toBe('all');
  });

  it('drops an environment no entry uses any more', () => {
    Settings.set('lastView', {
      filterType: 'all',
      filterValue: '',
      envFilter: 'staging',
      tagFilter: null,
      prefixFilter: null,
      projectIds: [],
    });
    restoreViewState();
    expect(st.currentEnvFilter).toBe('');
  });

  it('drops a tag no entry carries any more', () => {
    Settings.set('lastView', {
      filterType: 'all',
      filterValue: '',
      envFilter: '',
      tagFilter: 'retired',
      prefixFilter: null,
      projectIds: [],
    });
    restoreViewState();
    expect(st.activeTagFilter).toBeNull();
  });

  it('keeps a parent category selected when only a child exists', () => {
    // Categories nest by slash. "Acme" is a real selection when the vault only
    // stores "Acme/Web", and dropping it would clear a working filter.
    st.vault.user_categories = ['Acme/Web'];
    Settings.set('lastView', {
      filterType: 'category',
      filterValue: 'Acme',
      envFilter: '',
      tagFilter: null,
      prefixFilter: null,
      projectIds: [],
    });
    restoreViewState();
    expect(st.filter).toEqual({ type: 'category', value: 'Acme' });
  });

  it('saves nothing while rememberFilters is off', () => {
    Settings.set('rememberFilters', false);
    st.filter = { type: 'category', value: 'payments' };
    saveViewState();
    expect(Settings.get('lastView')).toBeNull();
  });

  it('restores nothing while rememberFilters is off', () => {
    Settings.set('lastView', {
      filterType: 'category',
      filterValue: 'payments',
      envFilter: '',
      tagFilter: null,
      prefixFilter: null,
      projectIds: [],
    });
    Settings.set('rememberFilters', false);
    expect(restoreViewState()).toBe(false);
    expect(st.filter.type).toBe('all');
  });

  it('survives a lastView written by an older build with missing keys', () => {
    Settings.set('lastView', { filterType: 'all' } as any);
    expect(() => restoreViewState()).not.toThrow();
  });

  it('reports false when the restored view is the default one', () => {
    // Callers use the return value to decide whether to tell the user their
    // view was restored; the default view is not worth mentioning.
    Settings.set('lastView', {
      filterType: 'all',
      filterValue: '',
      envFilter: '',
      tagFilter: null,
      prefixFilter: null,
      projectIds: ['Universal'],
    });
    expect(restoreViewState()).toBe(false);
  });

  it('resetViewState clears the persisted copy too', () => {
    // Invariant 3: the persisted view is a reference held across a restart.
    // Replacing the vault must not leave the previous vault's selection on disk
    // for the next launch to reapply.
    st.filter = { type: 'category', value: 'payments' };
    saveViewState();
    expect(Settings.get('lastView')).not.toBeNull();
    resetViewState();
    expect(Settings.get('lastView')).toBeNull();
  });
});

describe('clearAllFilters', () => {
  it('clears filters but leaves expand/reveal/bulk state alone', () => {
    // Distinct from resetViewState on purpose: "show me everything" must not
    // also collapse the cards the user opened or drop their bulk ticks.
    st.filter = { type: 'category', value: 'payments' };
    st.searchQ = 'stripe';
    st.currentEnvFilter = 'production';
    st.activeTagFilter = 'billing';
    st.activePrefixFilter = 'AWS_';
    st.currentSelectedProjectIds = ['p-web'];
    st.expanded.add('id-1');
    st.bulkSelected.add('id-1');
    st.bulkMode = true;

    clearAllFilters();

    expect(st.filter).toEqual({ type: 'all', value: '' });
    expect(st.searchQ).toBe('');
    expect(st.currentEnvFilter).toBe('');
    expect(st.activeTagFilter).toBeNull();
    expect(st.activePrefixFilter).toBeNull();
    expect(st.currentSelectedProjectIds).toEqual(['Universal']);
    expect(st.expanded.has('id-1')).toBe(true);
    expect(st.bulkSelected.has('id-1')).toBe(true);
    expect(st.bulkMode).toBe(true);
  });

  it('empties the search box in the DOM, not just st.searchQ', () => {
    const box = $('search') as HTMLInputElement;
    box.value = 'stripe';
    st.searchQ = 'stripe';
    clearAllFilters();
    expect(box.value).toBe('');
  });
});

// ── Active filter bar ───────────────────────────────────────────────────────

describe('active filter bar', () => {
  beforeEach(() => {
    st.vault = makeVault({
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'p-web', name: 'Web' }),
      ],
    });
  });

  it('stays hidden when nothing is filtering the grid', () => {
    updateActiveFilterBar();
    expect($('clear-filters-btn').style.display).toBe('none');
  });

  it('appears as soon as one filter is active', () => {
    st.activeTagFilter = 'billing';
    updateActiveFilterBar();
    expect($('clear-filters-btn').style.display).not.toBe('none');
  });

  it('counts only when more than one filter is active', () => {
    st.activeTagFilter = 'billing';
    updateActiveFilterBar();
    expect($('clear-filters-count').textContent).toBe('');

    st.currentEnvFilter = 'production';
    updateActiveFilterBar();
    expect($('clear-filters-count').textContent).toBe('(2)');
  });

  it('names the project rather than showing its raw id', () => {
    // A UUID in the tooltip tells the user nothing about what is being hidden —
    // which is the whole reason this control exists now that a project
    // selection can survive a restart.
    st.currentSelectedProjectIds = ['p-web'];
    expect(activeFilterLabels()).toContain('project: Web');
  });

  it('does not count the Universal catch-all as a filter', () => {
    st.currentSelectedProjectIds = ['Universal'];
    expect(activeFilterLabels()).toEqual([]);
  });
});

// ── Recent searches ─────────────────────────────────────────────────────────

describe('recent searches', () => {
  it('records most-recent-first', () => {
    pushRecentSearch('alpha');
    pushRecentSearch('beta');
    expect(Settings.get('recentSearches')).toEqual(['beta', 'alpha']);
  });

  it('ignores blank and whitespace-only queries', () => {
    pushRecentSearch('');
    pushRecentSearch('   ');
    expect(Settings.get('recentSearches')).toEqual([]);
  });

  it('de-duplicates case-insensitively, newest casing winning', () => {
    pushRecentSearch('Stripe');
    pushRecentSearch('alpha');
    pushRecentSearch('STRIPE');
    expect(Settings.get('recentSearches')).toEqual(['STRIPE', 'alpha']);
  });

  it('caps the history', () => {
    for (let i = 0; i < RECENT_SEARCH_MAX + 5; i++) pushRecentSearch(`q${i}`);
    expect(Settings.get('recentSearches')).toHaveLength(RECENT_SEARCH_MAX);
  });

  it('does not open the dropdown when there is no history', () => {
    expect(openSearchHistory(() => {})).toBe(false);
    expect($('search-history').style.display).toBe('none');
  });

  it('escapes stored queries before rendering them', () => {
    // The settings blob is plain JSON on disk, so a search string is untrusted
    // input by the time it comes back (invariant 4).
    Settings.set('recentSearches', ['<img src=x onerror=alert(1)>']);
    openSearchHistory(() => {});
    expect($('search-history').querySelector('img')).toBeNull();
    expect($('search-history').textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('hands the picked query back to the caller', () => {
    const picked = vi.fn();
    Settings.set('recentSearches', ['stripe']);
    openSearchHistory(picked);
    $('search-history').querySelector<HTMLElement>('[data-recent]')!.click();
    expect(picked).toHaveBeenCalledWith('stripe');
    expect($('search-history').style.display).toBe('none');
  });

  it('clears the history from the dropdown', () => {
    Settings.set('recentSearches', ['stripe', 'aws']);
    openSearchHistory(() => {});
    $('search-history').querySelector<HTMLElement>('[data-clear-history]')!.click();
    expect(Settings.get('recentSearches')).toEqual([]);
  });

  it('closeSearchHistory is safe when the panel was never opened', () => {
    expect(() => closeSearchHistory()).not.toThrow();
  });
});

// ── Password affordances ────────────────────────────────────────────────────

describe('password reveal', () => {
  it('toggles the input type and back', () => {
    wireRevealButtons(document);
    const input = $('unlock-password') as HTMLInputElement;
    const btn = document.querySelector<HTMLButtonElement>('[data-reveal="unlock-password"]')!;
    expect(input.type).toBe('password');
    btn.click();
    expect(input.type).toBe('text');
    btn.click();
    expect(input.type).toBe('password');
  });

  it('does not toggle twice per click after re-wiring', () => {
    // The unlock and relock screens are shown repeatedly across a lock cycle.
    // With addEventListener, each showing stacked another handler and a click
    // flipped the field an even number of times — leaving it exactly as it was.
    wireRevealButtons(document);
    wireRevealButtons(document);
    wireRevealButtons(document);
    const input = $('unlock-password') as HTMLInputElement;
    document.querySelector<HTMLButtonElement>('[data-reveal="unlock-password"]')!.click();
    expect(input.type).toBe('text');
  });

  it('resetReveal re-masks a revealed field', () => {
    // Without this, revealing once leaves every later visit to the lock screen
    // showing the master password in plaintext — including the auto-lock
    // screen, which fires precisely when the user has walked away.
    wireRevealButtons(document);
    const input = $('relock-password') as HTMLInputElement;
    document.querySelector<HTMLButtonElement>('[data-reveal="relock-password"]')!.click();
    expect(input.type).toBe('text');

    resetReveal('relock-password');
    expect(input.type).toBe('password');
    expect(
      document.querySelector('[data-reveal="relock-password"]')!.classList.contains('active'),
    ).toBe(false);
  });
});

describe('caps lock hint', () => {
  /**
   * A key event as the browser would deliver it, plus a deliberately *lying*
   * `getModifierState`. Both bugs this block covers came from trusting that
   * method under WebKitGTK, so every fixture here disagrees with it.
   */
  const key = (k: string, opts: { shift?: boolean; modifierSays?: boolean } = {}) => {
    const e = new KeyboardEvent('keydown', { key: k, shiftKey: !!opts.shift });
    Object.defineProperty(e, 'getModifierState', { value: () => !!opts.modifierSays });
    return e;
  };

  const wire = () => {
    wireCapsLockHint('unlock-password', 'unlock-capslock');
    return $('unlock-password');
  };
  const shown = () => $('unlock-capslock').style.display === 'flex';

  it('reads caps lock off an unshifted letter', () => {
    const input = wire();
    input.dispatchEvent(key('A'));
    expect(shown()).toBe(true);
    input.dispatchEvent(key('a'));
    expect(shown()).toBe(false);
  });

  it('inverts the reading while shift is held', () => {
    const input = wire();
    // Caps on + Shift produces the *lower* case letter.
    input.dispatchEvent(key('a', { shift: true }));
    expect(shown()).toBe(true);
    input.dispatchEvent(key('A', { shift: true }));
    expect(shown()).toBe(false);
  });

  it('ignores getModifierState, which WebKitGTK reported as on with caps off', () => {
    // The bug: the hint was shown to every user on every unlock screen because
    // GDK's modifier mask said CapsLock regardless of the actual lock state.
    const input = wire();
    input.dispatchEvent(key('a', { modifierSays: true }));
    expect(shown()).toBe(false);
  });

  it('keeps the warning up across keys that carry no case evidence', () => {
    // The other half of the bug: the hint vanished as soon as the user typed on,
    // because a second (disagreeing) event blanked it. Digits, punctuation and
    // editing keys say nothing about caps lock and must not clear it.
    const input = wire();
    input.dispatchEvent(key('A'));
    expect(shown()).toBe(true);
    ['1', '-', 'Backspace', 'Shift', 'Enter'].forEach((k) =>
      input.dispatchEvent(key(k, { modifierSays: false })),
    );
    expect(shown()).toBe(true);
  });

  it('ignores a ctrl/alt chord, which does not produce the letter it names', () => {
    const input = wire();
    const e = new KeyboardEvent('keydown', { key: 'A', ctrlKey: true });
    input.dispatchEvent(e);
    expect(shown()).toBe(false);
  });

  it('hides on blur and forgets the reading', () => {
    // Caps lock can be toggled while the field is unfocused, so the old reading
    // is void rather than merely hidden — a later no-evidence key must not
    // resurrect it.
    const input = wire();
    input.dispatchEvent(key('A'));
    input.dispatchEvent(new FocusEvent('blur'));
    expect(shown()).toBe(false);
    input.dispatchEvent(key('1'));
    expect(shown()).toBe(false);
  });

  it('starts hidden and survives an event with no getModifierState at all', () => {
    const input = wire();
    expect(shown()).toBe(false);
    const e = new KeyboardEvent('keydown', { key: 'a' });
    Object.defineProperty(e, 'getModifierState', { value: undefined });
    expect(() => input.dispatchEvent(e)).not.toThrow();
    expect(shown()).toBe(false);
  });

  it('rebinds rather than stacks when the screen is shown again', () => {
    // invariant 9: the unlock screen is shown, hidden and shown again across a
    // lock cycle; a second wiring must replace the first, not add to it.
    const input = wire();
    wireCapsLockHint('unlock-password', 'unlock-capslock');
    input.dispatchEvent(key('A'));
    expect(shown()).toBe(true);
    input.dispatchEvent(key('a'));
    expect(shown()).toBe(false);
  });
});

describe('passwordStrength', () => {
  it('scores an empty password as nothing at all', () => {
    expect(passwordStrength('')).toMatchObject({ score: 0, label: '' });
  });

  it('rates a long mixed password strong', () => {
    expect(passwordStrength('correct-horse-Battery-9-staple!').score).toBe(4);
  });

  it('does not rate a long run of one character as strong', () => {
    // Length alone would score this 3; the low-entropy penalty is the point.
    expect(passwordStrength('aaaaaaaaaaaaaaaaaaaaaaaa').score).toBeLessThan(3);
  });

  it('rates a short password weak', () => {
    expect(passwordStrength('abc').score).toBeLessThanOrEqual(1);
  });
});

// ── Relative time ───────────────────────────────────────────────────────────

describe('relativeTime', () => {
  it('describes a missing timestamp rather than rendering NaN', () => {
    expect(relativeTime(undefined)).toBe('never connected');
    expect(relativeTime('')).toBe('never connected');
    expect(relativeTime('not-a-date')).toBe('never connected');
  });

  it('formats recent times', () => {
    expect(relativeTime(new Date(Date.now() - 5_000).toISOString())).toBe('just now');
    expect(relativeTime(new Date(Date.now() - 5 * 60_000).toISOString())).toBe('5 minutes ago');
    expect(relativeTime(new Date(Date.now() - 60 * 60_000).toISOString())).toBe('1 hour ago');
    expect(relativeTime(new Date(Date.now() - 26 * 3600_000).toISOString())).toBe('yesterday');
  });

  it('treats a future timestamp as now instead of "in -3 minutes"', () => {
    // Servers and clients keep their own clocks; a remote stamped slightly
    // ahead of us is normal and must not render as a negative duration.
    expect(relativeTime(new Date(Date.now() + 120_000).toISOString())).toBe('just now');
  });

  it('singularises one unit', () => {
    expect(relativeTime(new Date(Date.now() - 61_000).toISOString())).toBe('1 minute ago');
  });
});
