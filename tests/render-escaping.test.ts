/**
 * Escaping of vault-controlled values in the card grid.
 *
 * `environment`, `secretType`, `price_type`, `expires_at`, `rotation_days` and
 * `project_type` are declared as unions, but TypeScript is erased at runtime and
 * a vault arrives as JSON from SQLCipher, a remote server someone else runs, or
 * an imported .json/.vaultbak. They are attacker-influenced like any other
 * field, and each one was being interpolated raw.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { renderGrid, render } from '../src/ts/render';
import { st, Settings } from '../src/ts/state';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

const grid = () => document.getElementById('card-grid')!;
const ATTR_BREAKOUT = '" onmouseover="steal()" x="';
const TAG_INJECTION = '<img src=x onerror=alert(1)>';

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  Settings.set('showExpiryWarning', true);
  Settings.set('groupByType', false);
});

/** Nothing rendered may have gained a scripting attribute or a live element. */
function assertNoInjection(root: HTMLElement = grid()) {
  expect(root.querySelector('img'), 'injected element became live').toBeNull();
  expect(root.querySelector('script')).toBeNull();
  expect(root.querySelector('[onmouseover]'), 'injected attribute became live').toBeNull();
  expect(root.querySelector('[onerror]')).toBeNull();
}

describe('environment', () => {
  it('does not break out of the data-env attribute', () => {
    st.vault.api_keys = [makeEntry({ environment: ATTR_BREAKOUT as any })];
    renderGrid();
    assertNoInjection();
    expect(grid().querySelector('.badge-env')!.getAttribute('data-env')).toBe(ATTR_BREAKOUT);
  });

  it('does not inject an element through the badge text', () => {
    st.vault.api_keys = [makeEntry({ environment: TAG_INJECTION as any })];
    renderGrid();
    assertNoInjection();
    expect(grid().querySelector('.badge-env')!.textContent).toBe(TAG_INJECTION);
  });

  it('still renders a normal environment', () => {
    st.vault.api_keys = [makeEntry({ environment: 'production' })];
    renderGrid();
    expect(grid().querySelector('.badge-env')!.getAttribute('data-env')).toBe('production');
    expect(grid().querySelector('.badge-env')!.textContent).toBe('production');
  });
});

describe('secretType', () => {
  it('does not inject an element through the type badge', () => {
    st.vault.api_keys = [makeEntry({ secretType: TAG_INJECTION as any })];
    renderGrid();
    assertNoInjection();
    expect(grid().textContent).toContain(TAG_INJECTION);
  });

  it('still renders a normal non-default type', () => {
    st.vault.api_keys = [makeEntry({ secretType: 'ssh_key' })];
    renderGrid();
    expect(grid().textContent).toContain('ssh_key');
  });
});

describe('price_type', () => {
  it('does not break out of the data-price attribute', () => {
    st.vault.api_keys = [makeEntry({ price_type: ATTR_BREAKOUT as any })];
    renderGrid();
    assertNoInjection();
    expect(grid().querySelector('.badge-price')!.getAttribute('data-price')).toBe(ATTR_BREAKOUT);
  });

  it('still renders a normal tier', () => {
    st.vault.api_keys = [makeEntry({ price_type: 'paid' })];
    renderGrid();
    expect(grid().querySelector('.badge-price')!.getAttribute('data-price')).toBe('paid');
  });
});

describe('expires_at', () => {
  it('does not break out of the expiry badge title', () => {
    // expires_at reaches `new Date(...)`, which yields NaN for junk — but the
    // raw string still landed in a title attribute before the date was used.
    const past = new Date(Date.now() - 86_400_000).toISOString();
    st.vault.api_keys = [makeEntry({ expires_at: `${past}" onmouseover="steal()` })];
    renderGrid();
    assertNoInjection();
  });

  it('still shows a real expiry date in the title', () => {
    const past = new Date(Date.now() - 5 * 86_400_000).toISOString();
    st.vault.api_keys = [makeEntry({ expires_at: past })];
    renderGrid();
    expect(grid().querySelector('.badge-expiry-expired')!.getAttribute('title')).toBe(past);
  });
});

describe('rotation_days', () => {
  it('does not break out of the rotation badge title', () => {
    st.vault.api_keys = [makeEntry({
      rotation_days: '1" onmouseover="steal()' as any,
      last_rotated_at: new Date(Date.now() - 400 * 86_400_000).toISOString(),
    })];
    renderGrid();
    assertNoInjection();
  });

  it('still flags a genuinely overdue rotation', () => {
    st.vault.api_keys = [makeEntry({
      rotation_days: 30,
      last_rotated_at: new Date(Date.now() - 400 * 86_400_000).toISOString(),
    })];
    renderGrid();
    expect(grid().querySelector('.badge-rotation-due')).not.toBeNull();
  });
});

describe('project_type badge in the sidebar', () => {
  it('does not inject through an unrecognised project type', () => {
    // Known types hit a lookup table; anything else printed the stored value.
    st.vault = makeVault({
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'p1', name: 'Evil', project_type: TAG_INJECTION as any }),
      ],
      api_keys: [makeEntry()],
    });
    render();
    const tree = document.getElementById('project-list')!;
    assertNoInjection(tree);
    expect(tree.textContent).toContain(TAG_INJECTION);
  });

  it('still shows the short label for a known type', () => {
    st.vault = makeVault({
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'p1', name: 'Net', project_type: 'wireguard' }),
      ],
      api_keys: [makeEntry()],
    });
    render();
    expect(document.getElementById('project-list')!.textContent).toContain('WG');
  });
});

describe('a fully hostile entry', () => {
  it('renders inert across every field at once', () => {
    st.vault = makeVault({
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'p1', name: TAG_INJECTION }),
      ],
      user_categories: [TAG_INJECTION],
      api_keys: [makeEntry({
        id: 'evil',
        provider: TAG_INJECTION,
        account_name: TAG_INJECTION,
        api_key: TAG_INJECTION,
        key_id: TAG_INJECTION,
        api_description: TAG_INJECTION,
        description: TAG_INJECTION,
        environment: ATTR_BREAKOUT as any,
        secretType: TAG_INJECTION as any,
        price_type: ATTR_BREAKOUT as any,
        categories: [TAG_INJECTION],
        tags: [TAG_INJECTION],
        env_prefixes: [TAG_INJECTION],
        api_url: 'javascript:alert(1)',
        projectIds: ['Universal', 'p1'],
      } as any)],
    });
    st.expanded = new Set(['evil']);
    render();
    assertNoInjection(document.body);
    expect(document.querySelector('a[href^="javascript:"]')).toBeNull();
  });
});
