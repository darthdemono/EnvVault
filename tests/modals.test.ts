/**
 * Add/Edit form tests. These drive the real `index.html`, so a missing or
 * renamed element id fails here rather than silently at runtime — the exact
 * failure mode recorded in CLAUDE.md when a formatter dropped
 * `#new-category-form`.
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  TYPE_CONFIG,
  buildCatChips,
  dynamicSecretFields,
  formToEntry,
  saveModal,
  refreshTotpStatus,
  wireTotpField,
  fillForm,
  populateProjectSelect,
  openModal,
  closeModal,
  openAdd,
  pushUndo,
  showDropdown,
  showContextMenu,
  CustomSelect,
  injectIntoForm,
} from '../src/ts/modals';
import { st } from '../src/ts/state';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const setVal = (id: string, v: string) => {
  ($(id) as HTMLInputElement).value = v;
};

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  st.formCustomSelects = new Map();
});

describe('form element contract with index.html', () => {
  // Every id `formToEntry`/`fillForm` reach for must actually exist in the
  // shipped markup — this is the check that catches silent id drift.
  const REQUIRED_IDS = [
    'f-provider',
    'f-purpose',
    'f-pool',
    'f-ratelimit-period',
    'f-ratelimit-note',
    'f-account',
    'f-username',
    'f-email',
    'f-key',
    'f-secret',
    'f-keyid',
    'f-price',
    'f-env',
    'f-project',
    'f-apiurl',
    'f-cburl',
    'f-version',
    'f-ratelimit',
    'f-expires',
    'f-scopes',
    'f-apidesc',
    'f-desc',
    'f-details',
    'f-icon',
    'f-icon-preview',
    'f-secret-type',
    'f-categories',
    'f-cert',
    'f-cert-key',
    'f-cert-issuer',
    'f-blob',
    'f-tags-input',
    'f-env-prefixes',
    'f-extra-vars-list',
    'f-envvar-subtype',
    'f-totp',
    'f-totp-reveal',
    'f-totp-status',
    'f-totp-params',
    'f-totp-algorithm',
    'f-totp-digits',
    'f-totp-period',
    'modal-overlay',
    'modal-title',
    'modal-duplicate',
    'edit-index',
    'undo-bar',
    'undo-msg',
    'dropdown',
    'toast',
  ];

  it.each(REQUIRED_IDS)('#%s exists', (id) => {
    expect(document.getElementById(id), `#${id} missing from index.html`).not.toBeNull();
  });

  it('renders #f-project as a div, not a native multi-select', () => {
    // A <select multiple size> draws a ghost native listbox in WebKitGTK even
    // when its parent is display:none — hence the custom div picker.
    expect($('f-project').tagName).toBe('DIV');
  });

  it('ships no static file inputs, which WebKitGTK renders regardless of CSS', () => {
    expect(document.querySelectorAll('input[type="file"]')).toHaveLength(0);
  });
});

describe('TYPE_CONFIG', () => {
  it('covers every secret type', () => {
    // Sorted, to match `Object.keys(...).sort()` on the left. The sixteen
    // Phase 24.5 types (`age_key` … `wifi`) are shape only — no `<option>` in
    // the type picker yet; see CLAUDE.md: "land the shape now, behavior later".
    expect(Object.keys(TYPE_CONFIG).sort()).toEqual([
      'age_key',
      'api_key',
      // Phase 24.1. A bundle's payload is entirely its members and local
      // variables; api_key is unused.
      'bundle',
      'certificate',
      // Phase 24.1. A composite's value is its rendered template; api_key is
      // unused.
      'composite',
      'connection_string',
      // Phase 23, step 5. A browser session is a credential the vault had no
      // home for: the jar went in a free-text field and the User-Agent it was
      // minted against went nowhere.
      'cookie',
      'crypto_wallet',
      'database',
      'env_var',
      'file_blob',
      'gpg_key',
      'identity_document',
      'license_key',
      'local_service',
      'oauth_client',
      'passkey',
      'password',
      'recovery_codes',
      'registry_token',
      'secure_note',
      'signing_key',
      'ssh_key',
      'tracker',
      'usenet_server',
      'wifi',
    ]);
  });

  it('labels certificate and file_blob by what they hold, not "API Key"', () => {
    expect(TYPE_CONFIG.certificate.keyLabel).not.toBe('API Key');
    expect(TYPE_CONFIG.file_blob.keyLabel).toBe('File Reference');
  });

  it('offers an account field only where a provider can have several', () => {
    expect(TYPE_CONFIG.api_key.showAccount).toBe(true);
    expect(TYPE_CONFIG.ssh_key.showAccount).toBe(true);
    expect(TYPE_CONFIG.password.showAccount).toBe(false);
  });
});

describe('dynamicSecretFields', () => {
  const typeIs = (t: string) => {
    ($('f-secret-type') as HTMLSelectElement).value = t;
    dynamicSecretFields();
  };

  it('shows the API secret field only for api_key', () => {
    typeIs('api_key');
    expect($('f-secret-group').style.display).toBe('flex');
    typeIs('password');
    expect($('f-secret-group').style.display).toBe('none');
  });

  it('swaps the key field for the certificate fields', () => {
    typeIs('certificate');
    expect($('f-key-group').style.display).toBe('none');
    expect($('f-cert-group').style.display).toBe('flex');
    expect($('f-cert-key-group').style.display).toBe('flex');
  });

  it('shows the blob field only for file_blob', () => {
    typeIs('file_blob');
    expect($('f-blob-group').style.display).toBe('flex');
    expect($('f-key-group').style.display).toBe('none');
  });

  it('shows the username row for password and ssh_key only', () => {
    typeIs('password');
    expect($('f-username-row').style.display).toBe('grid');
    typeIs('api_key');
    expect($('f-username-row').style.display).toBe('none');
  });

  it('shows the env_var subtype picker only for env_var', () => {
    typeIs('env_var');
    expect($('f-envvar-subtype-group').style.display).toBe('flex');
    typeIs('api_key');
    expect($('f-envvar-subtype-group').style.display).toBe('none');
  });

  it('relabels the provider and key fields per type', () => {
    typeIs('env_var');
    expect($('f-provider-label').textContent).toContain('Variable Name');
    expect($('f-key-label').textContent).toContain('Value');
  });

  it('falls back to the api_key config for an unknown type', () => {
    ($('f-secret-type') as HTMLSelectElement).innerHTML += '<option value="bogus">bogus</option>';
    expect(() => typeIs('bogus')).not.toThrow();
    expect($('f-provider-label').textContent).toContain('Provider');
  });

  describe('the required marker on the value field (A5, 2026-09-14)', () => {
    // The bug: the `*` was written once from `cfg.keyLabel` and never
    // re-evaluated, so an `env_var` entry whose real payload lives in a named
    // variable still showed "required" on a value the form does not require —
    // `primaryIsOptional` already said so; the label just never asked it.
    it('shows required for an ordinary api_key', () => {
      typeIs('api_key');
      expect($('f-key-label').innerHTML).toContain('req');
      expect(($('f-key') as HTMLInputElement).getAttribute('aria-required')).toBe('true');
    });

    it('drops to optional once an env_var entry has a named variable', () => {
      typeIs('env_var');
      expect($('f-key-label').innerHTML).toContain('req');
      const list = document.getElementById('f-extra-vars-list')!;
      list.innerHTML = '<div class="extra-var-row"><input class="extra-var-key" value="ID"></div>';
      // The delegated `input` listener on the list is glue bound once by
      // `openAdd()`; re-evaluating the marker after a DOM change is what
      // `dynamicSecretFields` itself does, which is the predicate this test
      // is really about.
      dynamicSecretFields();
      expect($('f-key-label').innerHTML).toContain('opt');
      expect(($('f-key') as HTMLInputElement).hasAttribute('aria-required')).toBe(false);
    });

    it('goes back to required when the last named variable is removed', () => {
      typeIs('env_var');
      const list = document.getElementById('f-extra-vars-list')!;
      list.innerHTML = '<div class="extra-var-row"><input class="extra-var-key" value="ID"></div>';
      dynamicSecretFields();
      expect($('f-key-label').innerHTML).toContain('opt');
      list.innerHTML = '';
      dynamicSecretFields();
      expect($('f-key-label').innerHTML).toContain('req');
    });
  });
});

describe('buildCatChips', () => {
  it('renders a chip per category and pre-selects the given ones', () => {
    st.vault.user_categories = ['infra', 'billing', 'ai'];
    buildCatChips(['billing']);
    const chips = [...document.querySelectorAll('#f-categories .cat-chip')];
    expect(chips.map((c) => c.textContent)).toEqual(['infra', 'billing', 'ai']);
    expect(chips.filter((c) => c.classList.contains('selected')).map((c) => c.textContent)).toEqual(
      ['billing'],
    );
  });

  it('toggles selection on click', () => {
    st.vault.user_categories = ['infra'];
    buildCatChips([]);
    const chip = document.querySelector<HTMLElement>('#f-categories .cat-chip')!;
    chip.click();
    expect(chip.classList.contains('selected')).toBe(true);
    chip.click();
    expect(chip.classList.contains('selected')).toBe(false);
  });

  it('renders category names as text, so a crafted name cannot inject markup', () => {
    st.vault.user_categories = ['<img src=x onerror=alert(1)>'];
    buildCatChips([]);
    expect(document.querySelector('#f-categories img')).toBeNull();
    expect(document.querySelector('#f-categories .cat-chip')!.textContent).toBe(
      '<img src=x onerror=alert(1)>',
    );
  });

  it('shows a hint instead of chips when no categories exist', () => {
    st.vault.user_categories = [];
    buildCatChips([]);
    expect(document.querySelectorAll('#f-categories .cat-chip')).toHaveLength(0);
    expect($('f-categories').textContent).toMatch(/no categories/i);
  });

  it('clears chips from a previous open rather than appending', () => {
    st.vault.user_categories = ['a', 'b'];
    buildCatChips([]);
    buildCatChips([]);
    expect(document.querySelectorAll('#f-categories .cat-chip')).toHaveLength(2);
  });
});

describe('populateProjectSelect', () => {
  beforeEach(() => {
    st.vault = makeVault({
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'p1', name: 'Acme' }),
        makeProject({ id: 'p2', name: 'Beta' }),
      ],
    });
  });

  it('lists every project except the Universal catch-all', () => {
    populateProjectSelect();
    const items = [...document.querySelectorAll<HTMLElement>('#f-project .project-pick-item')];
    expect(items.map((i) => i.dataset.value)).toEqual(['p1', 'p2']);
  });

  it('toggles an item on click', () => {
    populateProjectSelect();
    const item = document.querySelector<HTMLElement>('#f-project .project-pick-item')!;
    item.click();
    expect(item.classList.contains('selected')).toBe(true);
  });

  it('escapes project names', () => {
    st.vault.projects.push(makeProject({ id: 'x', name: '<b>bold</b>' }));
    populateProjectSelect();
    expect(document.querySelector('#f-project b')).toBeNull();
  });
});

describe('formToEntry', () => {
  beforeEach(populateProjectSelect);

  it('reads the basic fields and trims them', () => {
    setVal('f-provider', '  GitHub  ');
    setVal('f-key', ' sk-123 ');
    const entry = formToEntry();
    expect(entry.provider).toBe('GitHub');
    expect(entry.api_key).toBe('sk-123');
  });

  it('reads purpose and pool', () => {
    setVal('f-provider', 'GitHub');
    setVal('f-purpose', 'CI builds for the EnvVault repo');
    setVal('f-pool', 'github-ci');
    const entry = formToEntry();
    expect(entry.purpose).toBe('CI builds for the EnvVault repo');
    expect(entry.pool).toBe('github-ci');
  });

  it('reads the rate limit as a count and a period, and regenerates the legacy string', () => {
    // The legacy `rate_limit` string is still written so a vault edited here
    // stays readable to an older build that only knows that field.
    setVal('f-provider', 'GitHub');
    setVal('f-ratelimit', '5000');
    setVal('f-ratelimit-period', 'hour');
    const entry = formToEntry();
    expect(entry.rate_limit_count).toBe(5000);
    expect(entry.rate_limit_period).toBe('hour');
    expect(entry.rate_limit).toBe('5000/hour');
  });

  it('drops a count with no period rather than storing half a limit', () => {
    setVal('f-provider', 'GitHub');
    setVal('f-ratelimit', '5000');
    setVal('f-ratelimit-period', '');
    const entry = formToEntry();
    expect(entry.rate_limit_count).toBeUndefined();
    expect(entry.rate_limit_period).toBeUndefined();
    expect(entry.rate_limit).toBeUndefined();
  });

  it('round-trips a legacy free-text limit through the form', () => {
    // The migration path: an entry written before the field became a number is
    // filled into the two inputs, and saving it back keeps the same meaning.
    fillForm({ provider: 'GitHub', rate_limit: '100 req/min' } as any);
    expect(($('f-ratelimit') as HTMLInputElement).value).toBe('100');
    expect(($('f-ratelimit-period') as HTMLSelectElement).value).toBe('minute');
    const entry = formToEntry();
    expect(entry.rate_limit_count).toBe(100);
    expect(entry.rate_limit_period).toBe('minute');
  });

  it('carries unparseable rate-limit text through an edit instead of losing it', () => {
    // Regression: the field became a number, so text like "varies by endpoint"
    // had nowhere to go. Opening such an entry and pressing Save wiped the only
    // description of its limit that existed.
    fillForm({ provider: 'GitHub', rate_limit: 'varies by endpoint' } as any);
    expect(($('f-ratelimit') as HTMLInputElement).value).toBe('');
    const hint = $('f-ratelimit-note');
    expect(hint.hidden, 'the text must stay visible somewhere').toBe(false);
    expect(hint.textContent).toContain('varies by endpoint');
    const entry = formToEntry();
    expect(entry.rate_limit_note).toBe('varies by endpoint');
    expect(entry.rate_limit).toBe('varies by endpoint');
  });

  it("does not carry one entry's rate-limit note onto the next entry edited", () => {
    // The invariant-3 shape: module state pointing at the entry in the form.
    // `fillForm` is the single hook that clears it, and every path into the form
    // goes through it — including `fillForm({})` for a brand-new entry.
    fillForm({ provider: 'A', rate_limit: 'varies by endpoint' } as any);
    fillForm({ provider: 'B', rate_limit: '10/minute' } as any);
    expect(formToEntry().rate_limit_note).toBeUndefined();

    fillForm({ provider: 'A', rate_limit: 'varies by endpoint' } as any);
    fillForm({});
    expect(formToEntry().rate_limit_note).toBeUndefined();
    expect($('f-ratelimit-note').hidden).toBe(true);
  });

  it('always includes Universal in projectIds, even when specific projects are picked', () => {
    // Dropping Universal orphans the entry from the default view.
    st.vault = makeVault({
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'p1', name: 'Acme' }),
      ],
    });
    populateProjectSelect();
    document
      .querySelector<HTMLElement>('#f-project .project-pick-item[data-value="p1"]')!
      .classList.add('selected');
    expect(formToEntry().projectIds).toEqual(['Universal', 'p1']);
  });

  it('defaults to Universal alone when nothing is picked', () => {
    expect(formToEntry().projectIds).toEqual(['Universal']);
  });

  it('splits scopes on commas and drops blanks', () => {
    setVal('f-scopes', 'read, write ,, admin');
    expect(formToEntry().scopes).toEqual(['read', 'write', 'admin']);
  });

  it('splits tags on whitespace, and omits the field entirely when blank', () => {
    setVal('f-tags-input', 'prod  db');
    expect(formToEntry().tags).toEqual(['prod', 'db']);
    setVal('f-tags-input', '   ');
    expect(formToEntry().tags).toBeUndefined();
  });

  it('normalises env prefixes by stripping trailing underscores', () => {
    setVal('f-env-prefixes', 'VITE_, NEXT_PUBLIC__ ,');
    expect(formToEntry().env_prefixes).toEqual(['VITE', 'NEXT_PUBLIC']);
  });

  it('collects the selected category chips', () => {
    st.vault.user_categories = ['infra', 'billing'];
    buildCatChips(['infra']);
    expect(formToEntry().categories).toEqual(['infra']);
  });

  it('carries certificate fields only for the certificate type', () => {
    ($('f-secret-type') as HTMLSelectElement).value = 'certificate';
    setVal('f-cert', 'PEMDATA');
    setVal('f-cert-key', 'KEYDATA');
    const cert = formToEntry();
    expect(cert.certificate_data).toBe('PEMDATA');
    expect(cert.cert_key_data).toBe('KEYDATA');

    ($('f-secret-type') as HTMLSelectElement).value = 'api_key';
    const key = formToEntry();
    expect(key.certificate_data).toBeUndefined();
    expect(key.cert_key_data).toBeUndefined();
  });

  it('defaults price_type to free', () => {
    expect(formToEntry().price_type).toBe('free');
  });

  it('parses rotation_days as a number and drops non-numeric input', () => {
    setVal('f-rotation-days', '90');
    expect(formToEntry().rotation_days).toBe(90);
    setVal('f-rotation-days', 'abc');
    expect(formToEntry().rotation_days).toBeUndefined();
  });

  it('collects extra vars and skips rows with no key', () => {
    $('f-extra-vars-list').innerHTML = `
      <div class="extra-var-row">
        <input class="extra-var-key" value="A"><input class="extra-var-value" value="1">
        <input type="checkbox" class="extra-var-secret" checked>
      </div>
      <div class="extra-var-row">
        <input class="extra-var-key" value=""><input class="extra-var-value" value="orphan">
        <input type="checkbox" class="extra-var-secret">
      </div>`;
    expect(formToEntry().extra_vars).toEqual([{ key: 'A', value: '1', secret: true }]);
  });
});

describe('fillForm → formToEntry round trip', () => {
  beforeEach(populateProjectSelect);

  it('preserves an api_key entry through a full cycle', () => {
    st.vault.user_categories = ['infra'];
    const original = makeEntry({
      provider: 'GitHub',
      api_key: 'sk-123',
      api_secret: 'shh',
      key_id: 'kid-1',
      price_type: 'paid',
      environment: 'production',
      api_url: 'https://api.github.com',
      version: 'v3',
      rate_limit: '100/min',
      scopes: ['read', 'write'],
      api_description: 'CI token',
      description: 'notes',
      categories: ['infra'],
      tags: ['prod'],
      secretType: 'api_key',
      env_prefixes: ['VITE'],
    });
    buildCatChips(original.categories);
    fillForm(original);
    const out = formToEntry();

    expect(out.provider).toBe('GitHub');
    expect(out.api_key).toBe('sk-123');
    expect(out.api_secret).toBe('shh');
    expect(out.price_type).toBe('paid');
    expect(out.environment).toBe('production');
    expect(out.scopes).toEqual(['read', 'write']);
    expect(out.categories).toEqual(['infra']);
    expect(out.tags).toEqual(['prod']);
    expect(out.env_prefixes).toEqual(['VITE']);
    expect(out.secretType).toBe('api_key');
  });

  it('preserves a certificate entry, including its private key', () => {
    const original = makeEntry({
      provider: 'example.com',
      api_key: '',
      secretType: 'certificate',
      certificate_data: '-----BEGIN CERTIFICATE-----',
      cert_key_data: '-----BEGIN PRIVATE KEY-----',
      cert_issuer: 'Lets Encrypt',
    });
    fillForm(original);
    const out = formToEntry();
    expect(out.secretType).toBe('certificate');
    expect(out.certificate_data).toBe('-----BEGIN CERTIFICATE-----');
    expect(out.cert_key_data).toBe('-----BEGIN PRIVATE KEY-----');
    expect(out.cert_issuer).toBe('Lets Encrypt');
  });

  it('preserves extra vars across a cycle', () => {
    fillForm(
      makeEntry({
        extra_vars: [
          { key: 'A', value: '1', secret: false },
          { key: 'B', value: '2', secret: true },
        ],
      }),
    );
    expect(formToEntry().extra_vars).toEqual([
      { key: 'A', value: '1', secret: false },
      { key: 'B', value: '2', secret: true },
    ]);
  });

  it('clears fields left over from the previously edited entry', () => {
    fillForm(makeEntry({ provider: 'First', api_key: 'k1', key_id: 'leftover' }));
    fillForm(makeEntry({ provider: 'Second', api_key: 'k2' }));
    const out = formToEntry();
    expect(out.provider).toBe('Second');
    expect(out.key_id).toBeUndefined();
  });

  it("selects exactly the entry's projects in the picker", () => {
    st.vault = makeVault({
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'p1', name: 'Acme' }),
        makeProject({ id: 'p2', name: 'Beta' }),
      ],
    });
    populateProjectSelect();
    fillForm(makeEntry({ projectIds: ['Universal', 'p2'] }));
    const selected = [
      ...document.querySelectorAll<HTMLElement>('#f-project .project-pick-item.selected'),
    ];
    expect(selected.map((e) => e.dataset.value)).toEqual(['p2']);
    expect(formToEntry().projectIds).toEqual(['Universal', 'p2']);
  });

  it('does not treat a value containing markup as HTML', () => {
    fillForm(makeEntry({ provider: '<img src=x onerror=alert(1)>' }));
    expect(document.querySelector('#modal-overlay img')).toBeNull();
    expect(formToEntry().provider).toBe('<img src=x onerror=alert(1)>');
  });
});

describe('openModal / closeModal', () => {
  it('opens with the given title and hides Duplicate when adding', () => {
    openModal('Add Secret', -1);
    expect($('modal-overlay').classList.contains('open')).toBe(true);
    expect($('modal-title').textContent).toBe('Add Secret');
    expect($('modal-duplicate').style.display).toBe('none');
    expect(($('edit-index') as HTMLInputElement).value).toBe('-1');
  });

  it('shows Duplicate when editing an existing entry', () => {
    openModal('Edit Secret', 3);
    expect($('modal-duplicate').style.display).toBe('block');
    expect(($('edit-index') as HTMLInputElement).value).toBe('3');
  });

  it('closes and discards the in-progress draft', () => {
    sessionStorage.setItem('envvault-form-draft', '{"provider":"half typed"}');
    closeModal();
    expect($('modal-overlay').classList.contains('open')).toBe(false);
    expect(sessionStorage.getItem('envvault-form-draft')).toBeNull();
  });
});

describe('openAdd draft restore', () => {
  it('restores a saved draft into the form', () => {
    sessionStorage.setItem(
      'envvault-form-draft',
      JSON.stringify({ provider: 'Draft Co', api_key: 'sk-draft' }),
    );
    openAdd();
    expect(($('f-provider') as HTMLInputElement).value).toBe('Draft Co');
    expect(($('f-key') as HTMLInputElement).value).toBe('sk-draft');
  });

  it('opens a blank form when the stored draft is corrupt', () => {
    sessionStorage.setItem('envvault-form-draft', '{not json');
    expect(() => openAdd()).not.toThrow();
    expect(($('f-provider') as HTMLInputElement).value).toBe('');
  });
});

describe('pushUndo', () => {
  afterEach(() => vi.useRealTimers());

  it('shows the undo bar with the message', () => {
    pushUndo('Deleted GitHub', () => {});
    expect($('undo-bar').classList.contains('visible')).toBe(true);
    expect($('undo-msg').textContent).toBe('Deleted GitHub');
  });

  it('expires each entry independently, keeping the bar up for the newer one', () => {
    // Regression: the timeout used to pop() the newest entry rather than
    // removing its own, so two deletes inside the window dropped the wrong undo.
    vi.useFakeTimers();
    const first = vi.fn(),
      second = vi.fn();
    pushUndo('first', first);
    vi.advanceTimersByTime(3000);
    pushUndo('second', second);

    vi.advanceTimersByTime(2000); // first expires, second has 3s left
    expect(st.undoStack).toHaveLength(1);
    expect(st.undoStack[0].fn).toBe(second);
    expect($('undo-bar').classList.contains('visible')).toBe(true);

    vi.advanceTimersByTime(3000); // second expires
    expect(st.undoStack).toHaveLength(0);
    expect($('undo-bar').classList.contains('visible')).toBe(false);
  });
});

describe('showDropdown', () => {
  afterEach(() => vi.useRealTimers());

  it('renders one item per entry and separators for ---', () => {
    showDropdown($('sort-btn') ?? document.body, [
      { label: 'Copy', fn: () => {} },
      '---',
      { label: 'Delete', fn: () => {} },
    ]);
    const dd = $('dropdown');
    expect(dd.querySelectorAll('.dropdown-item')).toHaveLength(2);
    expect(dd.querySelectorAll('.dropdown-sep')).toHaveLength(1);
    expect(dd.style.display).toBe('block');
  });

  it("runs the clicked item's callback and closes", () => {
    const fn = vi.fn();
    showDropdown(document.body, [{ label: 'Copy', fn }]);
    $('dropdown').querySelector<HTMLElement>('.dropdown-item')!.click();
    expect(fn).toHaveBeenCalledOnce();
    expect($('dropdown').style.display).toBe('none');
  });

  it('marks the active item', () => {
    showDropdown(document.body, [
      { label: 'A', fn: () => {}, active: true },
      { label: 'B', fn: () => {} },
    ]);
    const items = [...$('dropdown').querySelectorAll('.dropdown-item')];
    expect(items[0].classList.contains('active')).toBe(true);
    expect(items[1].classList.contains('active')).toBe(false);
  });

  it('does not fire a stale callback after being reopened with new items', () => {
    const stale = vi.fn(),
      fresh = vi.fn();
    showDropdown(document.body, [{ label: 'Old', fn: stale }]);
    showDropdown(document.body, [{ label: 'New', fn: fresh }]);
    $('dropdown').querySelector<HTMLElement>('.dropdown-item')!.click();
    expect(stale).not.toHaveBeenCalled();
    expect(fresh).toHaveBeenCalledOnce();
  });

  it('closes on an outside click', () => {
    vi.useFakeTimers();
    showDropdown(document.body, [{ label: 'A', fn: () => {} }]);
    vi.advanceTimersByTime(100); // the outside-click listener binds late
    const outside = document.getElementById('card-grid');
    expect(outside, '#card-grid missing from index.html').not.toBeNull();
    outside!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect($('dropdown').style.display).toBe('none');
  });

  it('is positioned off-screen by default so WebKitGTK cannot paint it at 0,0', () => {
    loadRealIndexHtml();
    // Only the JS-set inline coords should ever place it on screen.
    expect($('dropdown').style.display).not.toBe('block');
  });
});

describe('showContextMenu', () => {
  it('positions at the given point and wires callbacks', () => {
    const fn = vi.fn();
    showContextMenu(120, 240, [{ label: 'Edit', fn }]);
    const dd = $('dropdown');
    expect(dd.style.top).toBe('240px');
    expect(dd.style.left).toBe('120px');
    dd.querySelector<HTMLElement>('.dropdown-item')!.click();
    expect(fn).toHaveBeenCalledOnce();
  });
});

describe('CustomSelect', () => {
  it('hides the native select and mirrors its label', () => {
    const sel = $('f-price') as HTMLSelectElement;
    const cs = new CustomSelect(sel);
    expect(sel.style.display).toBe('none');
    expect(cs._btn.textContent).toBe(sel.options[sel.selectedIndex].text);
  });

  it('updates the select and fires change when an option is picked', () => {
    const sel = $('f-price') as HTMLSelectElement;
    const cs = new CustomSelect(sel);
    const onChange = vi.fn();
    sel.addEventListener('change', onChange);

    cs._btn.click();
    const items = [...$('dropdown').querySelectorAll<HTMLElement>('.dropdown-item')];
    const target = items.findIndex(
      (i) => i.textContent === sel.options[sel.options.length - 1].text,
    );
    items[target].click();

    expect(sel.selectedIndex).toBe(sel.options.length - 1);
    expect(onChange).toHaveBeenCalled();
  });

  it('setValue syncs both the select and the button label', () => {
    const sel = $('f-price') as HTMLSelectElement;
    const cs = new CustomSelect(sel);
    const last = sel.options[sel.options.length - 1];
    cs.setValue(last.value);
    expect(sel.value).toBe(last.value);
    expect(cs._btn.textContent).toBe(last.text);
  });

  it('ignores a value that is not an option', () => {
    const sel = $('f-price') as HTMLSelectElement;
    const cs = new CustomSelect(sel);
    const before = sel.value;
    cs.setValue('does-not-exist');
    expect(sel.value).toBe(before);
  });
});

describe('injectIntoForm', () => {
  // These two used to assert the bug rather than the behaviour, and passed
  // because of it: the first called `injectIntoForm` with the modal *closed* and
  // expected the write to land, which is exactly what made every "→ Inject"
  // button in the Tools panel silently discard the user's generated secret.
  // `#f-key` is static markup, so it is in the document either way. Behavioural
  // coverage lives in `tests/inject-into-form.test.ts`.
  it('writes the generated value into the key field when the form is open', () => {
    openModal('Add', -1);
    injectIntoForm('generated-secret');
    expect(($('f-key') as HTMLInputElement).value).toBe('generated-secret');
  });

  it('refuses, without throwing, when the form is not open', () => {
    injectIntoForm('generated-secret');
    expect(($('f-key') as HTMLInputElement).value).toBe('');
    expect($('toast').textContent).toMatch(/open the add\/edit form first/i);
  });

  it('warns instead of throwing when the form is not present at all', () => {
    document.body.innerHTML = '<div id="toast"></div>';
    expect(() => injectIntoForm('x')).not.toThrow();
    expect($('toast').textContent).toMatch(/open the add\/edit form first/i);
  });
});

describe('the two-factor seed field (Phase 22)', () => {
  const $ = <T extends HTMLElement = HTMLInputElement>(id: string) =>
    document.getElementById(id) as unknown as T;

  it('splits a pasted otpauth:// URI into the seed and its parameters', () => {
    // The field is labelled "seed" and people paste the whole URI into it,
    // which is the reasonable thing to do. Storing the URI whole would mean a
    // second field that also holds the secret and has to be masked everywhere.
    $('f-totp').value =
      'otpauth://totp/GitHub:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60';
    refreshTotpStatus();
    expect($('f-totp').value).toBe('JBSWY3DPEHPK3PXP');
    expect($<HTMLSelectElement>('f-totp-algorithm').value).toBe('SHA256');
    expect($('f-totp-digits').value).toBe('8');
    expect($('f-totp-period').value).toBe('60');
    // The parameter row is revealed, because these are not the defaults and a
    // user who cannot see them cannot tell whether the URI was read correctly.
    expect($('f-totp-params').hidden).toBe(false);
    expect($('f-totp-status').textContent).toContain('GitHub');
  });

  it('writes only the parameters that differ from the defaults', () => {
    // A totp_algorithm of "SHA1" on every entry cannot be told apart from a
    // defaulted one, and nothing downstream could then say whether the issuer
    // chose it or we did.
    $('f-provider').value = 'GitHub';
    $('f-key').value = 'k';
    $('f-totp').value = 'jbsw y3dp ehpk 3pxp';
    refreshTotpStatus();
    const entry = formToEntry();
    expect(entry.totp_secret).toBe('JBSWY3DPEHPK3PXP');
    expect(entry.totp_algorithm).toBeUndefined();
    expect(entry.totp_digits).toBeUndefined();
    expect(entry.totp_period).toBeUndefined();
  });

  it('keeps an unusable seed in the field instead of silently dropping it', () => {
    // Dropping it leaves the user looking at an empty box with no sign the form
    // rejected anything. saveModal is what refuses the save.
    $('f-totp').value = 'not base32 at all!';
    refreshTotpStatus();
    expect(formToEntry().totp_secret).toBe('not base32 at all!');
    expect($('f-totp-status').textContent).toContain('Not a usable seed');
    expect($('f-totp-status').classList.contains('err')).toBe(true);
  });

  it('an empty field writes no seed and no parameters', () => {
    $('f-totp').value = '';
    $('f-totp-digits').value = '8';
    const entry = formToEntry();
    expect(entry.totp_secret).toBeUndefined();
    expect(entry.totp_digits).toBeUndefined();
  });

  it('re-masks the field on every open', () => {
    // A reveal toggle left on shows the seed on every later visit to the form,
    // and the form is opened from a card the user may be showing somebody.
    $('f-totp').type = 'text';
    $('f-totp-reveal').setAttribute('aria-pressed', 'true');
    fillForm({ provider: 'X', api_key: 'k' } as never);
    expect($('f-totp').type).toBe('password');
    expect($('f-totp-reveal').getAttribute('aria-pressed')).toBe('false');
  });

  it('an entry carrying only a seed can be saved, because that is what an import makes', () => {
    // An import from Ente or Aegis produces an entry with a second factor and
    // no password: the password may never be stored here at all. Demanding a
    // primary value would make every imported entry unsaveable the first time
    // somebody opened it to correct its name.
    $('f-provider').value = 'Imported';
    $('f-key').value = '';
    $('f-totp').value = 'JBSWY3DPEHPK3PXP';
    ($('edit-index') as HTMLInputElement).value = '-1';
    const before = st.vault.api_keys.length;
    void saveModal();
    expect(st.vault.api_keys.length).toBe(before + 1);
    expect(st.vault.api_keys[before].totp_secret).toBe('JBSWY3DPEHPK3PXP');
  });

  it('an entry with neither a value nor a seed is still refused', () => {
    // The carve-out above is for seeds, not a general relaxation.
    $('f-provider').value = 'Empty';
    $('f-key').value = '';
    $('f-totp').value = '';
    ($('edit-index') as HTMLInputElement).value = '-1';
    const before = st.vault.api_keys.length;
    void saveModal();
    expect(st.vault.api_keys.length).toBe(before);
  });

  it('the reveal button is bound by assignment, so opening twice does not stack it', () => {
    // Invariant 9. Two stacked handlers flip the type twice per click, which
    // looks exactly like a button that does nothing.
    wireTotpField();
    wireTotpField();
    $('f-totp').type = 'password';
    $('f-totp-reveal').click();
    expect($('f-totp').type).toBe('text');
  });
});

describe('an entry of an unrecognised secretType (A11, 2026-09-14)', () => {
  // The mechanism: a <select> handed a value with no matching <option> reads
  // back as ''. `formToEntry` used to fall through to 'api_key' whenever the
  // select was empty, so opening an entry of a type this build predates and
  // pressing Save silently rewrote it — every type-specific behaviour (a web
  // session's mask-whole rule, a bundle's membership) would then just stop
  // applying, with nobody told. This ships one release ahead of 24.1's first
  // new type for exactly that reason.
  afterEach(() => {
    // `_unknownSecretType` is module state, not DOM state — loadRealIndexHtml
    // in the outer beforeEach does not reset it. Leaving it set would fail
    // every unrelated saveModal() in a later test with no visible connection
    // to this block. A normal fillForm() is what really resets it.
    fillForm({ provider: 'X', api_key: 'k', secretType: 'api_key' } as never);
  });

  it('shows the banner and disables Save', () => {
    fillForm({ provider: 'Future', api_key: 'k', secretType: 'from_the_future' } as never);
    expect($('f-unknown-type-banner').hidden).toBe(false);
    expect(($('modal-save') as HTMLButtonElement).disabled).toBe(true);
  });

  it('does not touch the banner or Save for a type this build knows', () => {
    fillForm({ provider: 'X', api_key: 'k', secretType: 'password' } as never);
    expect($('f-unknown-type-banner').hidden).toBe(true);
    expect(($('modal-save') as HTMLButtonElement).disabled).toBe(false);
  });

  it('survives open -> save unchanged: formToEntry never downgrades it to api_key', () => {
    const base = { id: 'e1', provider: 'Future', api_key: 'k', secretType: 'from_the_future' };
    fillForm(base as never);
    // Even if something reaches formToEntry directly (saveModal's own guard is
    // the primary defence, asserted below), the fallback must not rewrite it.
    expect(formToEntry(base as never).secretType).toBe('from_the_future');
  });

  it('saveModal refuses outright, leaving the vault unchanged', async () => {
    st.vault.api_keys = [
      { id: 'e1', provider: 'Future', api_key: 'k', secretType: 'from_the_future' } as never,
    ];
    ($('edit-index') as HTMLInputElement).value = '0';
    fillForm(st.vault.api_keys[0]);
    setVal('f-provider', 'Future renamed');
    await saveModal();
    expect(st.vault.api_keys[0].provider).toBe('Future');
    expect(st.vault.api_keys[0].secretType as string).toBe('from_the_future');
  });
});
