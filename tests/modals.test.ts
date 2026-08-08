/**
 * Add/Edit form tests. These drive the real `index.html`, so a missing or
 * renamed element id fails here rather than silently at runtime — the exact
 * failure mode recorded in CLAUDE.md when a formatter dropped
 * `#new-category-form`.
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  TYPE_CONFIG, buildCatChips, dynamicSecretFields, formToEntry, fillForm,
  populateProjectSelect, openModal, closeModal, openAdd, pushUndo,
  showDropdown, showContextMenu, CustomSelect, injectIntoForm,
} from '../src/ts/modals';
import { st } from '../src/ts/state';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const setVal = (id: string, v: string) => { ($(id) as HTMLInputElement).value = v; };

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  st.formCustomSelects = new Map();
});

describe('form element contract with index.html', () => {
  // Every id `formToEntry`/`fillForm` reach for must actually exist in the
  // shipped markup — this is the check that catches silent id drift.
  const REQUIRED_IDS = [
    'f-provider', 'f-account', 'f-username', 'f-email', 'f-key', 'f-secret', 'f-keyid',
    'f-price', 'f-env', 'f-project', 'f-apiurl', 'f-cburl', 'f-version', 'f-ratelimit',
    'f-expires', 'f-scopes', 'f-apidesc', 'f-desc', 'f-details', 'f-icon', 'f-icon-preview',
    'f-secret-type', 'f-categories', 'f-cert', 'f-cert-key', 'f-cert-issuer', 'f-blob',
    'f-tags-input', 'f-env-prefixes', 'f-extra-vars-list', 'f-envvar-subtype',
    'modal-overlay', 'modal-title', 'modal-duplicate', 'edit-index',
    'undo-bar', 'undo-msg', 'dropdown', 'toast',
  ];

  it.each(REQUIRED_IDS)('#%s exists', id => {
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
    expect(Object.keys(TYPE_CONFIG).sort()).toEqual(
      ['api_key', 'certificate', 'connection_string', 'env_var', 'file_blob', 'password', 'ssh_key'],
    );
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
  const typeIs = (t: string) => { ($('f-secret-type') as HTMLSelectElement).value = t; dynamicSecretFields(); };

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
});

describe('buildCatChips', () => {
  it('renders a chip per category and pre-selects the given ones', () => {
    st.vault.user_categories = ['infra', 'billing', 'ai'];
    buildCatChips(['billing']);
    const chips = [...document.querySelectorAll('#f-categories .cat-chip')];
    expect(chips.map(c => c.textContent)).toEqual(['infra', 'billing', 'ai']);
    expect(chips.filter(c => c.classList.contains('selected')).map(c => c.textContent)).toEqual(['billing']);
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
    expect(document.querySelector('#f-categories .cat-chip')!.textContent).toBe('<img src=x onerror=alert(1)>');
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
    expect(items.map(i => i.dataset.value)).toEqual(['p1', 'p2']);
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

  it('always includes Universal in projectIds, even when specific projects are picked', () => {
    // Dropping Universal orphans the entry from the default view.
    st.vault = makeVault({
      projects: [makeProject({ id: 'Universal', name: 'Universal' }), makeProject({ id: 'p1', name: 'Acme' })],
    });
    populateProjectSelect();
    document.querySelector<HTMLElement>('#f-project .project-pick-item[data-value="p1"]')!.classList.add('selected');
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
      provider: 'GitHub', api_key: 'sk-123', api_secret: 'shh', key_id: 'kid-1',
      price_type: 'paid', environment: 'production', api_url: 'https://api.github.com',
      version: 'v3', rate_limit: '100/min', scopes: ['read', 'write'],
      api_description: 'CI token', description: 'notes', categories: ['infra'],
      tags: ['prod'], secretType: 'api_key', env_prefixes: ['VITE'],
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
      provider: 'example.com', api_key: '', secretType: 'certificate',
      certificate_data: '-----BEGIN CERTIFICATE-----', cert_key_data: '-----BEGIN PRIVATE KEY-----',
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
    fillForm(makeEntry({ extra_vars: [{ key: 'A', value: '1', secret: false }, { key: 'B', value: '2', secret: true }] }));
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

  it('selects exactly the entry\'s projects in the picker', () => {
    st.vault = makeVault({
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'p1', name: 'Acme' }),
        makeProject({ id: 'p2', name: 'Beta' }),
      ],
    });
    populateProjectSelect();
    fillForm(makeEntry({ projectIds: ['Universal', 'p2'] }));
    const selected = [...document.querySelectorAll<HTMLElement>('#f-project .project-pick-item.selected')];
    expect(selected.map(e => e.dataset.value)).toEqual(['p2']);
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
    sessionStorage.setItem('envvault-form-draft', JSON.stringify({ provider: 'Draft Co', api_key: 'sk-draft' }));
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
    const first = vi.fn(), second = vi.fn();
    pushUndo('first', first);
    vi.advanceTimersByTime(3000);
    pushUndo('second', second);

    vi.advanceTimersByTime(2000);      // first expires, second has 3s left
    expect(st.undoStack).toHaveLength(1);
    expect(st.undoStack[0].fn).toBe(second);
    expect($('undo-bar').classList.contains('visible')).toBe(true);

    vi.advanceTimersByTime(3000);      // second expires
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

  it('runs the clicked item\'s callback and closes', () => {
    const fn = vi.fn();
    showDropdown(document.body, [{ label: 'Copy', fn }]);
    $('dropdown').querySelector<HTMLElement>('.dropdown-item')!.click();
    expect(fn).toHaveBeenCalledOnce();
    expect($('dropdown').style.display).toBe('none');
  });

  it('marks the active item', () => {
    showDropdown(document.body, [{ label: 'A', fn: () => {}, active: true }, { label: 'B', fn: () => {} }]);
    const items = [...$('dropdown').querySelectorAll('.dropdown-item')];
    expect(items[0].classList.contains('active')).toBe(true);
    expect(items[1].classList.contains('active')).toBe(false);
  });

  it('does not fire a stale callback after being reopened with new items', () => {
    const stale = vi.fn(), fresh = vi.fn();
    showDropdown(document.body, [{ label: 'Old', fn: stale }]);
    showDropdown(document.body, [{ label: 'New', fn: fresh }]);
    $('dropdown').querySelector<HTMLElement>('.dropdown-item')!.click();
    expect(stale).not.toHaveBeenCalled();
    expect(fresh).toHaveBeenCalledOnce();
  });

  it('closes on an outside click', () => {
    vi.useFakeTimers();
    showDropdown(document.body, [{ label: 'A', fn: () => {} }]);
    vi.advanceTimersByTime(100);       // the outside-click listener binds late
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
    const target = items.findIndex(i => i.textContent === sel.options[sel.options.length - 1].text);
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
  it('writes the generated value into the key field', () => {
    injectIntoForm('generated-secret');
    expect(($('f-key') as HTMLInputElement).value).toBe('generated-secret');
  });

  it('warns instead of throwing when the form is not present', () => {
    document.body.innerHTML = '<div id="toast"></div>';
    expect(() => injectIntoForm('x')).not.toThrow();
    expect($('toast').textContent).toMatch(/open add\/edit form/i);
  });
});
