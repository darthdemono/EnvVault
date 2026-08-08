/**
 * @file Shared fixtures for the UI tests.
 *
 * `loadRealIndexHtml()` is deliberately not a hand-written stub of the markup:
 * a recurring class of bug in this project is JS referencing an element id that
 * a formatter silently dropped from `index.html` (see CLAUDE.md, Phase 3). A
 * fixture that mirrors the markup by hand would keep passing after that happens.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { VaultEntry, VaultData, Project } from '../src/ts/types';

const INDEX_HTML = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'index.html');

let cachedBody: string | null = null;

/** Replaces `document.body` with the real one from `index.html`. */
export function loadRealIndexHtml(): void {
  if (cachedBody === null) {
    const html = readFileSync(INDEX_HTML, 'utf8');
    const m = html.match(/<body[^>]*>([\s\S]*)<\/body>/i);
    if (!m) throw new Error('index.html has no <body> — fixture cannot load');
    // Strip <script> tags: the modules are imported directly by the tests, and
    // letting jsdom fetch/execute them would double-register event listeners.
    cachedBody = m[1].replace(/<script[\s\S]*?<\/script>/gi, '');
  }
  document.body.innerHTML = cachedBody!;
}

/** Minimal valid entry; override only the fields a test cares about. */
export function makeEntry(over: Partial<VaultEntry> = {}): VaultEntry {
  return {
    id: over.id ?? `id-${Math.random().toString(36).slice(2)}`,
    provider: 'Example',
    api_key: 'sk-secret-value',
    price_type: 'free',
    categories: [],
    scopes: [],
    projectIds: ['Universal'],
    ...over,
  } as VaultEntry;
}

export function makeProject(over: Partial<Project> = {}): Project {
  return { id: over.id ?? `p-${Math.random().toString(36).slice(2)}`, name: 'Proj', description: '', ...over } as Project;
}

export function makeVault(over: Partial<VaultData> = {}): VaultData {
  return {
    api_keys: [],
    user_categories: [],
    projects: [{ id: 'Universal', name: 'Universal', description: 'All keys belong here by default' }],
    ...over,
  } as VaultData;
}

/**
 * Resets the shared `st` singleton between tests.
 *
 * `st` is module state, so without this a filter left set by one test leaks
 * into the next and produces order-dependent passes.
 */
export function resetState(st: any, vault: VaultData = makeVault()): void {
  st.vault = vault;
  st.filter = { type: 'all', value: '' };
  st.searchQ = '';
  st.expanded = new Set<string>();
  st.allExpanded = false;
  st.revealed = {};
  st.currentSelectedProjectIds = ['Universal'];
  st.currentSortBy = 'provider';
  st.currentEnvFilter = '';
  st.activeTagFilter = null;
  st.activePrefixFilter = null;
  st.selectedUserId = null;
  st.activeRemoteId = null;
  st.undoStack = [];
  st.vaultOpen = true;
}
