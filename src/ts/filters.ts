import type { VaultEntry, Project } from './types';
import { st } from './state';

export function getDescendantProjectIds(projectId: string): string[] {
  let projectName: string;
  if (projectId.startsWith('virtual:')) {
    projectName = projectId.slice(8);
  } else {
    const project = st.vault.projects.find((p) => p.id === projectId);
    if (!project) return [projectId];
    projectName = project.name;
  }
  const prefix = projectName + '/';
  return st.vault.projects
    .filter((p) => p.name === projectName || p.name.startsWith(prefix))
    .map((p) => p.id);
}

export function buildProjectTree(projects: Project[]): any[] {
  const byName = new Map<string, any>();
  for (const p of projects) byName.set(p.name, { ...p, children: [], virtual: false });
  for (const p of projects) {
    const parts = p.name.split('/');
    for (let i = 1; i < parts.length; i++) {
      const anc = parts.slice(0, i).join('/');
      if (!byName.has(anc))
        byName.set(anc, {
          id: 'virtual:' + anc,
          name: anc,
          description: '',
          children: [],
          virtual: true,
        });
    }
  }
  const tree: any[] = [];
  for (const [name, node] of byName) {
    const parts = name.split('/');
    if (parts.length === 1) tree.push(node);
    else byName.get(parts.slice(0, -1).join('/'))!.children.push(node);
  }
  for (const [, node] of byName)
    node.children.sort((a: any, b: any) => a.name.localeCompare(b.name));
  tree.sort((a, b) => a.name.localeCompare(b.name));
  return tree;
}

/**
 * Search prefixes that mean "filter by this field". Everything else containing a
 * colon is ordinary text.
 *
 * Without the whitelist, any token with a colon became a filter: searching
 * `postgres://user` produced the filter `postgres="//user"`, which no branch in
 * `getFiltered` reads, and left the text query empty — so looking for a
 * connection string silently returned the *entire vault* instead of the one
 * entry, and looked like everything matched.
 */
const SEARCH_FILTER_KEYS = ['price', 'cat', 'env'];

export function parseSearch(q: string): { filters: Record<string, string>; text: string } {
  const filters: Record<string, string> = {};
  const words: string[] = [];
  q.split(/\s+/).forEach((t) => {
    const colon = t.indexOf(':');
    const k = colon > 0 ? t.slice(0, colon).toLowerCase() : '';
    const v = colon > 0 ? t.slice(colon + 1) : '';
    if (v && SEARCH_FILTER_KEYS.includes(k)) filters[k] = v.toLowerCase();
    else if (t) words.push(t.toLowerCase());
  });
  return { filters, text: words.join(' ') };
}

export function getFiltered(): VaultEntry[] {
  const { filters, text } = parseSearch(st.searchQ);
  // Fall back to the catch-all: an empty selection array would otherwise pass
  // undefined into getDescendantProjectIds and throw.
  const selectedProject = st.currentSelectedProjectIds[0] ?? 'Universal';
  const projectFilterIds =
    selectedProject === 'Universal' ? null : getDescendantProjectIds(selectedProject);
  return st.vault.api_keys.filter((k) => {
    if (projectFilterIds && !projectFilterIds.some((pid) => (k.projectIds || []).includes(pid)))
      return false;
    if (filters.price && k.price_type !== filters.price) return false;
    if (filters.cat && !(k.categories || []).some((c) => c.includes(filters.cat))) return false;
    if (filters.env && k.environment !== filters.env) return false;
    // Sidebar environment filter (separate from st.filter so it stacks with other filters)
    if (st.currentEnvFilter && k.environment !== st.currentEnvFilter) return false;
    // Tag sidebar filter
    if (st.activeTagFilter && !(k.tags ?? []).includes(st.activeTagFilter)) return false;
    // Env-prefix sidebar filter
    if (st.activePrefixFilter && !(k.env_prefixes ?? []).includes(st.activePrefixFilter))
      return false;
    if (text) {
      const hay = [
        k.provider,
        k.account_name,
        k.key_id,
        k.api_description,
        k.description,
        k.details,
        ...(k.categories || []),
        ...((k as any).tags || []),
      ]
        .join(' ')
        .toLowerCase();
      // Regex search (item 10): /pattern/flags syntax detected
      const reMatch = /^\/(.+)\/([gimsuy]*)$/.exec(text);
      if (reMatch) {
        try {
          const re = new RegExp(reMatch[1], reMatch[2] || 'i');
          if (!re.test(hay)) return false;
          // Malformed regex: fall back to a literal substring search on the
          // pattern itself. Matching against `text` instead would include the
          // wrapping slashes, which are never in the haystack, so the fallback
          // could never match anything.
        } catch {
          if (!hay.includes(reMatch[1])) return false;
        }
      } else {
        if (!hay.includes(text)) return false;
      }
    }
    if (st.filter.type === 'price') return k.price_type === st.filter.value;
    if (st.filter.type === 'category') {
      const pfx = st.filter.value + '/';
      return (k.categories || []).some((c) => c === st.filter.value || c.startsWith(pfx));
    }
    if (st.filter.type === 'secret_type') return (k.secretType || 'api_key') === st.filter.value;
    return true;
  });
}

export function sorted(arr: VaultEntry[]): VaultEntry[] {
  const by = st.currentSortBy;
  const priceOrder: Record<string, number> = { free: 0, local: 1, conditional: 2, paid: 3 };
  return [...arr].sort((a, b) => {
    // Pinned entries always float to top
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    // `??`, not `||`: `free` maps to 0, which `||` treats as missing and
    // replaces with 9 — sorting the free tier last instead of first.
    if (by === 'price')
      return (
        (priceOrder[a.price_type] ?? 9) - (priceOrder[b.price_type] ?? 9) ||
        a.provider.localeCompare(b.provider)
      );
    if (by === 'category')
      return (
        (a.categories?.[0] || 'zzz').localeCompare(b.categories?.[0] || 'zzz') ||
        a.provider.localeCompare(b.provider)
      );
    if (by === 'expiry') {
      const ae = a.expires_at ? new Date(a.expires_at).getTime() : Infinity;
      const be = b.expires_at ? new Date(b.expires_at).getTime() : Infinity;
      return ae - be;
    }
    return a.provider.localeCompare(b.provider);
  });
}
