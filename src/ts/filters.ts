import type { VaultEntry, Project } from './types';
import { st } from './state';

export function getDescendantProjectIds(projectId: string): string[] {
  let projectName: string;
  if (projectId.startsWith('virtual:')) {
    projectName = projectId.slice(8);
  } else {
    const project = st.vault.projects.find(p => p.id === projectId);
    if (!project) return [projectId];
    projectName = project.name;
  }
  const prefix = projectName + '/';
  return st.vault.projects.filter(p => p.name === projectName || p.name.startsWith(prefix)).map(p => p.id);
}

export function buildProjectTree(projects: Project[]): any[] {
  const byName = new Map<string, any>();
  for (const p of projects) byName.set(p.name, { ...p, children: [], virtual: false });
  for (const p of projects) {
    const parts = p.name.split('/');
    for (let i = 1; i < parts.length; i++) {
      const anc = parts.slice(0, i).join('/');
      if (!byName.has(anc)) byName.set(anc, { id: 'virtual:' + anc, name: anc, description: '', children: [], virtual: true });
    }
  }
  const tree: any[] = [];
  for (const [name, node] of byName) {
    const parts = name.split('/');
    if (parts.length === 1) tree.push(node);
    else byName.get(parts.slice(0, -1).join('/'))!.children.push(node);
  }
  for (const [, node] of byName) node.children.sort((a: any, b: any) => a.name.localeCompare(b.name));
  tree.sort((a, b) => a.name.localeCompare(b.name));
  return tree;
}

export function parseSearch(q: string): { filters: Record<string, string>; text: string } {
  const filters: Record<string, string> = {};
  const words: string[] = [];
  q.split(/\s+/).forEach(t => {
    const [k, v] = t.split(':');
    if (v) filters[k.toLowerCase()] = v.toLowerCase();
    else if (t) words.push(t.toLowerCase());
  });
  return { filters, text: words.join(' ') };
}

export function getFiltered(): VaultEntry[] {
  const { filters, text } = parseSearch(st.searchQ);
  const selectedProject = st.currentSelectedProjectIds[0];
  const projectFilterIds = selectedProject === 'Universal' ? null : getDescendantProjectIds(selectedProject);
  return st.vault.api_keys.filter(k => {
    if (projectFilterIds && !projectFilterIds.some(pid => (k.projectIds || []).includes(pid))) return false;
    if (filters.price && k.price_type !== filters.price) return false;
    if (filters.cat && !(k.categories || []).some(c => c.includes(filters.cat))) return false;
    if (filters.env && k.environment !== filters.env) return false;
    if (text) {
      const hay = [k.provider, k.account_name, k.key_id, k.api_description, k.description, k.details, ...(k.categories || [])].join(' ').toLowerCase();
      if (!hay.includes(text)) return false;
    }
    if (st.filter.type === 'price') return k.price_type === st.filter.value;
    if (st.filter.type === 'category') {
      const pfx = st.filter.value + '/';
      return (k.categories || []).some(c => c === st.filter.value || c.startsWith(pfx));
    }
    if (st.filter.type === 'secret_type') return (k.secretType || 'api_key') === st.filter.value;
    return true;
  });
}

export function sorted(arr: VaultEntry[]): VaultEntry[] {
  const by = st.currentSortBy;
  const priceOrder: Record<string, number> = { free: 0, local: 1, conditional: 2, paid: 3 };
  return [...arr].sort((a, b) => {
    if (by === 'price') return (priceOrder[a.price_type] || 9) - (priceOrder[b.price_type] || 9) || a.provider.localeCompare(b.provider);
    if (by === 'category') return (a.categories?.[0] || 'zzz').localeCompare(b.categories?.[0] || 'zzz') || a.provider.localeCompare(b.provider);
    if (by === 'expiry') {
      const ae = a.expires_at ? new Date(a.expires_at).getTime() : Infinity;
      const be = b.expires_at ? new Date(b.expires_at).getTime() : Infinity;
      return ae - be;
    }
    return a.provider.localeCompare(b.provider);
  });
}
