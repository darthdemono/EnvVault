/**
 * Read a rendered config back into a project's chunks (Phase 35 and 34
 * leftovers): "restore this snapshot", and "take what the node actually has".
 *
 * The parsers are the app's own import parsers (`chunks/parsers.ts`), so a
 * restored config is read exactly the way an imported one is. There is
 * deliberately no Rust twin: the `.env` case has one (`env_import_plan`), and a
 * second implementation of six config formats would be six chances for the app
 * and the CLI to disagree about what a file meant. The capability map records it
 * as a UI-only half with that reason.
 *
 * What it replaces is the *family* of chunk types the format produces, not the
 * whole project: restoring `wg0.conf` replaces the interface and peers and leaves
 * a note or an unrelated chunk alone. Values arrive as literal text (the file had
 * no references in it), so the caller says so before applying.
 */
import type { Project, SecretChunk } from './types';
import {
  parseApacheConf,
  parseDockerCompose,
  parseHaproxyConf,
  parseNginxConf,
  parseSshConfig,
  parseWgConf,
} from './chunks/parsers';

interface Reader {
  parse: (text: string) => SecretChunk[];
  /** Every chunk type the format owns, so a type absent from the file is removed too. */
  family: string[];
}

const READERS: Record<string, Reader> = {
  wireguard: { parse: parseWgConf, family: ['wg_interface', 'wg_peer'] },
  nginx: {
    parse: parseNginxConf,
    family: ['nginx_server', 'nginx_upstream', 'nginx_location'],
  },
  apache: { parse: parseApacheConf, family: ['apache_vhost', 'apache_directory'] },
  haproxy: {
    parse: parseHaproxyConf,
    family: ['haproxy_global', 'haproxy_frontend', 'haproxy_backend'],
  },
  compose: {
    parse: parseDockerCompose,
    family: ['docker_service', 'docker_network', 'docker_volume'],
  },
  ssh: { parse: parseSshConfig, family: ['ssh_host'] },
};

/** True for an exporter id this module can read back (`.env` has its own path). */
export function canRestore(exporter: string): boolean {
  return exporter in READERS;
}

export interface RestorePlan {
  exporter: string;
  /** What the file contains, as new chunks. */
  parsed: SecretChunk[];
  /** The project's existing chunks of this format, which would be replaced. */
  replaced: SecretChunk[];
  /** Everything else in the project, untouched. */
  kept: SecretChunk[];
}

/** What reading `text` back would do to `project`; `null` for a format with no reader. */
export function planRestore(project: Project, exporter: string, text: string): RestorePlan | null {
  const reader = READERS[exporter];
  if (!reader) return null;
  const parsed = reader.parse(text);
  const family = new Set([...reader.family, ...parsed.map((c) => c.chunk_type)]);
  const chunks = project.chunks ?? [];
  return {
    exporter,
    parsed,
    replaced: chunks.filter((c) => family.has(c.chunk_type)),
    kept: chunks.filter((c) => !family.has(c.chunk_type)),
  };
}

/** Counts by chunk type, for a confirmation that says what is about to change. */
export function describePlan(plan: RestorePlan): string {
  const count = (cs: SecretChunk[]) => {
    const m = new Map<string, number>();
    for (const c of cs) m.set(c.chunk_type, (m.get(c.chunk_type) ?? 0) + 1);
    return [...m].map(([t, n]) => `${n} ${t.replace(/_/g, ' ')}`).join(', ') || 'nothing';
  };
  return `Replace ${count(plan.replaced)} with ${count(plan.parsed)}.`;
}

/** Applies a plan: the parsed chunks take the place of the replaced ones. */
export function applyRestore(project: Project, plan: RestorePlan): void {
  project.chunks = [...plan.kept, ...plan.parsed];
}
