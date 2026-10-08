/**
 * @file
 * The config-view panel for cross-chunk checks (Phase 29).
 * @description Asks Rust (`vault_core::config_check`, the same code `envv check`
 *              runs) and paints the answer. There is deliberately no rule here:
 *              a second implementation is a second opinion about what a project
 *              means, and these rules exist to remove exactly that.
 *
 * The panel is silent when the project is clean and when the app is running in
 * a plain browser (no IPC bridge); a "✓ all good" line on every config view is
 * noise, and a message that the check could not run would be shown to everyone
 * who develops in `npm run dev`.
 */
import { st } from './state';
import { html, setHtml } from './html';
import { invokeTauri, isTauri } from './tauri';
import type { Project } from './types';

export interface ConfigFinding {
  rule: string;
  severity: 'error' | 'warning';
  chunk_id: string;
  chunk: string;
  chunk_type: string;
  field: string;
  message: string;
  related: string[];
}

/** Entry names a `${…}` reference may point at: provider, and provider_keyid. */
export function vaultNames(): string[] {
  const out: string[] = [];
  for (const e of st.vault.api_keys) {
    if (!e.provider) continue;
    if (e.key_id) out.push(`${e.provider}_${e.key_id}`);
    out.push(e.provider);
  }
  return out;
}

/** `null` outside the desktop app or when the check could not run. */
export async function checkProject(project: Project): Promise<ConfigFinding[] | null> {
  if (!isTauri()) return null;
  try {
    return await invokeTauri<ConfigFinding[]>('config_check_project', {
      project,
      vaultNames: vaultNames(),
    });
  } catch {
    return null;
  }
}

/** Scroll to and flash a chunk card, found by id without building a selector from it. */
function focusChunk(id: string): void {
  for (const el of document.querySelectorAll<HTMLElement>('[data-chunk-id]')) {
    if (el.dataset.chunkId !== id) continue;
    const card = el.closest<HTMLElement>('.chunk-card, .docker-service-card') ?? el;
    card.scrollIntoView({ block: 'center' });
    card.classList.add('flash');
    setTimeout(() => card.classList.remove('flash'), 1200);
    return;
  }
}

/**
 * Fill `host` with the findings for `project`. `host` is a placeholder the config
 * view has already placed; if the view was re-rendered before the answer arrived
 * it is detached and nothing happens.
 */
export async function mountConfigCheck(project: Project, host: HTMLElement): Promise<void> {
  const findings = await checkProject(project);
  if (!host.isConnected || !findings?.length) return;
  const errors = findings.filter((f) => f.severity === 'error').length;
  setHtml(
    host,
    html`<div class="config-check-head">
        ${errors ? `${errors} error${errors === 1 ? '' : 's'}, ` : ''}${findings.length - errors}
        warning${findings.length - errors === 1 ? '' : 's'} between chunks
      </div>
      <ul class="config-check-list">
        ${findings.map(
          (f) => html`<li class="config-check-item config-check-${f.severity}">
            <span class="badge config-check-sev">${f.severity}</span>
            <button type="button" class="config-check-chunk" data-check-chunk="${f.chunk_id}">
              ${f.chunk || f.chunk_type}
            </button>
            <span class="config-check-msg">${f.message}</span>
          </li>`,
        )}
      </ul>`,
  );
  host.hidden = false;
  for (const b of host.querySelectorAll<HTMLElement>('[data-check-chunk]')) {
    b.onclick = () => focusChunk(b.dataset.checkChunk ?? '');
  }
}
