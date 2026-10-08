/**
 * Tools -> Import -> "From another password manager" (Phase 33.3): the app side
 * of `envv import-vault`. The parsing and merge rules are Rust
 * (`envv_cli::import_vaults::plan_import`, over `import_vault_plan`), so a
 * preview here is exactly what the CLI would write. The preview carries
 * fingerprints, never secrets; applying replaces the entry array with the plan's
 * and saves once, so the compare-and-swap covers the whole import.
 */
import { inTauri, persist, st } from './state';
import { invokeTauri } from './tauri';
import { html, setHtml } from './html';
import { showToast } from './utils';
import type { VaultEntry } from './types';

interface PlanRow {
  provider: string;
  secret_type: string;
  fingerprint: string;
  username: string | null;
  folder: string | null;
}
interface Plan {
  entries: VaultEntry[];
  created: number;
  updated: number;
  unchanged: number;
  skipped: number;
  preview: PlanRow[];
}

let pending: Plan | null = null;

function readFile(): Promise<string | null> {
  return new Promise((resolve) => {
    // Created and removed per use: a static <input type=file> renders a native
    // ghost widget in WebKitGTK (AGENTS.md, Phase 3).
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = '.json,.1pif,.txt';
    inp.style.display = 'none';
    document.body.appendChild(inp);
    const done = (v: string | null) => {
      inp.remove();
      resolve(v);
    };
    inp.onchange = () => {
      const f = inp.files?.[0];
      if (!f) return done(null);
      f.text().then(done, () => done(null));
    };
    inp.click();
  });
}

function paint(plan: Plan): void {
  const host = document.getElementById('vi-preview')!;
  setHtml(
    host,
    html`<table class="diff-table">
      <tbody>${plan.preview.map(
        (r) => html`<tr>
          <td>${r.provider}</td>
          <td>${r.secret_type}</td>
          <td class="mono">${r.fingerprint}</td>
          <td>${r.username ?? ''}</td>
        </tr>`,
      )}</tbody>
    </table>`,
  );
}

export function initVendorImportPane(): void {
  const fileBtn = document.getElementById('vi-file-btn') as HTMLButtonElement | null;
  const applyBtn = document.getElementById('vi-apply-btn') as HTMLButtonElement | null;
  const status = document.getElementById('vi-status');
  if (!fileBtn || !applyBtn || !status) return;
  if (!inTauri) {
    status.textContent = 'Available in the desktop app. In a terminal: envv import-vault.';
    fileBtn.disabled = true;
    return;
  }
  fileBtn.onclick = () => {
    void (async () => {
      const text = await readFile();
      if (text === null) {
        status.textContent = 'No file chosen.';
        return;
      }
      const vendor = (document.getElementById('vi-vendor') as HTMLSelectElement).value;
      const keepFolders = (document.getElementById('vi-folders') as HTMLInputElement).checked;
      status.textContent = 'Reading…';
      try {
        const plan = await invokeTauri<Plan>('import_vault_plan', {
          vendor,
          text,
          vault: st.vault,
          project: null,
          keepFolders,
        });
        pending = plan;
        applyBtn.disabled = plan.created + plan.updated === 0;
        status.textContent = `${plan.created} to create, ${plan.updated} to update, ${plan.unchanged} unchanged, ${plan.skipped} skipped.`;
        paint(plan);
      } catch (e) {
        pending = null;
        applyBtn.disabled = true;
        status.textContent = `Cannot import: ${e instanceof Error ? e.message : String(e)}`;
      }
    })();
  };
  applyBtn.onclick = () => {
    if (!pending) {
      status.textContent = 'Choose a file first.';
      return;
    }
    const plan = pending;
    pending = null;
    applyBtn.disabled = true;
    st.vault.api_keys = plan.entries;
    void persist().then(() => {
      setHtml(document.getElementById('vi-preview')!, html``);
      status.textContent = '';
      showToast(`Imported: ${plan.created} created, ${plan.updated} updated`, 'ok', 2500);
    });
  };
}
