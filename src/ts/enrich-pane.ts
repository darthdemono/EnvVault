/**
 * Tools -> Enrich (Phase 33.1): `envv enrich` without `--online`, in the app.
 *
 * The planner is Rust (`envv_cli::enrich::plan_entry`, over the `enrich_plan`
 * command), so a Preview shows exactly what the CLI would propose, reasons and
 * all. It works from an entry's name and the public issuer prefix of its secret;
 * the secret itself never comes back, only a fingerprint. Nothing is written
 * until the user applies, and only the proposals still ticked.
 *
 * The `--online` half (asking each issuer about its own credential) is not here:
 * it sends the secret to a third party and needs its own consent screen. See the
 * 33.1 row in AGENTS.md.
 */
import { st, persist, entryId, inTauri, RemoteVaultStore } from './state';
import { invokeTauri } from './tauri';
import { html, setHtml } from './html';
import { showConfirm, showToast } from './utils';
import type { VaultEntry } from './types';

interface Proposal {
  field: string;
  value: unknown;
  reason: string;
}
interface Plan {
  id: string | null;
  provider: string;
  fingerprint: string;
  proposals: Proposal[];
  /** What an issuer said about its own credential (`--online`), when asked. */
  live?: { issuer: string; status: string; detail: string };
}
interface Live {
  id: string | null;
  provider: string;
  issuer: string;
  status: string;
  detail: string;
  proposals: Proposal[];
}

let plans: Plan[] = [];

function show(v: unknown): string {
  return typeof v === 'string' ? v : JSON.stringify(v);
}

function paint(): void {
  const host = document.getElementById('enrich-results')!;
  const apply = document.getElementById('enrich-apply-btn') as HTMLButtonElement;
  apply.disabled = plans.length === 0;
  if (!plans.length) {
    setHtml(
      host,
      html`<p class="tl-muted">Nothing to enrich: every entry already carries what could be inferred.</p>`,
    );
    return;
  }
  setHtml(
    host,
    html`${plans.map(
      (p, i) => html`<div class="health-entry-group">
        <div class="health-entry-header">
          <span class="health-entry-provider">${p.provider}</span>
          <span class="health-entry-count">${p.fingerprint}</span>
          ${p.live ? html`<span class="badge">${p.live.issuer}: ${p.live.status}</span>` : ''}
        </div>
        ${p.live && p.live.status !== 'ok' ? html`<div class="health-row"><span class="health-msg">${p.live.detail}</span></div>` : ''}
        ${p.proposals.map(
          (q, j) => html`<label class="health-row">
            <input type="checkbox" data-enrich="${i}:${j}" checked />
            <span class="health-field">${q.field}</span>
            <span class="health-msg">${show(q.value)} <span class="tl-muted">${q.reason}</span></span>
          </label>`,
        )}
      </div>`,
    )}`,
  );
}

/**
 * `--online`: names every recipient before any request is made, then asks. A
 * credential sent to its own issuer is the one place a secret leaves this machine
 * in this feature, and it also reveals whether a stored key has been revoked.
 */
async function askIssuers(force: boolean, status: HTMLElement): Promise<void> {
  const targets = await invokeTauri<{ id: string | null; provider: string; issuer: string }[]>(
    'enrich_online_targets',
    { entries: st.vault.api_keys },
  );
  if (!targets.length) {
    status.textContent = 'No stored secret has a recognised issuer to ask.';
    return;
  }
  const byIssuer = new Map<string, number>();
  for (const t of targets) byIssuer.set(t.issuer, (byIssuer.get(t.issuer) ?? 0) + 1);
  const list = [...byIssuer].map(([i, n]) => `${i} (${n})`).join(', ');
  const ok = await showConfirm(
    `Send ${targets.length} stored secret${targets.length === 1 ? '' : 's'} over TLS to the service that issued each one, and to no one else? Recipients: ${list}. Each issuer will see the request, and a rejected key shows it was revoked.`,
  );
  if (!ok) {
    status.textContent = 'Online check cancelled; nothing was sent.';
    return;
  }
  status.textContent = 'Asking issuers…';
  const ids = new Set(targets.map((t) => t.id));
  const lives = await invokeTauri<Live[]>('enrich_online', {
    entries: st.vault.api_keys.filter((e) => ids.has(entryId(e))),
    force,
  });
  for (const live of lives) {
    let plan = plans.find((p) => p.id === live.id);
    if (!plan) {
      plan = { id: live.id, provider: live.provider, fingerprint: '', proposals: [] };
      plans.push(plan);
    }
    plan.live = { issuer: live.issuer, status: live.status, detail: live.detail };
    // A live answer replaces an inferred one for the same field, like the CLI.
    for (const q of live.proposals) {
      plan.proposals = plan.proposals.filter((x) => x.field !== q.field);
      plan.proposals.push(q);
    }
  }
}

async function preview(): Promise<void> {
  const status = document.getElementById('enrich-status')!;
  const force = (document.getElementById('enrich-force') as HTMLInputElement).checked;
  status.textContent = 'Working…';
  try {
    plans = await invokeTauri<Plan[]>('enrich_plan', { entries: st.vault.api_keys, force });
    if ((document.getElementById('enrich-online') as HTMLInputElement).checked) {
      await askIssuers(force, status);
    }
    status.textContent = `${plans.length} entr${plans.length === 1 ? 'y' : 'ies'} with proposals.`;
  } catch (e) {
    plans = [];
    status.textContent = `Could not plan: ${e instanceof Error ? e.message : String(e)}`;
  }
  paint();
}

async function apply(): Promise<void> {
  const ticked = Array.from(
    document.querySelectorAll<HTMLInputElement>('#enrich-results input[data-enrich]:checked'),
  );
  if (!ticked.length) {
    showToast('Tick at least one proposal first', 'err', 1800);
    return;
  }
  let written = 0;
  for (const box of ticked) {
    const [i, j] = box.dataset.enrich!.split(':').map(Number);
    const plan = plans[i];
    const q = plan?.proposals[j];
    // Resolved by id at apply time (invariant 1): the vault may have changed
    // since the preview, and an entry that is gone is skipped, not retargeted.
    const entry = st.vault.api_keys.find((e) => entryId(e) === plan?.id) as
      (VaultEntry & Record<string, unknown>) | undefined;
    if (!entry || !q) continue;
    entry[q.field] = q.value;
    written++;
  }
  await persist();
  plans = [];
  paint();
  document.getElementById('enrich-status')!.textContent = '';
  showToast(`Enriched: ${written} field${written === 1 ? '' : 's'} written`, 'ok', 2500);
}

export function initEnrichPane(): void {
  const status = document.getElementById('enrich-status');
  const previewBtn = document.getElementById('enrich-preview-btn') as HTMLButtonElement | null;
  if (!status || !previewBtn) return;
  if (!inTauri) {
    status.textContent = 'Available in the desktop app. In a terminal: envv enrich.';
    previewBtn.disabled = true;
    return;
  }
  previewBtn.onclick = () => void preview();
  (document.getElementById('enrich-apply-btn') as HTMLButtonElement).onclick = () => void apply();
}

// ── Diagnose (Phase 33.2) ───────────────────────────────────────────────────
// The document half of `envv doctor`, in the Health pane. The database-level
// checks (integrity, storage, salt, file permissions, audit chain) need the file
// run too when the vault is this machine's (`doctor_file`); against a remote the
// pane says the rest is the server's.

interface Finding {
  check: string;
  level: 'ok' | 'note' | 'warn' | 'fail';
  message: string;
  remedy: string;
}

export function initDoctorPane(): void {
  const btn = document.getElementById('doctor-run-btn') as HTMLButtonElement | null;
  const status = document.getElementById('doctor-status');
  const host = document.getElementById('doctor-results');
  if (!btn || !status || !host) return;
  if (!inTauri) {
    status.textContent = 'Available in the desktop app. In a terminal: envv doctor.';
    btn.disabled = true;
    return;
  }
  btn.onclick = () => {
    status.textContent = 'Checking…';
    void (async () => {
      try {
        const findings = await invokeTauri<Finding[]>('doctor_document', { vault: st.vault });
        // The file half needs this machine's database, so it only runs against the
        // local vault; a remote's file belongs to the server (`envv doctor` there).
        const local = !(st.store instanceof RemoteVaultStore);
        if (local) findings.push(...(await invokeTauri<Finding[]>('doctor_file')));
        const bad = findings.filter((f) => f.level === 'warn' || f.level === 'fail').length;
        const tail = local
          ? ''
          : ' File, integrity and audit checks run on the server: envv doctor.';
        status.textContent =
          (bad ? `${bad} thing${bad === 1 ? '' : 's'} need attention.` : 'All checks passed.') +
          tail;
        setHtml(
          host,
          html`${findings.map(
            (f) => html`<div class="health-row">
              <span class="badge">${f.level}</span>
              <span class="health-field">${f.check}</span>
              <span class="health-msg">${f.message}${f.remedy ? html` <span class="tl-muted">${f.remedy}</span>` : ''}</span>
            </div>`,
          )}`,
        );
      } catch (e: unknown) {
        status.textContent = `Could not run the checks: ${e instanceof Error ? e.message : String(e)}`;
      }
    })();
  };
}
