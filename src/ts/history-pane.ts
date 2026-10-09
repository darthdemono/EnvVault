/**
 * Tools -> Config history (Phase 35): the app side of `unv history ...`.
 *
 * The same dispatcher answers every surface: a local vault reaches it through the
 * `history_call` command, a remote one through `POST /api/history`. The pane never
 * renders anything itself, so what it shows is what `unv history` shows.
 *
 * Default is the fingerprinted text, in which a rotated secret is a changed
 * fingerprint. The real text appears only when Reveal is ticked and confirmed,
 * and the Save button writes it to a file, not into the page.
 */
import { html, setHtml } from './html';
import { RemoteVaultStore, st } from './state';
import { invokeTauri, isTauri } from './tauri';
import { saveFile, showConfirm, showToast } from './utils';
import { applyRestore, canRestore, describePlan, planRestore } from './restore-chunks';
import { persist } from './state';
import { triggerRender } from './state';

const $ = (id: string) => document.getElementById(id)!;

interface Snap {
  seq: number;
  project: string;
  project_name: string;
  exporter: string;
  at: string;
  sha256: string;
  bytes: number;
  cause: string;
}

function say(msg: string, kind: 'ok' | 'err' = 'ok'): void {
  const el = $('history-status');
  el.textContent = msg;
  el.className = `tool-status ${kind}`;
}

async function hcall(op: string, args: Record<string, unknown> = {}): Promise<unknown> {
  say('Working…');
  try {
    if (st.store instanceof RemoteVaultStore) {
      const a = await st.store.nodesRequest('POST', '/api/history', { op, args });
      if (a.status >= 200 && a.status < 300) return a.body;
      if (a.status === 403) say('Only the vault owner reaches the config history.', 'err');
      else {
        const msg = (a.body as { error?: string } | null)?.error;
        say(msg ? msg : `Refused (${a.status})`, 'err');
      }
      return null;
    }
    if (isTauri()) return await invokeTauri<unknown>('history_call', { op, args });
    say(
      'The config history lives in the vault. Open the desktop app, or connect to a remote vault.',
      'err',
    );
    return null;
  } catch (e) {
    say(e instanceof Error ? e.message : String(e), 'err');
    return null;
  }
}

function project(): string {
  return ($('history-project') as HTMLSelectElement).value;
}
function exporter(): string {
  return ($('history-exporter') as HTMLInputElement).value.trim();
}
function wantsReveal(): boolean {
  return ($('history-reveal') as HTMLInputElement).checked;
}

function fillProjects(): void {
  const sel = $('history-project') as HTMLSelectElement;
  const keep = sel.value;
  const names = (st.vault?.projects ?? []).map((p) => p.name);
  setHtml(
    sel,
    html`<option value="">All projects</option>${names.map((n) => html`<option value="${n}">${n}</option>`)}`,
  );
  if (names.includes(keep)) sel.value = keep;
}

function show(text: string): void {
  $('history-output').textContent = text;
}

async function list(): Promise<void> {
  fillProjects();
  const v = (await hcall('list', {
    project: project() || undefined,
    exporter: exporter() || undefined,
    limit: 100,
  })) as { snapshots?: Snap[] } | null;
  if (!v) return;
  const rows = v.snapshots ?? [];
  setHtml(
    $('history-list'),
    rows.length
      ? html`<table class="history-table">
          <tbody>
            ${rows.map(
              (
                r,
              ) => html`<tr data-seq="${r.seq}" data-project="${r.project}" data-exporter="${r.exporter}">
                <td>#${r.seq}</td>
                <td>${r.at}</td>
                <td>${r.project_name}</td>
                <td>${r.exporter}</td>
                <td>${r.bytes} B</td>
                <td class="mono">${r.sha256.slice(0, 8)}</td>
                <td>${r.cause}</td>
                <td>
                  <button class="btn btn-ghost btn-sm" data-history-act="show">Show</button>
                  <button class="btn btn-ghost btn-sm" data-history-act="diff">Diff with previous</button>
                  <button class="btn btn-ghost btn-sm" data-history-act="save">Save file</button>${
                    canRestore(r.exporter)
                      ? html`<button class="btn btn-ghost btn-sm" data-history-act="restore">
                          Restore into chunks
                        </button>`
                      : ''
                  }
                </td>
              </tr>`,
            )}
          </tbody>
        </table>`
      : html`<p class="tool-hint">
          No snapshots yet. One is recorded whenever a save changes a project's rendered config.
        </p>`,
  );
  say(`${rows.length} snapshot${rows.length === 1 ? '' : 's'}`);
}

/** Asked before the real values go on screen, because a screenshot keeps them. */
async function mayReveal(): Promise<boolean> {
  if (!wantsReveal()) return false;
  return showConfirm(
    'Show the real secret values on screen? They are the values that were deployed at the time.',
  );
}

async function showSnap(seq: number): Promise<void> {
  const reveal = await mayReveal();
  const v = (await hcall('show', { seq, reveal })) as { text?: string } | null;
  if (!v) return;
  show(v.text ?? '');
  say(reveal ? `Snapshot #${seq} (real values).` : `Snapshot #${seq} (secrets as fingerprints).`);
}

/** A file's text, from a picker created and removed per use (a static one is a WebKitGTK ghost). */
function chooseFile(): Promise<string | null> {
  return new Promise((resolve) => {
    const inp = document.createElement('input');
    inp.type = 'file';
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

async function diffSnap(args: Record<string, unknown>): Promise<void> {
  const reveal = await mayReveal();
  const v = (await hcall('diff', { ...args, reveal })) as {
    diff?: string;
    from?: number;
    to?: number;
    added?: number;
    removed?: number;
  } | null;
  if (!v) return;
  show(v.diff || `#${v.from} and #${v.to} render identically.`);
  say(
    `#${v.from} to #${v.to}: +${v.added ?? 0} -${v.removed ?? 0}${reveal ? ' (real values)' : ''}`,
  );
}

/**
 * Reads a snapshot back into the project's chunks. The snapshot's real text is
 * what was deployed, so this needs it unmasked; the question says what is replaced
 * and that values arrive as literal text, not references.
 */
async function restoreSnap(seq: number, projectRef: string, exp: string): Promise<void> {
  const proj = (st.vault?.projects ?? []).find((p) => p.id === projectRef || p.name === projectRef);
  if (!proj) return say(`The project '${projectRef}' no longer exists.`, 'err');
  const v = (await hcall('show', { seq, reveal: true })) as { text?: string } | null;
  if (!v?.text) return;
  const plan = planRestore(proj, exp, v.text);
  if (!plan) return say(`A ${exp} config cannot be read back into chunks here.`, 'err');
  if (!plan.parsed.length) return say('Nothing in that snapshot could be read as chunks.', 'err');
  const ok = await showConfirm(
    `Restore snapshot #${seq} into '${proj.name}'?\n${describePlan(plan)}\n` +
      'The values arrive as literal text from the snapshot, not as references to your entries. ' +
      'Other chunks in the project are left alone.',
  );
  if (!ok) return say('Nothing was changed.');
  applyRestore(proj, plan);
  await persist();
  triggerRender();
  say(`Restored snapshot #${seq} into '${proj.name}'.`);
}

async function saveSnap(seq: number, name: string): Promise<void> {
  const v = (await hcall('show', { seq, reveal: true })) as { text?: string } | null;
  if (!v) return;
  const saved = await saveFile(v.text ?? '', name);
  if (saved.ok) {
    say(`Saved${saved.path ? ` to ${saved.path}` : ''} (the file holds the real secrets).`);
    showToast('Snapshot saved', 'ok', 2000);
  } else say(`Could not save: ${saved.error}`, 'err');
}

function policyFields(): { enabled: boolean; keep: number; days: number } {
  return {
    enabled: ($('history-enabled') as HTMLInputElement).checked,
    keep: Number(($('history-keep') as HTMLInputElement).value) || 50,
    days: Number(($('history-days') as HTMLInputElement).value) || 0,
  };
}

async function loadPolicy(): Promise<void> {
  const p = (await hcall('policy')) as { enabled: boolean; keep: number; days: number } | null;
  if (!p) return;
  ($('history-enabled') as HTMLInputElement).checked = p.enabled;
  ($('history-keep') as HTMLInputElement).value = String(p.keep);
  ($('history-days') as HTMLInputElement).value = String(p.days);
  say(
    `History is ${p.enabled ? 'on' : 'off'}: newest ${p.keep} per config, and everything from the last ${p.days} days.`,
  );
}

export function initHistoryPane(): void {
  if (!document.getElementById('history-list-btn')) return;
  $('history-list-btn').onclick = () => void list();
  $('history-diff-btn').onclick = () => {
    if (!project()) return say('Pick a project to compare its two newest snapshots.', 'err');
    void diffSnap({ project: project(), exporter: exporter() || undefined });
  };
  $('history-diff-file-btn').onclick = () => {
    if (!project()) return say('Pick a project (and a config, if it has several) first.', 'err');
    void (async () => {
      const text = await chooseFile();
      if (text === null) return say('No file chosen.');
      const reveal = await mayReveal();
      const v = (await hcall('diff_text', {
        project: project(),
        exporter: exporter() || undefined,
        text,
        reveal,
      })) as {
        seq?: number;
        diff?: string;
        added?: number;
        removed?: number;
        identical?: boolean;
      } | null;
      if (!v) return;
      show(v.identical ? '' : (v.diff ?? ''));
      say(
        v.identical
          ? `#${v.seq} and the file are identical.`
          : `#${v.seq} against the file: +${v.added ?? 0} -${v.removed ?? 0}${
              reveal ? ' (real values)' : ' (values hidden; tick Reveal to see the lines)'
            }`,
      );
    })();
  };
  $('history-snapshot-btn').onclick = () =>
    void (async () => {
      const v = (await hcall('snapshot', { project: project() || undefined })) as {
        recorded?: number;
        unchanged?: number;
      } | null;
      if (v) {
        say(`${v.recorded ?? 0} recorded, ${v.unchanged ?? 0} unchanged.`);
        await list();
      }
    })();
  $('history-verify-btn').onclick = () =>
    void (async () => {
      const v = (await hcall('verify')) as { snapshots: number; problems: string[] } | null;
      if (!v) return;
      show(v.problems.join('\n'));
      if (v.problems.length) say(`${v.problems.length} problem(s) in the history.`, 'err');
      else say(`${v.snapshots} snapshot(s) intact.`);
    })();
  $('history-policy-load-btn').onclick = () => void loadPolicy();
  $('history-policy-btn').onclick = () =>
    void (async () => {
      const p = policyFields();
      const v = await hcall('policy', p);
      if (v) say('Policy saved.');
    })();
  $('history-prune-btn').onclick = () =>
    void (async () => {
      const p = policyFields();
      const dry = (await hcall('prune', { keep: p.keep, days: p.days, dry_run: true })) as {
        would_delete: number;
        bytes_freed: number;
      } | null;
      if (!dry) return;
      if (!dry.would_delete) return say('Nothing is old enough to prune.');
      const ok = await showConfirm(
        `Delete ${dry.would_delete} old snapshot(s) (${dry.bytes_freed} bytes)? Their secrets are gone for good, and so is the record of what was deployed then.`,
      );
      if (!ok) return say('Cancelled.');
      const done = (await hcall('prune', { keep: p.keep, days: p.days, dry_run: false })) as {
        deleted: number;
      } | null;
      if (done) say(`Deleted ${done.deleted} snapshot(s); a checkpoint keeps the rest verifiable.`);
    })();
  $('history-list').onclick = (ev) => {
    const btn = (ev.target as HTMLElement).closest<HTMLElement>('[data-history-act]');
    const row = btn?.closest<HTMLElement>('tr[data-seq]');
    if (!btn || !row) return;
    const seq = Number(row.dataset.seq);
    const act = btn.dataset.historyAct;
    if (act === 'show') void showSnap(seq);
    else if (act === 'diff')
      void diffSnap({ project: row.dataset.project, exporter: row.dataset.exporter, to: seq });
    else if (act === 'save')
      void saveSnap(seq, `${row.dataset.project}-${row.dataset.exporter}-${seq}`);
    else if (act === 'restore')
      void restoreSnap(seq, row.dataset.project ?? '', row.dataset.exporter ?? '');
  };
}
