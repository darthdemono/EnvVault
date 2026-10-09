/**
 * Tools -> Nodes (Phase 34): the app side of `unv node ...`, over the hub's
 * `/api/nodes/*` routes. Nodes are managed on a server started with `--nodes`,
 * so this works against a remote vault; against a local one the pane says so.
 *
 * What it will not do: show a pull target's file. It is the node's own and holds
 * its secrets, so it goes to a file through `saveFile` (the app's `--out`) and the
 * toast names the path. An enrollment token is shown once, in the output box,
 * and kept nowhere.
 */
import { html, setHtml } from './html';
import { RemoteVaultStore, persist, st } from './state';
import { saveFile, showConfirm, showPrompt, showToast } from './utils';
import { invokeTauri, isTauri } from './tauri';
import { applyRestore, canRestore, describePlan, planRestore } from './restore-chunks';

const $ = (id: string) => document.getElementById(id)!;

interface TargetRow {
  id: string;
  project?: string;
  exporter?: string;
  mode: string;
  apply: boolean;
  status: string;
  refusal?: string | null;
  error?: string | null;
  /** The newest config-history snapshot whose hash the node reports (Phase 35). */
  snapshot?: { seq: number; at: string } | null;
}
interface ApprovalRow {
  id: string;
  target: string;
  sha256: string;
  status: string;
  requested_at: string;
  decided_by?: string | null;
  from_seq?: number | null;
  to_seq?: number | null;
}
interface NodeRow {
  id: string;
  name: string;
  fingerprint: string;
  projects: string[];
  last_seen?: string | null;
  revoked_at?: string | null;
  host?: { hostname?: string; os?: string; arch?: string; version?: string } | null;
  targets: TargetRow[];
  approval?: string;
  approvals?: ApprovalRow[];
  /** Set when the hub dials this node (Phase 34.1). */
  listen?: { endpoint: string; cert_sha256: string } | null;
  last_polled?: string | null;
}

function say(msg: string, kind: 'ok' | 'err' = 'ok'): void {
  const el = $('nodes-status');
  el.textContent = msg;
  el.className = `tool-status ${kind}`;
}

type Answer = { status: number; body: unknown };

async function call(method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown) {
  if (!(st.store instanceof RemoteVaultStore)) {
    say('Nodes live on a server. Connect to a remote vault first.', 'err');
    return null;
  }
  say('Working…');
  try {
    const a: Answer = await st.store.nodesRequest(method, path, body);
    if (a.status >= 200 && a.status < 300) return a;
    if (a.status === 404 && path === '/api/nodes')
      say('Not found: is the server running with --nodes?', 'err');
    else if (a.status === 403) say('Only the vault owner manages nodes.', 'err');
    else if (a.status === 429) say('Rate limited. Wait and try again.', 'err');
    else {
      const msg = (a.body as { error?: string } | null)?.error;
      say(msg ? `Refused (${a.status}): ${msg}` : `Refused (${a.status})`, 'err');
    }
    return null;
  } catch (e) {
    say(`Could not reach the server: ${e instanceof Error ? e.message : String(e)}`, 'err');
    return null;
  }
}

function targetLine(t: TargetRow) {
  const note = t.refusal ?? t.error ?? '';
  return html`<li>
    <span class="mono">${t.id}</span> · ${t.mode} · apply ${t.apply ? 'on' : 'off'} ·
    <strong>${t.status}</strong>${note ? html` <em>(${note})</em>` : ''}${
      t.snapshot ? html` · file matches history #${t.snapshot.seq} (${t.snapshot.at})` : ''
    }
    ${
      t.mode === 'pull'
        ? html`<button class="btn btn-ghost btn-sm" data-node-act="pull" data-target="${t.id}">
            Fetch file
          </button>
          ${
            t.exporter === 'env' || t.exporter === 'compose-env' || canRestore(t.exporter ?? '')
              ? html`<button
                  class="btn btn-ghost btn-sm"
                  data-node-act="into-chunk"
                  data-target="${t.id}"
                  data-project="${t.project ?? ''}"
                  data-exporter="${t.exporter ?? ''}"
                >
                  Read into a chunk
                </button>`
              : ''
          }
          <button class="btn btn-ghost btn-sm" data-node-act="accept" data-target="${t.id}">
            Accept
          </button>`
        : ''
    }
  </li>`;
}

const HELD = (n: NodeRow) =>
  n.approval === 'device'
    ? html`<p class="tool-hint">Every push to this node needs a yes signed on your own device; this hub cannot approve it by itself.</p>`
    : n.approval === 'required'
      ? html`<p class="tool-hint">Every push to this node is held for your approval.</p>`
      : '';

function approvalBlock(n: NodeRow) {
  const open = (n.approvals ?? []).filter((a) => a.status === 'pending');
  const recent = (n.approvals ?? []).filter((a) => a.status !== 'pending').slice(0, 3);
  if (!open.length && !recent.length) {
    return HELD(n);
  }
  return html`<div class="node-approvals">
    ${HELD(n)}
    ${open.map(
      (
        a,
      ) => html`<div class="node-approval" data-approval-id="${a.id}" data-sha="${a.sha256}" data-target="${a.target}" data-from="${a.from_seq ?? ''}" data-to="${a.to_seq ?? ''}">
        Held: <span class="mono">${a.target}</span> · file <span class="mono">${a.sha256.slice(0, 12)}</span> ·
        asked ${a.requested_at}
        <button class="btn btn-ghost btn-sm" data-node-act="review">Review changes</button>
        <button class="btn btn-accent btn-sm" data-node-act="approve">Approve</button>
        <button class="btn btn-ghost btn-sm" data-node-act="reject">Reject</button>
      </div>`,
    )}
    ${recent.map(
      (a) => html`<div class="tool-hint">
        ${a.status}: <span class="mono">${a.target}</span> ${a.sha256.slice(0, 12)}${a.decided_by ? html` by ${a.decided_by}` : ''}
      </div>`,
    )}
  </div>`;
}

export function renderNodes(nodes: NodeRow[]): void {
  const list = $('nodes-list');
  if (!nodes.length) {
    setHtml(list, html`<p class="tool-hint">No nodes enrolled.</p>`);
    return;
  }
  setHtml(
    list,
    html`${nodes.map((n) => {
      const revoked = !!n.revoked_at;
      return html`<section class="node-card" data-node-id="${n.id}" data-node-name="${n.name}" data-approval="${n.approval ?? ''}">
        <h4>
          ${n.name} ${revoked ? html`<em>(revoked)</em>` : ''}
          <button class="btn btn-ghost btn-sm" data-node-act="blast">Blast radius</button>
          ${
            revoked
              ? ''
              : html`<button
                class="btn btn-ghost btn-sm"
                data-node-act="policy"
                data-policy="${n.approval ? 'none' : 'required'}"
              >
                ${n.approval ? 'Stop requiring approval' : 'Require approval'}
              </button>${
                n.approval === 'device'
                  ? ''
                  : html`<button
                      class="btn btn-ghost btn-sm"
                      data-node-act="policy"
                      data-policy="device"
                      title="Approvals must be signed with a key on your own machine"
                    >
                      Require approval on my device
                    </button>`
              }`
          }
          ${
            revoked
              ? ''
              : html`<button class="btn btn-ghost btn-sm" data-node-act="revoke">
                Revoke
              </button>`
          }
        </h4>
        <p class="tool-hint">
          key ${n.fingerprint.slice(0, 16)}… · projects ${n.projects.join(', ')} · last seen
          ${n.last_seen ?? 'never'}${
            n.listen
              ? html` · hub dials ${n.listen.endpoint} (certificate ${n.listen.cert_sha256.slice(0, 12)}…), last polled
                ${n.last_polled ?? 'never'}`
              : ''
          }${
            n.host?.hostname
              ? html` · ${n.host.hostname} (${n.host.os ?? ''} ${n.host.arch ?? ''}, unv
              ${n.host.version ?? ''})`
              : ''
          }
        </p>
        ${approvalBlock(n)}
        <ul class="node-targets" data-node-id="${n.id}">
          ${n.targets.map((t) => targetLine(t))}
        </ul>
      </section>`;
    })}`,
  );
}

export async function refreshNodes(): Promise<void> {
  const store = st.store;
  setHtml($('nodes-list'), '');
  const a = await call('GET', '/api/nodes');
  if (!a || st.store !== store) return;
  const nodes = ((a.body as { nodes?: NodeRow[] } | null)?.nodes ?? []) as NodeRow[];
  renderNodes(nodes);
  say(`${nodes.length} node${nodes.length === 1 ? '' : 's'}`);
}

function decode(b64: string): string {
  const bin = atob(b64);
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

/** Asks a node for a pull target's file and waits for it. `null` after saying why. */
async function pullContent(nodeId: string, target: string): Promise<string | null> {
  const store = st.store;
  if (!(store instanceof RemoteVaultStore)) return null;
  if (!(await call('POST', `/api/nodes/${encodeURIComponent(nodeId)}/pull`, { target }))) {
    return null;
  }
  say('Asked the node. It answers on its next beat…');
  for (let i = 0; i < 90; i++) {
    await new Promise((r) => setTimeout(r, 700));
    const a = await store.nodesRequest('GET', `/api/nodes/${nodeId}/content/${target}`);
    if (a.status === 200) {
      return decode((a.body as { content_b64?: string }).content_b64 ?? '');
    }
    if (a.status !== 204) {
      say(`Refused (${a.status})`, 'err');
      return null;
    }
  }
  say('The node did not answer within about a minute.', 'err');
  return null;
}

async function fetchFile(nodeId: string, target: string): Promise<void> {
  const text = await pullContent(nodeId, target);
  if (text === null) return;
  const saved = await saveFile(text, `${target}.pulled`);
  if (saved.ok) {
    say(`File saved${saved.path ? ` to ${saved.path}` : ''} (the file holds the node's secrets).`);
    showToast('Pulled file saved', 'ok', 2000);
  } else say(`Could not save the file: ${saved.error}`, 'err');
}

interface EnvPlan {
  fields: unknown[];
  added: string[];
  changed: string[];
  removed: string[];
  kept_references: string[];
}

/**
 * Reads a pulled `.env`-style file back into an `env_file` chunk of the target's
 * project, with the rules `unv node pull --into-chunk` has (Rust, once): names
 * only in the question, a field holding a `${reference}` is never flattened into
 * its secret, and nothing is written until the user says yes. The file stays in
 * memory.
 */
async function readIntoChunk(
  nodeId: string,
  target: string,
  projectRef: string,
  exporterId = '',
): Promise<void> {
  if (!isTauri()) {
    return say(
      'Reading a file into a chunk needs the desktop app, or `unv node pull --into-chunk`.',
      'err',
    );
  }
  const project = st.vault.projects.find((p) => p.id === projectRef || p.name === projectRef);
  if (project && canRestore(exporterId)) {
    // A format with an app-side reader: replace the project's chunks of that
    // family with what the node's file contains.
    const text = await pullContent(nodeId, target);
    if (text === null) return;
    const plan = planRestore(project, exporterId, text);
    if (!plan?.parsed.length)
      return say('Nothing in the node’s file could be read as chunks.', 'err');
    const ok = await showConfirm(
      `Update '${project.name}' from the node's ${exporterId} file?\n${describePlan(plan)}\n` +
        'The values arrive as literal text, not as references to your entries. Other chunks are left alone.',
    );
    if (!ok) return say('Nothing was changed.');
    applyRestore(project, plan);
    await persist();
    say(`'${project.name}' updated from the node's file.`);
    return;
  }
  const chunks = (project?.chunks ?? []).filter((c) => c.chunk_type === 'env_file');
  if (!project || !chunks.length) {
    return say(`Project '${projectRef}' has no .env chunk to read this into.`, 'err');
  }
  let chunk = chunks[0];
  if (chunks.length > 1) {
    const name = await showPrompt(
      `Which chunk? (${chunks.map((c) => c.name).join(', ')})`,
      chunks[0].name,
    );
    const hit = chunks.find((c) => c.name === name);
    if (!hit) return say('No such chunk; nothing was read.', 'err');
    chunk = hit;
  }
  const text = await pullContent(nodeId, target);
  if (text === null) return;
  let plan: EnvPlan;
  try {
    plan = await invokeTauri<EnvPlan>('env_import_plan', { fields: chunk.fields, text });
  } catch (e) {
    return say(`Could not read the file: ${e instanceof Error ? e.message : String(e)}`, 'err');
  }
  const names = (label: string, l: string[]) => (l.length ? `\n${label}: ${l.join(', ')}` : '');
  const ok = await showConfirm(
    `Update chunk '${chunk.name}' from the node's file?` +
      names('Added', plan.added) +
      names('Changed', plan.changed) +
      names('Removed', plan.removed) +
      names('Kept as references', plan.kept_references) +
      (plan.added.length + plan.changed.length + plan.removed.length === 0
        ? '\nNothing differs.'
        : ''),
  );
  if (!ok) return say('Nothing was changed.');
  chunk.fields = plan.fields as typeof chunk.fields;
  await persist();
  say(`Chunk '${chunk.name}' updated from the node's file.`);
}

interface BlastEntry {
  provider: string;
  key_id: string;
  fields: string[];
  first_seen: string;
  last_seen: string;
  times: number;
  still_current: boolean;
  removed: boolean;
  short: boolean;
  console_url?: string | null;
}
interface BlastReport {
  host: string;
  since?: string | null;
  deployments: number;
  unaccounted: { at: string; via: string; sha256: string }[];
  entries: BlastEntry[];
  command: string;
}

/** The report as text: which credentials, whether each is still live, and the one command. */
export function formatBlast(r: BlastReport): string {
  const lines = [
    `Blast radius of ${r.host}${r.since ? ` since ${r.since}` : ''}: ${r.deployments} deployment(s), ${r.entries.length} credential(s)`,
  ];
  for (const e of r.entries) {
    const tag = e.removed ? 'removed' : e.still_current ? 'ROTATE ' : 'rotated';
    const name = e.key_id ? `${e.provider}:${e.key_id}` : e.provider;
    lines.push(
      `  ${tag} ${name} (${e.fields.join(', ')})  first ${e.first_seen}  last ${e.last_seen}  x${e.times}` +
        (e.short ? '  [short value: may be a coincidence]' : '') +
        (e.console_url ? `  revoke at ${e.console_url}` : ''),
    );
  }
  if (r.unaccounted.length) {
    lines.push(
      '',
      `${r.unaccounted.length} deployment(s) have no recorded contents (history was off, or pruned): their exposure is unknown.`,
    );
    for (const d of r.unaccounted) lines.push(`  ${d.at} ${d.via} ${d.sha256.slice(0, 8)}`);
  }
  lines.push('');
  lines.push(
    r.command
      ? `Rotate these and nothing else:\n  ${r.command}\n\nThat replaces the vault's copy. Revoke the old credential at its issuer too.`
      : 'Nothing in the vault needs rotating for this host.',
  );
  return lines.join('\n');
}

async function blast(nodeName: string): Promise<void> {
  const since = ($('nodes-since') as HTMLInputElement).value.trim();
  const a = await call('POST', '/api/history', {
    op: 'blast',
    args: { host: nodeName, ...(since ? { since } : {}) },
  });
  if (!a) return;
  $('nodes-output').textContent = formatBlast(a.body as BlastReport);
  say(`Blast radius of ${nodeName}.`);
}

/** The held push's changes, as the CLI shows them: secrets as fingerprints. */
async function review(row: HTMLElement): Promise<void> {
  const from = Number(row.dataset.from);
  const to = Number(row.dataset.to);
  if (!to) {
    $('nodes-output').textContent =
      'The proposal is not in the history (is the config history off?).';
    return say('Nothing to compare.', 'err');
  }
  if (from) {
    const a = await call('POST', '/api/history', { op: 'diff', args: { from, to, reveal: false } });
    if (!a) return;
    const d = a.body as { diff?: string };
    $('nodes-output').textContent = d.diff || 'The two render identically.';
  } else {
    const a = await call('POST', '/api/history', { op: 'show', args: { seq: to, reveal: false } });
    if (!a) return;
    const t = (a.body as { text?: string }).text ?? '';
    $('nodes-output').textContent =
      "The node's current file is not in the history: this is the whole proposed file.\n" +
      t
        .split('\n')
        .map((l) => `+${l}`)
        .join('\n');
  }
  say('Secrets are shown as fingerprints.');
}

async function approvalAction(
  act: string,
  btn: HTMLElement,
  card: HTMLElement | null,
): Promise<void> {
  if (act === 'policy') {
    const nodeId = card?.dataset.nodeId ?? '';
    const policy = btn.dataset.policy ?? 'none';
    if (
      await call('POST', `/api/nodes/${encodeURIComponent(nodeId)}/policy`, { approval: policy })
    ) {
      await refreshNodes();
    }
    return;
  }
  const row = btn.closest<HTMLElement>('[data-approval-id]');
  if (!row) return;
  if (act === 'review') return review(row);
  const id = row.dataset.approvalId ?? '';
  if (act === 'approve') {
    // The hash is in the question so what is approved is what was on screen.
    const sha = (row.dataset.sha ?? '').slice(0, 12);
    const ok = await showConfirm(
      `Approve exactly these bytes (file ${sha}) for ${card?.dataset.nodeName ?? 'this node'}? Review the changes first. The approval lapses in an hour.`,
    );
    if (!ok) return;
  }
  let body: unknown;
  if (act === 'approve' && card?.dataset.approval === 'device') {
    // Signed here, with a key that never leaves this machine; the hub only checks
    // the signature and passes it on.
    if (!isTauri()) {
      return say(
        'Signing needs the desktop app, or `unv node approve` in a terminal on your own machine.',
        'err',
      );
    }
    try {
      const signed = await invokeTauri<{ token: string; sig: string }>('approver_sign', {
        nodeId: card.dataset.nodeId ?? '',
        target: row.dataset.target ?? '',
        sha256: row.dataset.sha ?? '',
        approvalId: id,
      });
      body = { signed };
    } catch (e) {
      return say(`Could not sign: ${e instanceof Error ? e.message : String(e)}`, 'err');
    }
  }
  const a = await call('POST', `/api/node-approvals/${encodeURIComponent(id)}/${act}`, body);
  if (a) {
    say(act === 'approve' ? 'Approved. The node picks it up on its next beat.' : 'Rejected.');
    await refreshNodes();
  }
}

export function initNodesPane(): void {
  if (!document.getElementById('nodes-refresh-btn')) return;
  $('nodes-refresh-btn').onclick = () => void refreshNodes();
  $('nodes-approver-btn').onclick = () => {
    void (async () => {
      if (!isTauri()) {
        return say(
          'The approver key lives in the desktop app. In a terminal: unv node approver register --label NAME',
          'err',
        );
      }
      try {
        const me = await invokeTauri<{ public_key: string; fingerprint: string }>(
          'approver_public',
        );
        const a = await call('POST', '/api/node-approvers', {
          pubkey: me.public_key,
          label: 'Desktop app',
        });
        if (a) {
          say(
            `Registered this device (${me.fingerprint.slice(0, 16)}). Put the public key in a node's config as approver = "${me.public_key}" and choose "Require approval on my device".`,
          );
        }
      } catch (e) {
        say(`Could not register: ${e instanceof Error ? e.message : String(e)}`, 'err');
      }
    })();
  };
  $('nodes-token-btn').onclick = () => {
    const name = ($('nodes-name') as HTMLInputElement).value.trim();
    const projects = ($('nodes-projects') as HTMLInputElement).value
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);
    const mins = Number(($('nodes-ttl') as HTMLInputElement).value) || 15;
    if (!name) return say('Give the node a name.', 'err');
    if (!projects.length) return say('Name at least one project this node may receive.', 'err');
    void (async () => {
      const a = await call('POST', '/api/nodes/tokens', {
        name,
        projects,
        ttl_secs: Math.round(mins * 60),
      });
      if (!a) return;
      const token = (a.body as { token?: string }).token ?? '';
      $('nodes-output').textContent = token;
      say(
        `Token for '${name}' (single use, ${mins} min). Put it in a file on the node and run: unv node enroll --hub URL --token-file FILE`,
      );
    })();
  };
  $('nodes-list').onclick = (ev) => {
    const btn = (ev.target as HTMLElement).closest<HTMLElement>('[data-node-act]');
    if (!btn) return;
    const act = btn.dataset.nodeAct;
    const card = btn.closest<HTMLElement>('[data-node-id]');
    const nodeId = card?.dataset.nodeId ?? '';
    if (!nodeId) return;
    if (act === 'review' || act === 'approve' || act === 'reject' || act === 'policy') {
      void approvalAction(act, btn, card);
    } else if (act === 'blast') {
      void blast(card?.dataset.nodeName ?? '');
    } else if (act === 'revoke') {
      void (async () => {
        const ok = await showConfirm(
          'Revoke this node? It stops receiving config at once. Files already written stay where they are.',
        );
        if (!ok) return;
        if (await call('DELETE', `/api/nodes/${encodeURIComponent(nodeId)}`)) await refreshNodes();
      })();
    } else if (act === 'pull') {
      void fetchFile(nodeId, btn.dataset.target ?? '');
    } else if (act === 'into-chunk') {
      void readIntoChunk(
        nodeId,
        btn.dataset.target ?? '',
        btn.dataset.project ?? '',
        btn.dataset.exporter ?? '',
      );
    } else if (act === 'accept') {
      void (async () => {
        const a = await call('POST', `/api/nodes/${encodeURIComponent(nodeId)}/accept`, {
          target: btn.dataset.target ?? '',
        });
        if (a) await refreshNodes();
      })();
    }
  };
}
