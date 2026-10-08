/**
 * Tools -> Unique IDs (Phase 33.4): the app side of `envv uid ...`, over the
 * server's `/api/uid/*` routes (Phase 24.4). The registry is server-side only, so
 * this works against a remote vault; against a local one the pane says so instead
 * of sitting there.
 *
 * Every button answers: the status line carries the HTTP status and, for a rate
 * limit, the wait the server asked for. A minted ID is shown once in the output
 * and is not stored anywhere in the app.
 */
import { RemoteVaultStore, st } from './state';
import { showConfirm, showToast } from './utils';

const $ = (id: string) => document.getElementById(id)!;

function lines(): string[] {
  return ($('uid-values') as HTMLTextAreaElement).value
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

function say(msg: string, kind: 'ok' | 'err' = 'ok'): void {
  const el = $('uid-status');
  el.textContent = msg;
  el.className = `tool-status ${kind}`;
}

async function call(method: 'GET' | 'POST', path: string, body?: unknown): Promise<void> {
  if (!(st.store instanceof RemoteVaultStore)) {
    say('The unique-ID registry lives on a server. Connect to a remote vault first.', 'err');
    return;
  }
  say('Working…');
  try {
    const { status, body: out } = await st.store.uidRequest(method, path, body);
    $('uid-output').textContent = out === null ? '' : JSON.stringify(out, null, 2);
    if (status >= 200 && status < 300) say(`OK (${status})`);
    else if (status === 404) say('Not found: is the server running with --uid-registry?', 'err');
    else if (status === 429)
      say('Rate limited. Wait and try again; the response says how long.', 'err');
    else if (status === 403) say('Your account lacks the capability for this call.', 'err');
    else say(`Refused (${status})`, 'err');
  } catch (e) {
    say(`Could not reach the server: ${e instanceof Error ? e.message : String(e)}`, 'err');
  }
}

export function initUidPane(): void {
  if (!document.getElementById('uid-mint-btn')) return;
  $('uid-mint-btn').onclick = () => {
    const length = Number(($('uid-length') as HTMLInputElement).value) || 32;
    const namespace = ($('uid-namespace') as HTMLInputElement).value.trim();
    void call('POST', '/api/uid/mint', { length, ...(namespace ? { namespace } : {}) });
  };
  $('uid-stats-btn').onclick = () => void call('GET', '/api/uid/stats');
  $('uid-check-btn').onclick = () => {
    const values = lines();
    if (!values.length) return say('Enter at least one value.', 'err');
    void call('POST', '/api/uid/check', { values });
  };
  $('uid-lookup-btn').onclick = () => {
    const [value] = lines();
    if (!value) return say('Enter a value to look up.', 'err');
    void call('POST', '/api/uid/lookup', { value });
  };
  const pruneBefore = () => ($('uid-prune-before') as HTMLInputElement).value;
  $('uid-prune-dry-btn').onclick = () => {
    if (!pruneBefore()) return say('Pick a date first.', 'err');
    void call('POST', '/api/uid/prune', { before: pruneBefore(), dry_run: true });
  };
  $('uid-prune-btn').onclick = () => {
    if (!pruneBefore()) return say('Pick a date first.', 'err');
    void (async () => {
      const ok = await showConfirm(
        `Delete every registry record before ${pruneBefore()}? A pruned ID can be issued again without a collision being detected. Run the dry run first.`,
      );
      if (!ok) return;
      await call('POST', '/api/uid/prune', { before: pruneBefore(), dry_run: false });
      showToast('Prune requested', 'ok', 1500);
    })();
  };
}
