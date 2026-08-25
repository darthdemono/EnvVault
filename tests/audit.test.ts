/**
 * Audit log hash chain.
 *
 * The whole point of the chain is tamper evidence, so these build real chains
 * with the same hash the backend uses, then tamper with them in each of the
 * ways an attacker actually would.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import type { AuditRow } from '../src/ts/types';
import { verifyChain, resetAuditPanel } from '../src/ts/audit';
import { loadRealIndexHtml } from './helpers';

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Builds a valid chain the way `compute_audit_hash` in vault-core does. */
async function buildChain(
  specs: { action: string; provider: string; actor?: string }[],
): Promise<AuditRow[]> {
  const rows: AuditRow[] = [];
  let prev: string | null = null;
  for (let i = 0; i < specs.length; i++) {
    const s = specs[i];
    const timestamp = `2024-01-0${i + 1}T00:00:00Z`;
    const prevForHash: string = prev ?? 'genesis';
    const entry_hash: string = s.actor
      ? await sha256Hex(`${s.action}|${s.provider}|${timestamp}|${s.actor}|${prevForHash}`)
      : await sha256Hex(`${s.action}|${s.provider}|${timestamp}|${prevForHash}`);
    rows.push({
      id: i + 1,
      action: s.action,
      entry_provider: s.provider,
      timestamp,
      details: null,
      actor: s.actor ?? null,
      prev_hash: prev,
      entry_hash,
    } as AuditRow);
    prev = entry_hash;
  }
  return rows;
}

const FIVE = [
  { action: 'add', provider: 'Alpha' },
  { action: 'add', provider: 'Bravo' },
  { action: 'update', provider: 'Bravo' },
  { action: 'delete', provider: 'Alpha' },
  { action: 'add', provider: 'Charlie' },
];

beforeEach(async () => {
  loadRealIndexHtml();
  // The audit pane is injected at runtime, not shipped in index.html.
  const markup = await import('../src/ts/tools-markup');
  markup.mountToolsPanes();
});

describe('verifyChain — intact chains', () => {
  it('accepts a well-formed chain', async () => {
    const result = await verifyChain(await buildChain(FIVE));
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(5);
    expect(result.brokenAt).toBeNull();
  });

  it('accepts a chain that binds an actor into each row', async () => {
    const rows = await buildChain(FIVE.map((s) => ({ ...s, actor: 'alice' })));
    expect((await verifyChain(rows)).ok).toBe(true);
  });

  it('does not care what order the rows arrive in', async () => {
    const rows = await buildChain(FIVE);
    expect((await verifyChain([...rows].reverse())).ok).toBe(true);
  });

  it('reports nothing to verify when no row carries a hash', async () => {
    const legacy = [
      {
        id: 1,
        action: 'add',
        entry_provider: 'X',
        timestamp: 't',
        details: null,
        actor: null,
        prev_hash: null,
        entry_hash: null,
      },
    ] as any;
    const result = await verifyChain(legacy);
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(0);
  });
});

describe('verifyChain — tampering', () => {
  it('catches an edited row', async () => {
    const rows = await buildChain(FIVE);
    rows[2].entry_provider = 'Rewritten';
    const result = await verifyChain(rows);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(3);
  });

  it('catches an altered timestamp', async () => {
    const rows = await buildChain(FIVE);
    rows[1].timestamp = '1999-01-01T00:00:00Z';
    expect((await verifyChain(rows)).ok).toBe(false);
  });

  it('catches a row deleted from the middle', async () => {
    const rows = await buildChain(FIVE);
    rows.splice(2, 1);
    expect((await verifyChain(rows)).ok).toBe(false);
  });

  it('catches rows deleted from the START of the log', async () => {
    // This verified clean before: the surviving first row still hashed
    // correctly over its own stored prev_hash, and the link check is skipped on
    // the first iteration because there is no predecessor to compare to. The
    // most useful thing to erase from an append-only log was the one edit it
    // could not see.
    const rows = await buildChain(FIVE);
    const truncated = rows.slice(2);
    const result = await verifyChain(truncated);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/removed/i);
  });

  it('catches removal of just the genesis row', async () => {
    const rows = await buildChain(FIVE);
    expect((await verifyChain(rows.slice(1))).ok).toBe(false);
  });

  it('catches an appended row that was not properly chained', async () => {
    const rows = await buildChain(FIVE);
    rows.push({
      id: 6,
      action: 'delete',
      entry_provider: 'Charlie',
      timestamp: '2024-02-01T00:00:00Z',
      details: null,
      actor: null,
      prev_hash: 'made-up',
      entry_hash: 'also-made-up',
    } as AuditRow);
    expect((await verifyChain(rows)).ok).toBe(false);
  });

  it('catches an actor swapped out of a row', async () => {
    const rows = await buildChain(FIVE.map((s) => ({ ...s, actor: 'alice' })));
    rows[3].actor = 'mallory';
    expect((await verifyChain(rows)).ok).toBe(false);
  });

  it('catches stripping the actor to fall back to the older hash format', async () => {
    const rows = await buildChain(FIVE.map((s) => ({ ...s, actor: 'alice' })));
    rows[3].actor = null;
    expect((await verifyChain(rows)).ok).toBe(false);
  });

  it('accepts a truncation that leaves a genuine genesis row first', async () => {
    // Sanity check on the new rule: a chain whose first row legitimately has no
    // predecessor must still pass.
    const rows = await buildChain(FIVE);
    expect((await verifyChain(rows.slice(0, 3))).ok).toBe(true);
  });
});

describe('resetAuditPanel', () => {
  it('clears rows rendered from a previous vault', () => {
    // _rows outlived a vault switch, so Verify reported on the old vault's log
    // and Export copied it to the clipboard.
    document.getElementById('audit-results')!.innerHTML = '<table>old vault rows</table>';
    document.getElementById('audit-count')!.textContent = '42 entries';
    resetAuditPanel();
    expect(document.getElementById('audit-results')!.innerHTML).toBe('');
    expect(document.getElementById('audit-count')!.textContent).toBe('');
  });

  it('hides a status line left over from the previous vault', () => {
    const status = document.getElementById('audit-status')!;
    status.style.display = '';
    status.textContent = '✓ Chain intact';
    resetAuditPanel();
    expect(status.style.display).toBe('none');
  });
});
