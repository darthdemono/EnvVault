import { describe, expect, it } from 'vitest';
import { applyRestore, canRestore, describePlan, planRestore } from '../src/ts/restore-chunks';
import type { Project } from '../src/ts/types';

const WG = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.0.0.2/32
`;

function project(): Project {
  return {
    id: 'p',
    name: 'p',
    project_type: 'wireguard',
    chunks: [
      { id: 'keep', chunk_type: 'generic', label: 'note', fields: [] },
      { id: 'old', chunk_type: 'wg_peer', label: 'stale', fields: [] },
    ],
  } as unknown as Project;
}

describe('restore into chunks', () => {
  it('knows which formats it can read', () => {
    expect(canRestore('wireguard')).toBe(true);
    expect(canRestore('env')).toBe(false);
  });

  it('replaces the format family and keeps unrelated chunks', () => {
    const p = project();
    const plan = planRestore(p, 'wireguard', WG);
    expect(plan).not.toBeNull();
    expect(plan!.parsed.length).toBe(2);
    expect(plan!.replaced.length).toBe(1);
    expect(describePlan(plan!)).toMatch(/1/);
    applyRestore(p, plan!);
    expect(p.chunks!.map((c) => c.id)).toContain('keep');
    expect(p.chunks!.some((c) => c.id === 'old')).toBe(false);
    expect(p.chunks!.filter((c) => c.chunk_type === 'wg_peer').length).toBe(1);
  });

  it('refuses an unknown exporter', () => {
    expect(planRestore(project(), 'env', 'A=1')).toBeNull();
  });
});
