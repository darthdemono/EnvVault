import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { st } from '../src/ts/state';
import { exportK8s } from '../src/ts/chunk-ops';
import { loadRealIndexHtml, resetState } from './helpers';

const HERE = dirname(fileURLToPath(import.meta.url));
const vaultFixture = JSON.parse(
  readFileSync(join(HERE, 'fixtures', 'parity', 'vault.json'), 'utf8'),
);

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  st.vault = JSON.parse(JSON.stringify(vaultFixture));
});

describe('k8s Secret encoding', () => {
  it('base64-encodes non-ASCII as UTF-8, not Latin-1', () => {
    // `btoa` is Latin-1 and throws (or mangles) above U+00FF. A Secret whose
    // value contains a non-ASCII character must still decode correctly *in the
    // cluster* — this is asserted against a real k3s apply in Phase 18.
    const p: any = st.vault.projects.find((x: any) => x.id === 'k8s');
    p.chunks[0].fields.push({
      key: 'UNICODE',
      value: 'pässwörd–日本語',
      field_type: 'secret',
      secret: true,
    });
    const out = exportK8s(p);
    const line = out.split('\n').find((l) => l.includes('UNICODE:'))!;
    const b64 = line.split(': ')[1].trim();
    expect(Buffer.from(b64, 'base64').toString('utf8')).toBe('pässwörd–日本語');
  });
});
