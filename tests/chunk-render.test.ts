/**
 * The remaining chunk-ops surface: clipboard formatting, the nginx↔certificate
 * linking helpers, and the chunk card renderer.
 *
 * `chunkToString` output is checked by round trip through the matching parser
 * where one exists — a copied config that a parser cannot read back is one the
 * server will not read either.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { st } from '../src/ts/state';
import {
  chunkToString, renderChunkCard,
  domainFromCertPath, nginxCertDomains, certEntryForDomain, ensureCertForDomain,
  redundantCertKeyChunkIds,
} from '../src/ts/chunk-ops';
import { parseWgConf, parseNginxConf, parseSshConfig } from '../src/ts/chunks/parsers';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

const chunk = (over: any) => ({ id: crypto.randomUUID(), fields: [], ...over });
const field = (c: any, key: string) => c.fields.find((f: any) => f.key === key);

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
});

describe('chunkToString — WireGuard', () => {
  const wg = (value: string) => chunk({
    name: 'Interface', chunk_type: 'wg_interface',
    fields: [
      { key: 'PrivateKey', value, field_type: 'secret', secret: true },
      { key: 'Address', value: '10.0.0.1/24', field_type: 'subnet' },
    ],
  });

  it('emits a section header and key = value lines', () => {
    const out = chunkToString(wg('rawkey'));
    expect(out.startsWith('[Interface]')).toBe(true);
    expect(out).toContain('PrivateKey = rawkey');
  });

  it('resolves a reference so the copied config is deployable', () => {
    // The only caller is copy-to-clipboard and it does not resolve, so this
    // pasted `PrivateKey = ${MyKey}` into wg0.conf and the tunnel stayed down.
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'MyKey', api_key: 'REAL_SECRET' })] });
    const out = chunkToString(wg('${MyKey/key}'));
    expect(out).toContain('PrivateKey = REAL_SECRET');
    expect(out).not.toContain('${');
  });

  it('round-trips through the WireGuard parser', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'MyKey', api_key: 'REAL_SECRET' })] });
    const reparsed = parseWgConf(chunkToString(wg('${MyKey}')));
    expect(field(reparsed[0], 'PrivateKey').value).toBe('REAL_SECRET');
  });

  it('labels a peer chunk correctly', () => {
    const out = chunkToString(chunk({
      name: 'Peer 1', chunk_type: 'wg_peer',
      fields: [{ key: 'PublicKey', value: 'pk', field_type: 'var' }],
    }));
    expect(out.startsWith('[Peer]')).toBe(true);
  });
});

describe('chunkToString — nginx', () => {
  const upstream = chunk({
    name: 'backend', chunk_type: 'nginx_upstream',
    fields: [{ key: 'server', value: '10.0.0.1:8080', field_type: 'endpoint' }],
  });

  it('emits an upstream block, not a server block', () => {
    // `upstream` was folded in with `server`, producing
    // `server { server 10.0.0.1:8080; }` — wrong directive, name dropped, and
    // nginx rejects it. exportNginx always got this right.
    const out = chunkToString(upstream);
    expect(out.startsWith('upstream backend {')).toBe(true);
    expect(out).toContain('    server 10.0.0.1:8080;');
  });

  it('round-trips an upstream through the nginx parser', () => {
    const reparsed = parseNginxConf(chunkToString(upstream));
    expect(reparsed).toHaveLength(1);
    expect(reparsed[0].chunk_type).toBe('nginx_upstream');
    expect(reparsed[0].name).toBe('backend');
  });

  it('emits a server block with no inline name', () => {
    const out = chunkToString(chunk({
      name: 'example.com:443', chunk_type: 'nginx_server',
      fields: [{ key: 'listen', value: '443 ssl', field_type: 'port' }],
    }));
    expect(out.startsWith('server {')).toBe(true);
  });

  it('emits a location block with its path', () => {
    const out = chunkToString(chunk({
      name: 'location /api', chunk_type: 'nginx_location',
      fields: [
        { key: 'path', value: '/api', field_type: 'var' },
        { key: 'proxy_pass', value: 'http://backend', field_type: 'endpoint' },
      ],
    }));
    expect(out.startsWith('location /api {')).toBe(true);
    expect(out).not.toContain('path /api;');
  });

  it('resolves a certificate reference', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'CertPath', api_key: '/etc/ssl/full.pem' })] });
    const out = chunkToString(chunk({
      name: 'srv', chunk_type: 'nginx_server',
      fields: [{ key: 'ssl_certificate', value: '${CertPath}', field_type: 'cert' }],
    }));
    expect(out).toContain('ssl_certificate /etc/ssl/full.pem;');
  });

  it('skips empty fields rather than emitting a bare directive', () => {
    const out = chunkToString(chunk({
      name: 'srv', chunk_type: 'nginx_server',
      fields: [
        { key: 'listen', value: '80', field_type: 'port' },
        { key: 'root', value: '', field_type: 'var' },
      ],
    }));
    expect(out).not.toContain('root ;');
  });
});

describe('chunkToString — other types', () => {
  it('round-trips an ssh host through the ssh parser', () => {
    const out = chunkToString(chunk({
      name: 'prod', chunk_type: 'ssh_host',
      fields: [{ key: 'HostName', value: '10.0.0.1', field_type: 'var' }],
    }));
    const reparsed = parseSshConfig(out);
    expect(reparsed[0].name).toBe('prod');
    expect(field(reparsed[0], 'HostName').value).toBe('10.0.0.1');
  });

  it('resolves references in an env_file chunk', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'DbPass', api_key: 's3cret' })] });
    const out = chunkToString(chunk({
      name: '.env', chunk_type: 'env_file',
      fields: [{ key: 'DB_PASSWORD', value: '${DbPass}', field_type: 'env_var' }],
    }));
    expect(out).toBe('DB_PASSWORD=s3cret');
  });

  it('returns the raw PEM for an nginx_key chunk', () => {
    const pem = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----';
    const out = chunkToString(chunk({
      name: 'fullchain', chunk_type: 'nginx_key',
      fields: [{ key: 'content', value: pem, field_type: 'cert' }],
    }));
    expect(out).toBe(pem);
  });

  it('emits key: value for a k8s chunk', () => {
    const out = chunkToString(chunk({
      name: 'api', chunk_type: 'k8s_service',
      fields: [{ key: 'port', value: '80', field_type: 'port' }],
    }));
    expect(out).toBe('port: 80');
  });
});

describe('domainFromCertPath', () => {
  it.each([
    ['/etc/letsencrypt/live/example.com/fullchain.pem', 'example.com'],
    ['/etc/letsencrypt/live/www.example.com/privkey.pem', 'example.com'],
    ['/etc/ssl/example.com/fullchain.pem', 'example.com'],
  ])('%s -> %s', (path, expected) => {
    expect(domainFromCertPath(path)).toBe(expected);
  });

  it('returns null for a path with no domain in it', () => {
    expect(domainFromCertPath('/etc/ssl/certs/ca-bundle.crt')).toBeNull();
  });
});

describe('nginxCertDomains', () => {
  it('collects domains from server_name and certificate paths', () => {
    const proj = makeProject({
      id: 'p1', name: 'Web',
      chunks: [chunk({
        name: 'srv', chunk_type: 'nginx_server',
        fields: [
          { key: 'server_name', value: 'example.com www.example.com', field_type: 'var' },
          { key: 'ssl_certificate', value: '/etc/letsencrypt/live/other.org/fullchain.pem', field_type: 'cert' },
        ],
      })],
    } as any);
    expect(nginxCertDomains(proj).sort()).toEqual(['example.com', 'other.org']);
  });

  it('folds www. and the bare domain into one entry', () => {
    const proj = makeProject({
      id: 'p1', name: 'Web',
      chunks: [chunk({
        name: 'srv', chunk_type: 'nginx_server',
        fields: [{ key: 'server_name', value: 'www.example.com example.com', field_type: 'var' }],
      })],
    } as any);
    expect(nginxCertDomains(proj)).toEqual(['example.com']);
  });

  it('ignores a project name that is not a domain', () => {
    const proj = makeProject({ id: 'p1', name: 'My Web Stack', chunks: [] } as any);
    expect(nginxCertDomains(proj)).toEqual([]);
  });

  it('picks up a wildcard server_name without its star', () => {
    const proj = makeProject({
      id: 'p1', name: 'Web',
      chunks: [chunk({
        name: 'srv', chunk_type: 'nginx_server',
        fields: [{ key: 'server_name', value: '*.example.com', field_type: 'var' }],
      })],
    } as any);
    expect(nginxCertDomains(proj)).toEqual(['example.com']);
  });
});

describe('certEntryForDomain / ensureCertForDomain', () => {
  it('finds an existing certificate entry regardless of www', () => {
    st.vault = makeVault({
      api_keys: [makeEntry({ provider: 'www.example.com', secretType: 'certificate' })],
    });
    expect(certEntryForDomain('example.com')).not.toBeNull();
  });

  it('ignores a non-certificate entry with the same name', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'example.com', secretType: 'api_key' })] });
    expect(certEntryForDomain('example.com')).toBeNull();
  });

  it('creates a stub certificate entry when none exists', () => {
    st.vault = makeVault({ api_keys: [] });
    const entry = ensureCertForDomain('example.com', 'p1');
    expect(entry.secretType).toBe('certificate');
    expect(entry.provider).toBe('example.com');
    expect(entry.projectIds).toEqual(['Universal', 'p1']);
    expect(st.vault.api_keys).toHaveLength(1);
  });

  it('does not create a second entry for a domain it already has', () => {
    st.vault = makeVault({ api_keys: [] });
    ensureCertForDomain('example.com');
    ensureCertForDomain('www.example.com');
    expect(st.vault.api_keys).toHaveLength(1);
  });
});

describe('redundantCertKeyChunkIds', () => {
  it('flags an nginx_key chunk whose PEM duplicates the vault entry', () => {
    const pem = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----';
    st.vault = makeVault({
      api_keys: [makeEntry({ provider: 'example.com', secretType: 'certificate', certificate_data: pem })],
    });
    const proj = makeProject({
      id: 'p1', name: 'Web',
      chunks: [
        chunk({ id: 'dup', name: 'fullchain', chunk_type: 'nginx_key', fields: [{ key: 'content', value: pem, field_type: 'cert' }] }),
        chunk({ id: 'srv', name: 'srv', chunk_type: 'nginx_server', fields: [{ key: 'server_name', value: 'example.com', field_type: 'var' }] }),
      ],
    } as any);
    expect(redundantCertKeyChunkIds(proj)).toEqual(['dup']);
  });

  it('does not flag a chunk holding different content', () => {
    st.vault = makeVault({
      api_keys: [makeEntry({ provider: 'example.com', secretType: 'certificate', certificate_data: 'AAA' })],
    });
    const proj = makeProject({
      id: 'p1', name: 'Web',
      chunks: [
        chunk({ id: 'other', name: 'k', chunk_type: 'nginx_key', fields: [{ key: 'content', value: 'BBB', field_type: 'cert' }] }),
        chunk({ id: 'srv', name: 'srv', chunk_type: 'nginx_server', fields: [{ key: 'server_name', value: 'example.com', field_type: 'var' }] }),
      ],
    } as any);
    expect(redundantCertKeyChunkIds(proj)).toEqual([]);
  });

  it('returns nothing when no certificate entry exists', () => {
    st.vault = makeVault({ api_keys: [] });
    const proj = makeProject({
      id: 'p1', name: 'Web',
      chunks: [chunk({ id: 'k', name: 'k', chunk_type: 'nginx_key', fields: [{ key: 'content', value: 'AAA', field_type: 'cert' }] })],
    } as any);
    expect(redundantCertKeyChunkIds(proj)).toEqual([]);
  });
});

describe('renderChunkCard', () => {
  const proj = () => makeProject({ id: 'p1', name: 'Web' } as any);

  it('masks a secret field rather than printing it', () => {
    const card = renderChunkCard(chunk({
      name: 'Interface', chunk_type: 'wg_interface',
      fields: [{ key: 'PrivateKey', value: 'SUPER_SECRET_KEY', field_type: 'secret', secret: true }],
    }), proj());
    expect(card.textContent).not.toContain('SUPER_SECRET_KEY');
    expect(card.textContent).toContain('••');
  });

  it('carries the real value in data-value so copy still works', () => {
    const card = renderChunkCard(chunk({
      name: '.env', chunk_type: 'env_file',
      fields: [{ key: 'TOKEN', value: 'tok-123', field_type: 'var' }],
    }), proj());
    const copyBtn = card.querySelector('[data-action="chunk-copy"]')!;
    expect(copyBtn.getAttribute('data-value')).toBe('TOKEN=tok-123');
  });

  it('marks an unresolved reference as unresolved', () => {
    st.vault = makeVault({ api_keys: [] });
    const card = renderChunkCard(chunk({
      name: '.env', chunk_type: 'env_file',
      fields: [{ key: 'TOKEN', value: '${Missing}', field_type: 'env_var' }],
    }), proj());
    expect(card.querySelector('.chunk-ref-unresolved')).not.toBeNull();
    expect(card.textContent).toContain('Missing');
  });

  it('shows a resolved reference as a vault link without revealing the secret', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'Tok', api_key: 'real-secret' })] });
    const card = renderChunkCard(chunk({
      name: '.env', chunk_type: 'env_file',
      fields: [{ key: 'TOKEN', value: '${Tok}', field_type: 'env_var' }],
    }), proj());
    expect(card.querySelector('.chunk-ref-jump')).not.toBeNull();
    expect(card.textContent).not.toContain('real-secret');
  });

  it('does not execute markup in a field key or value', () => {
    const card = renderChunkCard(chunk({
      name: '<img src=x onerror=alert(1)>', chunk_type: 'env_file',
      fields: [{ key: '<img src=y onerror=alert(2)>', value: '<script>alert(3)</script>', field_type: 'var' }],
    }), proj());
    expect(card.querySelector('img')).toBeNull();
    expect(card.querySelector('script')).toBeNull();
  });

  it('marks a disabled chunk', () => {
    const card = renderChunkCard(chunk({ name: 'x', chunk_type: 'env_file', disabled: true }), proj());
    expect(card.className).toContain('chunk-disabled');
  });
});
