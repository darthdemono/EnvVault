/**
 * Config export functions.
 *
 * These produce files the user pastes onto a server, so the bar is that what
 * comes out is valid and carries the *resolved* secret — a `${…}` placeholder
 * reaching a wg0.conf or a Kubernetes Secret is a broken deploy, and a silently
 * mis-encoded one is worse.
 *
 * Where a parser exists for the same format, the export is checked by round
 * trip rather than by string matching.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { st } from '../src/ts/state';
import {
  exportWireGuard, exportDockerCompose, exportK8s, exportSshConfig, exportNginx,
} from '../src/ts/chunk-ops';
import { parseWgConf, parseSshConfig, parseNginxConf, parseDockerCompose } from '../src/ts/chunks/parsers';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

const chunk = (over: any) => ({ id: crypto.randomUUID(), fields: [], ...over });
const field = (c: any, key: string) => c.fields.find((f: any) => f.key === key);

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
});

describe('exportWireGuard', () => {
  function projectWith(value: string) {
    return makeProject({
      id: 'p1', name: 'VPN', project_type: 'wireguard',
      chunks: [chunk({
        name: 'Interface', chunk_type: 'wg_interface',
        fields: [
          { key: 'PrivateKey', value, field_type: 'secret', secret: true },
          { key: 'Address', value: '10.0.0.1/24', field_type: 'subnet' },
        ],
      })],
    } as any);
  }

  it('emits section headers and key = value lines', () => {
    const out = exportWireGuard(projectWith('rawkey'));
    expect(out).toContain('[Interface]');
    expect(out).toContain('PrivateKey = rawkey');
    expect(out).toContain('Address = 10.0.0.1/24');
  });

  it('resolves a bare ${Provider} reference', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'WgKey', api_key: 'SECRET_A' })] });
    expect(exportWireGuard(projectWith('${WgKey}'))).toContain('PrivateKey = SECRET_A');
  });

  it('resolves a ${Provider/field} reference', () => {
    // The hand-rolled matcher understood only the bare form, so this shape was
    // written out as literal ${…} text and WireGuard rejected the config.
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'WgKey', api_key: 'SECRET_B' })] });
    const out = exportWireGuard(projectWith('${WgKey/key}'));
    expect(out).toContain('PrivateKey = SECRET_B');
    expect(out).not.toContain('${');
  });

  it('resolves a ${Provider_KeyId} reference', () => {
    st.vault = makeVault({
      api_keys: [makeEntry({ provider: 'Wg', key_id: 'prod', api_key: 'SECRET_C' })],
    });
    expect(exportWireGuard(projectWith('${Wg_prod}'))).toContain('PrivateKey = SECRET_C');
  });

  it('leaves an unresolvable reference visible rather than emitting a blank key', () => {
    st.vault = makeVault({ api_keys: [] });
    expect(exportWireGuard(projectWith('${Missing}'))).toContain('PrivateKey = ${Missing}');
  });

  it('round-trips through the WireGuard parser', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'WgKey', api_key: 'SECRET_D' })] });
    const reparsed = parseWgConf(exportWireGuard(projectWith('${WgKey/key}')));
    expect(reparsed[0].chunk_type).toBe('wg_interface');
    expect(field(reparsed[0], 'PrivateKey').value).toBe('SECRET_D');
    expect(field(reparsed[0], 'PrivateKey').secret).toBe(true);
  });

  it('skips empty fields', () => {
    const proj = projectWith('k');
    (proj as any).chunks[0].fields.push({ key: 'DNS', value: '', field_type: 'ip' });
    expect(exportWireGuard(proj)).not.toContain('DNS');
  });
});

describe('exportDockerCompose', () => {
  function projectWith(envValue: string) {
    return makeProject({
      id: 'p1', name: 'Stack', project_type: 'docker',
      chunks: [chunk({
        name: 'web', chunk_type: 'docker_service',
        fields: [
          { key: 'image', value: 'nginx:alpine', field_type: 'var' },
          { key: 'ports', value: '80:80', field_type: 'port' },
          { key: 'DB_PASSWORD', value: envValue, field_type: 'env_var', description: 'env' },
        ],
      })],
    } as any);
  }

  it('emits a services block with the scalar fields', () => {
    const { yaml } = exportDockerCompose(projectWith('plain'));
    expect(yaml).toContain('services:');
    expect(yaml).toContain('  web:');
    // Quoted because the value contains a colon — valid YAML either way, and
    // the parser strips the quotes back off (see the round-trip test below).
    expect(yaml).toContain('    image: "nginx:alpine"');
  });

  it('writes a resolved ${Provider/field} secret into the .env side file', () => {
    // Only the bare ${PROVIDER} form resolved before, so any other shape wrote
    // an empty value and the container came up with a blank secret.
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'DbPass', api_key: 'p@ssw0rd' })] });
    const { yaml, envFile } = exportDockerCompose(projectWith('${DbPass/key}'));
    expect(envFile).toContain('DB_PASSWORD=p@ssw0rd');
    expect(yaml).toContain('- DB_PASSWORD=${DB_PASSWORD}');
  });

  it('uses a shell-safe variable name for compose substitution', () => {
    // Compose only substitutes valid identifiers; a raw `Provider/field` is not
    // one, so it would never have been substituted at all.
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'DbPass', api_key: 'x' })] });
    const { yaml, envFile } = exportDockerCompose(projectWith('${DbPass/key}'));
    expect(yaml).not.toContain('/');
    expect(envFile.split('\n')[0]).toMatch(/^[A-Z0-9_]+=/);
  });

  it('resolves a bare reference too', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'DbPass', api_key: 'bare-ok' })] });
    expect(exportDockerCompose(projectWith('${DbPass}')).envFile).toContain('bare-ok');
  });

  it('passes a literal env value straight through', () => {
    const { yaml } = exportDockerCompose(projectWith('literal-value'));
    expect(yaml).toContain('- DB_PASSWORD=literal-value');
  });

  it('quotes port entries so YAML keeps them as strings', () => {
    const { yaml } = exportDockerCompose(projectWith('x'));
    expect(yaml).toContain('      - "80:80"');
  });

  it('round-trips the service through the compose parser', () => {
    const { yaml } = exportDockerCompose(projectWith('literal-value'));
    const reparsed = parseDockerCompose(yaml);
    const web = reparsed.find(c => c.chunk_type === 'docker_service')!;
    expect(web.name).toBe('web');
    expect(field(web, 'image').value).toBe('nginx:alpine');
  });
});

describe('exportK8s', () => {
  function secretProject(value: string) {
    return makeProject({
      id: 'p1', name: 'K8s', project_type: 'kubernetes',
      chunks: [chunk({
        name: 'app-secret', chunk_type: 'k8s_secret',
        fields: [
          { key: 'name', value: 'app-secret', field_type: 'var' },
          { key: 'DB_PASSWORD', value, field_type: 'secret', secret: true },
        ],
      })],
    } as any);
  }

  const dataValue = (manifest: string) =>
    manifest.split('\n').find(l => l.trim().startsWith('DB_PASSWORD:'))!.split(': ')[1];

  it('base64-encodes an ASCII secret', () => {
    const out = exportK8s(secretProject('hunter2'));
    expect(out).toContain('kind: Secret');
    expect(dataValue(out)).toBe(Buffer.from('hunter2', 'utf8').toString('base64'));
  });

  it('does not throw on a secret containing characters outside Latin-1', () => {
    // btoa threw InvalidCharacterError above U+00FF, taking the whole export
    // down rather than the one field.
    const out = exportK8s(secretProject('pass🔑word'));
    expect(dataValue(out)).toBe(Buffer.from('pass🔑word', 'utf8').toString('base64'));
  });

  it('encodes accented characters as UTF-8, not Latin-1', () => {
    // btoa encoded the Latin-1 byte, so the cluster decoded a different secret
    // than the one stored — wrong, and silently so.
    const out = exportK8s(secretProject('café'));
    expect(dataValue(out)).toBe(Buffer.from('café', 'utf8').toString('base64'));
    expect(dataValue(out)).not.toBe('Y2Fm6Q==');   // the old Latin-1 output
  });

  it('resolves a reference before encoding it', () => {
    // A field holding ${DB_PASSWORD} was base64'd literally, shipping the
    // placeholder text to the cluster as if it were the secret.
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'DbPass', api_key: 'resolved-secret' })] });
    const out = exportK8s(secretProject('${DbPass/key}'));
    expect(dataValue(out)).toBe(Buffer.from('resolved-secret', 'utf8').toString('base64'));
  });

  it('emits a deployment manifest', () => {
    const proj = makeProject({
      id: 'p1', name: 'K8s', project_type: 'kubernetes',
      chunks: [chunk({
        name: 'api', chunk_type: 'k8s_deployment',
        fields: [
          { key: 'name', value: 'api', field_type: 'var' },
          { key: 'image', value: 'api:1.2.3', field_type: 'var' },
          { key: 'replicas', value: '3', field_type: 'var' },
        ],
      })],
    } as any);
    const out = exportK8s(proj);
    expect(out).toContain('kind: Deployment');
    expect(out).toContain('replicas: 3');
    expect(out).toContain('image: api:1.2.3');
  });

  it('separates multiple manifests with a document marker', () => {
    const proj = makeProject({
      id: 'p1', name: 'K8s', project_type: 'kubernetes',
      chunks: [
        chunk({ name: 'a', chunk_type: 'k8s_service', fields: [{ key: 'name', value: 'a', field_type: 'var' }] }),
        chunk({ name: 'b', chunk_type: 'k8s_service', fields: [{ key: 'name', value: 'b', field_type: 'var' }] }),
      ],
    } as any);
    expect(exportK8s(proj).split('\n---\n')).toHaveLength(2);
  });
});

describe('exportSshConfig', () => {
  it('round-trips through the ssh_config parser', () => {
    const proj = makeProject({
      id: 'p1', name: 'Hosts', project_type: 'ssh_config',
      chunks: [chunk({
        name: 'prod', chunk_type: 'ssh_host',
        fields: [
          { key: 'HostName', value: '10.0.0.1', field_type: 'var' },
          { key: 'User', value: 'deploy', field_type: 'var' },
        ],
      })],
    } as any);
    const reparsed = parseSshConfig(exportSshConfig(proj));
    expect(reparsed).toHaveLength(1);
    expect(reparsed[0].name).toBe('prod');
    expect(field(reparsed[0], 'User').value).toBe('deploy');
  });
});

describe('exportNginx', () => {
  it('round-trips a server block through the nginx parser', () => {
    const proj = makeProject({
      id: 'p1', name: 'Web', project_type: 'nginx',
      chunks: [chunk({
        name: 'example.com:443', chunk_type: 'nginx_server',
        fields: [
          { key: 'listen', value: '443 ssl', field_type: 'port' },
          { key: 'server_name', value: 'example.com', field_type: 'var' },
          { key: 'root', value: '/var/www/html', field_type: 'var' },
        ],
      })],
    } as any);
    const reparsed = parseNginxConf(exportNginx(proj));
    const server = reparsed.find(c => c.chunk_type === 'nginx_server')!;
    expect(server).toBeDefined();
    expect(field(server, 'server_name').value).toBe('example.com');
    expect(field(server, 'root').value).toBe('/var/www/html');
  });
});

describe('disabled chunks are excluded from exports', () => {
  // A disabled chunk is greyed out in the config view and documented as
  // "excluded from exports". Only the four later exporters (apache, haproxy,
  // ansible, postgres) actually checked the flag, so the four people deploy
  // shipped disabled chunks anyway: turning a WireGuard peer off left the
  // tunnel trusting a peer the user believed they had removed, and a disabled
  // Compose service still came up.
  const withDisabled = (type: any, chunkType: string, fields: any[]) =>
    makeProject({
      id: 'p1', name: 'P', project_type: type,
      chunks: [
        chunk({ name: 'live', chunk_type: chunkType, fields }),
        chunk({ name: 'off', chunk_type: chunkType, disabled: true, fields: [
          { key: fields[0].key, value: 'NEVER_EXPORTED', field_type: 'var' },
        ] }),
      ],
    } as any);

  it('exportWireGuard skips them', () => {
    const proj = withDisabled('wireguard', 'wg_peer', [
      { key: 'PublicKey', value: 'LIVE_KEY', field_type: 'var' },
    ]);
    const out = exportWireGuard(proj);
    expect(out).toContain('LIVE_KEY');
    expect(out).not.toContain('NEVER_EXPORTED');
  });

  it('exportDockerCompose skips them', () => {
    const proj = withDisabled('docker', 'docker_service', [
      { key: 'image', value: 'nginx:alpine', field_type: 'var' },
    ]);
    const { yaml } = exportDockerCompose(proj);
    expect(yaml).toContain('nginx:alpine');
    expect(yaml).not.toContain('NEVER_EXPORTED');
  });

  it('exportNginx skips them', () => {
    const proj = withDisabled('nginx', 'nginx_server', [
      { key: 'server_name', value: 'live.example.com', field_type: 'var' },
    ]);
    const out = exportNginx(proj);
    expect(out).toContain('live.example.com');
    expect(out).not.toContain('NEVER_EXPORTED');
  });
});

describe('exportNginx resolves references', () => {
  it('writes the certificate path, not the ${…} placeholder', () => {
    // This exporter interpolated the raw field value while every other one
    // resolved. The nginx starter template ships `ssl_certificate ${…}` fields,
    // so the generated config reached nginx with literal placeholder text and
    // the server refused to start — while copying the same chunk from its card
    // resolved correctly, so the two disagreed about what the config said.
    st.vault = makeVault({
      api_keys: [makeEntry({ provider: 'TLS', api_key: '/etc/ssl/fullchain.pem' })],
    });
    const proj = makeProject({
      id: 'p1', name: 'Web', project_type: 'nginx',
      chunks: [chunk({
        name: 'HTTPS', chunk_type: 'nginx_server',
        fields: [
          { key: 'listen', value: '443 ssl', field_type: 'port' },
          { key: 'ssl_certificate', value: '${TLS}', field_type: 'cert' },
        ],
      })],
    } as any);
    const out = exportNginx(proj);
    expect(out).toContain('ssl_certificate /etc/ssl/fullchain.pem;');
    expect(out).not.toContain('${');
  });
});
