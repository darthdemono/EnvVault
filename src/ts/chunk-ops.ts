/**
 * @file Chunk operations — starter chunks, chunk card rendering,
 *       config exporters/parsers, chunk edit modal.
 */

import type { Project, SecretChunk, ChunkField, ChunkFieldType, ChunkType, ProjectType, VaultEntry } from './types';
import { st, Settings, triggerRender } from './state';
import { esc, escAttr, copySVG, editSVG, delSVG, showToast } from './utils';

// ── Starter chunk factories ────────────────────────────────────────────────

export function makeWgStarterChunks(): SecretChunk[] {
  return [
    {
      id: crypto.randomUUID(),
      name: 'Interface',
      chunk_type: 'wg_interface',
      fields: [
        { key: 'PrivateKey', value: '', field_type: 'secret', secret: true },
        { key: 'Address',    value: '', field_type: 'var' },
        { key: 'MTU',        value: '', field_type: 'var' },
        { key: 'Table',      value: '', field_type: 'var' },
        { key: 'DNS',        value: '', field_type: 'var' },
        { key: 'PostUp',     value: '', field_type: 'multiline' },
        { key: 'PostDown',   value: '', field_type: 'multiline' },
        { key: 'ListenPort', value: '', field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(),
      name: 'Peer',
      chunk_type: 'wg_peer',
      fields: [
        { key: 'PublicKey',            value: '', field_type: 'var' },
        { key: 'AllowedIPs',           value: '', field_type: 'var' },
        { key: 'Endpoint',             value: '', field_type: 'var' },
        { key: 'PersistentKeepalive',  value: '', field_type: 'var' },
        { key: 'PresharedKey',         value: '', field_type: 'secret', secret: true },
      ],
    },
  ];
}

export function makeDockerStarterChunks(): SecretChunk[] {
  return [
    {
      id: crypto.randomUUID(),
      name: 'service-1',
      chunk_type: 'docker_service',
      fields: [],
    },
    {
      id: crypto.randomUUID(),
      name: 'networks',
      chunk_type: 'docker_network',
      fields: [],
    },
    {
      id: crypto.randomUUID(),
      name: 'volumes',
      chunk_type: 'docker_volume',
      fields: [],
    },
  ];
}

export function makeNginxStarterChunks(): SecretChunk[] {
  return [
    {
      id: crypto.randomUUID(), name: 'HTTP :80 redirect', chunk_type: 'nginx_server',
      fields: [
        { key: 'listen',       value: '80',                                    field_type: 'port' },
        { key: 'listen',       value: '[::]:80',                               field_type: 'port', description: 'ipv6' },
        { key: 'server_name',  value: 'example.com www.example.com',           field_type: 'var' },
        { key: 'return',       value: '301 https://example.com$request_uri',   field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'HTTPS www redirect', chunk_type: 'nginx_server',
      fields: [
        { key: 'listen',              value: '443 ssl http2',                           field_type: 'port' },
        { key: 'listen',              value: '[::]:443 ssl http2',                      field_type: 'port', description: 'ipv6' },
        { key: 'server_name',         value: 'www.example.com',                         field_type: 'var' },
        { key: 'ssl_certificate',     value: '${example_cert}',                         field_type: 'cert' },
        { key: 'ssl_certificate_key', value: '${example_cert_key}',                     field_type: 'cert' },
        { key: 'return',              value: '301 https://example.com$request_uri',     field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'HTTPS :443 main', chunk_type: 'nginx_server',
      fields: [
        { key: 'listen',              value: '443 ssl http2',              field_type: 'port' },
        { key: 'listen',              value: '[::]:443 ssl http2',         field_type: 'port', description: 'ipv6' },
        { key: 'server_name',         value: 'example.com',                field_type: 'var' },
        { key: 'ssl_certificate',     value: '${example_cert}',            field_type: 'cert' },
        { key: 'ssl_certificate_key', value: '${example_cert_key}',        field_type: 'cert' },
        { key: 'root',                value: '/var/www/html',               field_type: 'var' },
        { key: 'index',               value: 'index.php index.html',        field_type: 'var' },
        { key: 'access_log',          value: '/var/log/nginx/access.log',   field_type: 'var' },
        { key: 'error_log',           value: '/var/log/nginx/error.log',    field_type: 'var' },
        { key: 'add_header X-Frame-Options',            value: '"SAMEORIGIN" always',                 field_type: 'var' },
        { key: 'add_header X-Content-Type-Options',     value: '"nosniff" always',                    field_type: 'var' },
        { key: 'add_header Strict-Transport-Security',  value: '"max-age=31536000; includeSubDomains; preload" always', field_type: 'var' },
        { key: 'gzip',                value: 'on',                          field_type: 'var' },
        { key: 'gzip_types',          value: 'text/plain text/css text/javascript application/javascript application/json', field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'location /', chunk_type: 'nginx_location',
      fields: [
        { key: 'path',      value: '/',                          field_type: 'var' },
        { key: 'try_files', value: '$uri $uri/ $uri.php?$args',  field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'location ~ .php', chunk_type: 'nginx_location',
      fields: [
        { key: 'path',         value: '~ \\.php$',                      field_type: 'var' },
        { key: 'include',      value: 'snippets/fastcgi-php.conf',       field_type: 'var' },
        { key: 'fastcgi_pass', value: 'unix:/run/php/php8.1-fpm.sock',   field_type: 'endpoint' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'location ~ assets', chunk_type: 'nginx_location',
      fields: [
        { key: 'path',          value: '~* \\.(jpg|jpeg|png|gif|webp|ico|css|js|svg|woff2)$', field_type: 'var' },
        { key: 'expires',       value: '30d',                           field_type: 'var' },
        { key: 'add_header Cache-Control', value: '"public, immutable"', field_type: 'var' },
        { key: 'access_log',    value: 'off',                           field_type: 'var' },
      ],
    },
  ];
}

export function makeK8sStarterChunks(): SecretChunk[] {
  return [
    {
      id: crypto.randomUUID(), name: 'Deployment', chunk_type: 'k8s_deployment',
      fields: [
        { key: 'name',          value: 'my-app',       field_type: 'var' },
        { key: 'namespace',     value: 'default',      field_type: 'var' },
        { key: 'image',         value: 'nginx:latest', field_type: 'var' },
        { key: 'replicas',      value: '1',            field_type: 'var' },
        { key: 'containerPort', value: '80',           field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'Service', chunk_type: 'k8s_service',
      fields: [
        { key: 'name',       value: 'my-app',    field_type: 'var' },
        { key: 'namespace',  value: 'default',   field_type: 'var' },
        { key: 'port',       value: '80',        field_type: 'var' },
        { key: 'targetPort', value: '80',        field_type: 'var' },
        { key: 'type',       value: 'ClusterIP', field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'Ingress', chunk_type: 'k8s_ingress',
      fields: [
        { key: 'name',        value: 'my-ingress',  field_type: 'var' },
        { key: 'namespace',   value: 'default',     field_type: 'var' },
        { key: 'host',        value: 'example.com', field_type: 'var' },
        { key: 'serviceName', value: 'my-app',      field_type: 'var' },
        { key: 'servicePort', value: '80',          field_type: 'var' },
      ],
    },
  ];
}

export function makeSshStarterChunks(): SecretChunk[] {
  return [
    {
      id: crypto.randomUUID(), name: 'server', chunk_type: 'ssh_host',
      fields: [
        { key: 'HostName',            value: 'server.example.com', field_type: 'var' },
        { key: 'User',                value: 'ubuntu',             field_type: 'var' },
        { key: 'Port',                value: '22',                 field_type: 'var' },
        { key: 'IdentityFile',        value: '~/.ssh/id_ed25519',  field_type: 'var' },
        { key: 'ServerAliveInterval', value: '60',                 field_type: 'var' },
        { key: 'ForwardAgent',        value: 'yes',                field_type: 'var' },
      ],
    },
  ];
}

export function makeTraefikStarterChunks(): SecretChunk[] {
  return [
    {
      id: crypto.randomUUID(), name: 'router-https', chunk_type: 'traefik_router',
      fields: [
        { key: 'entryPoints',  value: 'websecure',          field_type: 'list' },
        { key: 'rule',         value: 'Host(`example.com`)', field_type: 'var' },
        { key: 'service',      value: 'service-app',        field_type: 'var' },
        { key: 'certResolver', value: 'letsencrypt',        field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'service-app', chunk_type: 'traefik_service',
      fields: [
        { key: 'url',            value: 'http://app:8080', field_type: 'var' },
        { key: 'passHostHeader', value: 'true',            field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'redirect-to-https', chunk_type: 'traefik_middleware',
      fields: [
        { key: 'type',      value: 'redirectScheme', field_type: 'var' },
        { key: 'scheme',    value: 'https',          field_type: 'var' },
        { key: 'permanent', value: 'true',           field_type: 'var' },
      ],
    },
  ];
}

export function makeApacheStarterChunks(): SecretChunk[] {
  return [
    {
      id: crypto.randomUUID(), name: 'VirtualHost :80', chunk_type: 'apache_vhost',
      fields: [
        { key: 'ServerName',    value: 'example.com',         field_type: 'var' },
        { key: 'ServerAlias',   value: 'www.example.com',     field_type: 'var' },
        { key: 'DocumentRoot',  value: '/var/www/html',        field_type: 'var' },
        { key: 'ErrorLog',      value: '${APACHE_LOG_DIR}/error.log', field_type: 'var' },
        { key: 'CustomLog',     value: '${APACHE_LOG_DIR}/access.log combined', field_type: 'var' },
        { key: 'Redirect',      value: 'permanent / https://example.com/', field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'VirtualHost :443', chunk_type: 'apache_vhost',
      fields: [
        { key: 'ServerName',        value: 'example.com',         field_type: 'var' },
        { key: 'DocumentRoot',      value: '/var/www/html',        field_type: 'var' },
        { key: 'SSLEngine',         value: 'on',                   field_type: 'var' },
        { key: 'SSLCertificateFile',    value: '/etc/letsencrypt/live/example.com/fullchain.pem', field_type: 'cert' },
        { key: 'SSLCertificateKeyFile', value: '/etc/letsencrypt/live/example.com/privkey.pem',   field_type: 'cert' },
        { key: 'Header',            value: 'always set Strict-Transport-Security "max-age=31536000"', field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: '/var/www/html', chunk_type: 'apache_directory',
      fields: [
        { key: 'path',          value: '/var/www/html',       field_type: 'var' },
        { key: 'Options',       value: '-Indexes +FollowSymLinks', field_type: 'var' },
        { key: 'AllowOverride', value: 'All',                 field_type: 'var' },
        { key: 'Require',       value: 'all granted',         field_type: 'var' },
      ],
    },
  ];
}

export function makeHaproxyStarterChunks(): SecretChunk[] {
  return [
    {
      id: crypto.randomUUID(), name: 'global', chunk_type: 'haproxy_global',
      fields: [
        { key: 'log',        value: '/dev/log local0',        field_type: 'var' },
        { key: 'chroot',     value: '/var/lib/haproxy',       field_type: 'var' },
        { key: 'stats',      value: 'socket /run/haproxy/admin.sock mode 660 level admin', field_type: 'var' },
        { key: 'user',       value: 'haproxy',                field_type: 'var' },
        { key: 'group',      value: 'haproxy',                field_type: 'var' },
        { key: 'maxconn',    value: '4096',                   field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'http-in', chunk_type: 'haproxy_frontend',
      fields: [
        { key: 'bind',       value: '*:80',                   field_type: 'port' },
        { key: 'mode',       value: 'http',                   field_type: 'var' },
        { key: 'option',     value: 'httplog',                field_type: 'var' },
        { key: 'default_backend', value: 'app',              field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'app', chunk_type: 'haproxy_backend',
      fields: [
        { key: 'mode',       value: 'http',                   field_type: 'var' },
        { key: 'balance',    value: 'roundrobin',             field_type: 'var' },
        { key: 'option',     value: 'httpchk GET /health',   field_type: 'var' },
        { key: 'server',     value: 'app1 127.0.0.1:8080 check', field_type: 'endpoint' },
      ],
    },
  ];
}

export function makeAnsibleStarterChunks(): SecretChunk[] {
  return [
    {
      id: crypto.randomUUID(), name: 'vars', chunk_type: 'ansible_vars',
      fields: [
        { key: 'app_name',   value: 'myapp',                  field_type: 'var' },
        { key: 'app_port',   value: '8080',                   field_type: 'port' },
        { key: 'db_host',    value: 'localhost',              field_type: 'var' },
        { key: 'db_name',    value: 'myapp_db',               field_type: 'var' },
        { key: 'db_user',    value: 'myapp',                  field_type: 'var' },
        { key: 'db_pass',    value: '${DB_PASSWORD}',         field_type: 'secret', secret: true },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'Install packages', chunk_type: 'ansible_task',
      fields: [
        { key: 'name',       value: 'Install required packages', field_type: 'var' },
        { key: 'module',     value: 'ansible.builtin.package',  field_type: 'var' },
        { key: 'state',      value: 'present',                field_type: 'var' },
        { key: 'pkg',        value: 'nginx, git, curl',       field_type: 'list' },
      ],
    },
  ];
}

export function makePostgresStarterChunks(): SecretChunk[] {
  return [
    {
      id: crypto.randomUUID(), name: 'primary', chunk_type: 'pg_connection',
      fields: [
        { key: 'host',       value: 'localhost',              field_type: 'var' },
        { key: 'port',       value: '5432',                   field_type: 'port' },
        { key: 'dbname',     value: 'myapp',                  field_type: 'var' },
        { key: 'user',       value: 'myapp',                  field_type: 'var' },
        { key: 'password',   value: '${DB_PASSWORD}',         field_type: 'secret', secret: true },
        { key: 'sslmode',    value: 'require',                field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'app_user', chunk_type: 'pg_role',
      fields: [
        { key: 'rolname',    value: 'myapp',                  field_type: 'var' },
        { key: 'rolpassword', value: '${DB_PASSWORD}',        field_type: 'secret', secret: true },
        { key: 'rolcanlogin', value: 'true',                  field_type: 'var' },
        { key: 'rolcreatedb', value: 'false',                 field_type: 'var' },
      ],
    },
  ];
}

export function exportApache(project: Project): string {
  const chunks = project.chunks || [];
  const lines: string[] = ['# Generated by API Vault', ''];
  for (const chunk of chunks) {
    if (chunk.disabled) continue;
    if (chunk.chunk_type === 'apache_vhost') {
      const port = chunk.fields.find(f => f.key === 'SSLEngine') ? '443' : '80';
      lines.push(`<VirtualHost *:${port}>`);
      for (const f of chunk.fields) {
        if (f.value) lines.push(`    ${f.key} ${f.value}`);
      }
      lines.push('</VirtualHost>', '');
    } else if (chunk.chunk_type === 'apache_directory') {
      const path = chunk.fields.find(f => f.key === 'path')?.value || '/';
      lines.push(`<Directory ${path}>`);
      for (const f of chunk.fields) {
        if (f.key !== 'path' && f.value) lines.push(`    ${f.key} ${f.value}`);
      }
      lines.push('</Directory>', '');
    }
  }
  return lines.join('\n');
}

export function exportHaproxy(project: Project): string {
  const chunks = project.chunks || [];
  const lines: string[] = ['# Generated by API Vault', ''];
  for (const chunk of chunks) {
    if (chunk.disabled) continue;
    if (chunk.chunk_type === 'haproxy_global') {
      lines.push('global');
      for (const f of chunk.fields) { if (f.value) lines.push(`    ${f.key} ${f.value}`); }
      lines.push('');
    } else if (chunk.chunk_type === 'haproxy_frontend') {
      lines.push(`frontend ${chunk.name}`);
      for (const f of chunk.fields) { if (f.value) lines.push(`    ${f.key} ${f.value}`); }
      lines.push('');
    } else if (chunk.chunk_type === 'haproxy_backend') {
      lines.push(`backend ${chunk.name}`);
      for (const f of chunk.fields) { if (f.value) lines.push(`    ${f.key} ${f.value}`); }
      lines.push('');
    }
  }
  return lines.join('\n');
}

export function exportAnsible(project: Project): string {
  const chunks = project.chunks || [];
  const sections: string[] = ['# Generated by API Vault'];
  for (const chunk of chunks) {
    if (chunk.disabled) continue;
    if (chunk.chunk_type === 'ansible_vars') {
      sections.push('', `# ${chunk.name}`);
      for (const f of chunk.fields) { if (f.key) sections.push(`${f.key}: ${JSON.stringify(f.value)}`); }
    } else if (chunk.chunk_type === 'ansible_task') {
      const name = chunk.fields.find(f => f.key === 'name')?.value || chunk.name;
      const module = chunk.fields.find(f => f.key === 'module')?.value || 'debug';
      sections.push('', `- name: ${name}`, `  ${module}:`);
      for (const f of chunk.fields) {
        if (f.key !== 'name' && f.key !== 'module') sections.push(`    ${f.key}: ${f.value}`);
      }
    }
  }
  return sections.join('\n');
}

export function exportPostgres(project: Project): string {
  const chunks = project.chunks || [];
  const lines: string[] = ['# Generated by API Vault — .pgpass format: host:port:dbname:user:password'];
  for (const chunk of chunks) {
    if (chunk.disabled) continue;
    if (chunk.chunk_type === 'pg_connection') {
      const g = (k: string) => chunk.fields.find(f => f.key === k)?.value || '';
      lines.push(`${g('host')}:${g('port') || '5432'}:${g('dbname')}:${g('user')}:${g('password')}`);
    }
  }
  return lines.join('\n');
}

export function parseApacheConf(text: string): SecretChunk[] {
  const chunks: SecretChunk[] = [];
  const lines = text.split(/\r?\n/);
  let cur: SecretChunk | null = null;
  let depth = 0;
  let blockType = '';
  let blockArg = '';

  for (const raw of lines) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;

    const openM = line.match(/^<(\w+)\s*(.*)>$/);
    const closeM = line.match(/^<\/(\w+)>$/);

    if (openM) {
      depth++;
      blockType = openM[1].toLowerCase();
      blockArg = openM[2].trim();
      if (depth === 1) {
        const chunkType: ChunkType = blockType === 'virtualhost' ? 'apache_vhost' : 'apache_directory';
        const n = chunks.filter(c => c.chunk_type === chunkType).length + 1;
        cur = { id: crypto.randomUUID(), name: `${blockType}-${n}`, chunk_type: chunkType, fields: [] };
        if (blockType === 'directory') {
          cur.fields.push({ key: 'path', value: blockArg, field_type: 'var' });
        }
        chunks.push(cur);
      }
    } else if (closeM) {
      depth--;
      if (depth === 0) { cur = null; blockType = ''; blockArg = ''; }
    } else if (cur && depth === 1) {
      const sp = line.split(/\s+/);
      const key = sp[0];
      const val = sp.slice(1).join(' ');
      const ft: ChunkFieldType = /^(SSLCertificate|SSLCertificateKey)/i.test(key) ? 'cert' : 'var';
      cur.fields.push({ key, value: val, field_type: ft });
    }
  }
  return chunks;
}

export function parseHaproxyConf(text: string): SecretChunk[] {
  const chunks: SecretChunk[] = [];
  let cur: SecretChunk | null = null;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;

    const sectionM = line.match(/^(global|defaults|frontend|backend|listen)\s*(.*)$/);
    if (sectionM) {
      const stype = sectionM[1];
      const sname = sectionM[2].trim() || stype;
      const chunkType: ChunkType = stype === 'frontend' ? 'haproxy_frontend'
        : stype === 'backend' ? 'haproxy_backend' : 'haproxy_global';
      cur = { id: crypto.randomUUID(), name: sname, chunk_type: chunkType, fields: [] };
      chunks.push(cur);
      continue;
    }
    if (cur) {
      const sp = line.split(/\s+/);
      const key = sp[0];
      const val = sp.slice(1).join(' ');
      const ft: ChunkFieldType = /^(bind|server)$/i.test(key) ? 'endpoint' : 'var';
      cur.fields.push({ key, value: val, field_type: ft });
    }
  }
  return chunks;
}

// ── Field resolution ───────────────────────────────────────────────────────

export function resolveFieldRef(value: string, useEnvCopyField = false): { resolved: string | null; refName: string | null; unresolved: boolean; source: 'vault' | 'env_file' | null } {
  const match = value.match(/^\$\{(.+)}$/);
  if (!match) return { resolved: value, refName: null, unresolved: false, source: null };
  const refName = match[1];

  // Exact provider match, then compound PROVIDER_KEYID match
  let entry = st.vault.api_keys.find(e => e.provider === refName);
  if (!entry && refName.includes('_')) {
    const lastUs = refName.lastIndexOf('_');
    const provPart = refName.slice(0, lastUs);
    const labelPart = refName.slice(lastUs + 1);
    entry = st.vault.api_keys.find(e => e.provider === provPart && e.key_id === labelPart);
  }

  if (entry) {
    let resolved: string | null;
    if (useEnvCopyField) {
      const fieldName = (Settings.get('envCopyField') || 'api_key') as keyof VaultEntry;
      const rawVal = entry[fieldName];
      resolved = (rawVal != null && rawVal !== '') ? String(rawVal) : (entry.api_key || null);
    } else {
      resolved = entry.api_key || null;
    }
    return { resolved, refName, unresolved: false, source: 'vault' };
  }

  for (const project of st.vault.projects) {
    for (const chunk of project.chunks || []) {
      if (chunk.chunk_type !== 'env_file') continue;
      const field = chunk.fields.find(f => f.key === refName);
      if (field) return { resolved: field.value, refName, unresolved: false, source: 'env_file' };
    }
  }
  return { resolved: null, refName, unresolved: true, source: null };
}

// ── Field copy text formatter ──────────────────────────────────────────────

/** Returns the field formatted in its native config syntax for clipboard. */
function chunkFieldCopyText(key: string, value: string, chunkType: string): string {
  if (chunkType === 'env_file') return `${key}=${value}`;
  if (chunkType === 'wg_interface' || chunkType === 'wg_peer') return `${key} = ${value}`;
  if (chunkType === 'ssh_host') return `    ${key} ${value}`;
  if (chunkType.startsWith('nginx_')) return `${key} ${value};`;
  if (chunkType.startsWith('k8s_') || chunkType.startsWith('traefik_')) return `${key}: ${value}`;
  return `${key} = ${value}`;
}

// ── Cert link helpers ──────────────────────────────────────────────────────

/** Find a vault cert entry linked to a field value (${REF} or path pattern). */
function findLinkedCert(value: string): VaultEntry | null {
  if (!value) return null;

  // ${REF} syntax
  const ref = value.match(/^\$\{(.+)}$/);
  if (ref) {
    const name = ref[1];
    const base = name.replace(/[_-]?(key|privkey|fullchain|cert|certificate)$/i, '');
    return st.vault.api_keys.find(e =>
      e.secretType === 'certificate' && (e.provider === name || e.provider === base)
    ) || st.vault.api_keys.find(e => e.provider === name || e.provider === base) || null;
  }

  // /etc/letsencrypt/live/DOMAIN/...
  const lePath = value.match(/\/live\/([^/]+)\//);
  if (lePath) {
    const domain = lePath[1];
    return st.vault.api_keys.find(e =>
      e.secretType === 'certificate' &&
      (e.provider === domain || e.provider.replace(/^www\./, '') === domain.replace(/^www\./, ''))
    ) || null;
  }

  return null;
}

/** Render a certificate info panel for a linked vault cert entry. */
function renderCertPanel(entry: VaultEntry, isCertKey: boolean): string {
  const cn    = entry.api_description || entry.provider;
  const expiry = entry.expires_at ? new Date(entry.expires_at) : null;
  const now    = new Date();
  const soon   = expiry && expiry.getTime() - now.getTime() < 30 * 86_400_000;
  const expired = expiry && expiry < now;
  const expiryColor = expired ? 'var(--price-paid)' : soon ? '#f0ad4e' : 'var(--text3)';
  const expiryText  = expiry
    ? expiry.toISOString().slice(0, 10)
    : 'no expiry';
  const pemContent = isCertKey
    ? (entry.cert_key_data || '')
    : (entry.certificate_data || entry.api_key || '');
  const pemPreview = pemContent ? pemContent.split('\n').slice(0, 3).join('\n') + '\n…' : '—';

  return `
    <div class="cert-panel">
      <div class="cert-panel-row">
        <span class="cert-panel-icon">🔒</span>
        <div class="cert-panel-meta">
          <span class="cert-panel-cn">${esc(cn)}</span>
          <span class="cert-panel-expiry" style="color:${expiryColor}">${expired ? '⚠ EXPIRED ' : soon ? '⚠ expires ' : 'exp '}${esc(expiryText)}</span>
        </div>
        <div class="cert-panel-actions">
          ${pemContent ? `<button class="btn btn-ghost btn-xs" data-action="chunk-copy" data-value="${escAttr(pemContent)}" title="Copy PEM">Copy PEM</button>` : ''}
        </div>
      </div>
      <pre class="cert-panel-pem">${esc(pemPreview)}</pre>
    </div>
  `;
}

// ── Nginx display helpers ──────────────────────────────────────────────────

/** Render an nginx listen directive as a badge row. */
function renderListenBadge(value: string): string {
  const raw   = value.trim();
  const parts = raw.split(/\s+/);
  const addr  = parts[0];
  const hasSSL  = parts.includes('ssl');
  const hasH2   = parts.includes('http2');
  const hasH3   = parts.includes('http3');
  const isIpv6  = addr.startsWith('[');

  // Extract port from addr (could be "443", "[::]:443", "0.0.0.0:443")
  const portMatch = addr.match(/:(\d+)$/) || addr.match(/^(\d+)$/);
  const port = portMatch ? portMatch[1] : addr;

  return `<span class="listen-badge">
    ${isIpv6 ? `<span class="listen-tag listen-ipv6">ipv6</span>` : ''}
    <span class="listen-port">${esc(port)}</span>
    ${hasSSL  ? `<span class="listen-tag listen-ssl">SSL</span>` : ''}
    ${hasH2   ? `<span class="listen-tag listen-proto">h2</span>` : ''}
    ${hasH3   ? `<span class="listen-tag listen-proto">h3</span>` : ''}
  </span>`;
}

/** Render server_name value as individual hostname badges. */
function renderServerNameBadges(value: string): string {
  return value.trim().split(/\s+/).filter(Boolean)
    .map(n => `<span class="hostname-badge">${esc(n)}</span>`).join('');
}

/** Render an nginx return directive as a redirect badge. */
function renderReturnBadge(value: string): string {
  const m = value.match(/^(\d{3})\s+(.+)$/);
  if (!m) return esc(value);
  const code  = m[1];
  const dest  = m[2];
  const color = code === '301' ? '#4fc97e' : code === '302' ? '#f0ad4e' : 'var(--text2)';
  return `<span class="redirect-badge">
    <span class="redirect-status" style="color:${color}">${esc(code)}</span>
    <span class="redirect-arrow">→</span>
    <span class="redirect-dest">${esc(dest)}</span>
  </span>`;
}

// ── Chunk card renderer ────────────────────────────────────────────────────

export function renderChunkCard(chunk: SecretChunk, project: Project): HTMLElement {
  const card = document.createElement('div');
  card.className = `chunk-card${chunk.disabled ? ' chunk-disabled' : ''}`;
  const typeLabel = chunk.chunk_type.replace(/_/g, ' ');

  const isWg       = chunk.chunk_type === 'wg_interface' || chunk.chunk_type === 'wg_peer';
  const isDockerSvc = chunk.chunk_type === 'docker_service';
  const isNginx    = ['nginx_server','nginx_location','nginx_upstream'].includes(chunk.chunk_type);

  const chunkEnvFields = isDockerSvc ? chunk.fields.filter(f => f.description === 'env') : [];
  const hasChunkEnvFields = chunkEnvFields.length > 0;
  const hasChunkEnvRefs = chunkEnvFields.some(f => /^\$\{.+\}$/.test(f.value));

  let fieldsHtml = '';
  for (const field of chunk.fields) {
    const { resolved, refName, unresolved, source: refSource } = resolveFieldRef(field.value);
    const isSecret = field.secret || field.field_type === 'secret';

    // Context-aware effective type — lets old imported data display smartly
    // without needing a data migration.
    let effType: ChunkFieldType = field.field_type;
    if (!isSecret && !refName) {
      if (isWg) {
        if (/^(Address|AllowedIPs)$/i.test(field.key)) effType = 'subnet';
        else if (/^DNS$/i.test(field.key)) effType = 'ip';
        else if (/^Endpoint$/i.test(field.key)) effType = 'endpoint';
        else if (/^ListenPort$/i.test(field.key)) effType = 'port';
        else if (/^(PostUp|PostDown|PreUp|PreDown)$/i.test(field.key)) effType = 'multiline';
      }
      if (isNginx) {
        if (/^listen$/i.test(field.key))                                    effType = 'port';
        else if (/^server_name$/i.test(field.key))                          effType = 'ip';  // repurpose as multi-badge via nginx branch
        else if (/^(ssl_certificate|ssl_certificate_key|ssl_trusted_certificate)$/i.test(field.key)) effType = 'cert';
        else if (/^return$/i.test(field.key))                               effType = 'endpoint'; // repurpose; handled in nginx branch
        else if (/^(proxy_pass|fastcgi_pass|uwsgi_pass)$/i.test(field.key)) effType = 'endpoint';
        else if (/^(add_header|proxy_set_header|more_set_headers)$/i.test(field.key)) effType = 'multiline';
      }
      if (field.field_type === 'cert') effType = 'cert';
      if (isDockerSvc && field.field_type === 'list') {
        if (field.key === 'volumes') effType = 'volume_mount';
      }
    }

    let displayVal = '';
    let badgeHtml = '';

    if (refName) {
      if (unresolved) {
        displayVal = `\${${refName}}`;
        badgeHtml = `<span class="chunk-ref-badge chunk-ref-unresolved" title="Not linked — no vault entry or .env field named '${esc(refName)}'">unresolved: ${esc(refName)}</span>`;
      } else if (refSource === 'env_file') {
        displayVal = '••••••••';
        badgeHtml = `<span class="chunk-ref-badge chunk-ref-env" title="Linked from .env chunk field '${esc(refName)}'">→ .env: ${esc(refName)}</span>`;
      } else {
        displayVal = '••••••••';
        badgeHtml = `<span class="chunk-ref-badge" title="Linked from vault entry '${esc(refName)}'">→ vault: ${esc(refName)}</span>`;
      }
    } else if (isSecret && field.value) {
      displayVal = '••••••••';
    } else {
      displayVal = field.value || '';
    }

    const isEnvField = chunk.chunk_type === 'env_file' || (isDockerSvc && field.description === 'env');
    const envCopyResolved = (isEnvField && refName) ? resolveFieldRef(field.value, true).resolved : null;
    const valClass = `chunk-field-val${isSecret && field.value ? ' masked' : ''}`;
    // Copy format: KEY=VALUE for env, native config syntax for everything else.
    // Linked ${REF} fields copy the template string (not the resolved secret).
    const copyData =
      isEnvField ? `${field.key}=${field.value}`
      : refName  ? chunkFieldCopyText(field.key, field.value, chunk.chunk_type)
      : isSecret ? (field.value || '')
      : chunkFieldCopyText(field.key, field.value, chunk.chunk_type);
    const isMultiline = (effType === 'multiline' || effType === 'list') && !isSecret && !refName;
    const copyBtn = copyData !== undefined && copyData !== ''
      ? `<button class="icon-btn sm" data-action="chunk-copy" data-value="${escAttr(copyData)}" title="Copy">${copySVG}</button>` : '';
    const envCopyBtn = envCopyResolved !== null
      ? `<button class="btn btn-ghost btn-xs" data-action="chunk-copy" data-value="${escAttr(`${field.key}=${envCopyResolved}`)}" title="Copy resolved value">.env</button>`
      : '';

    // JSON object/array detection for pretty display
    let parsedJson: object | null = null;
    if (!isSecret && !refName && field.value) {
      const trimmed = field.value.trim();
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        try { parsedJson = JSON.parse(trimmed) as object; } catch {}
      }
    }
    const isJsonVal = parsedJson !== null;

    const renderPortBadge = (portStr: string) => {
      const protoMatch = portStr.match(/\/(tcp|udp|sctp)$/i);
      const proto = protoMatch ? protoMatch[1].toLowerCase() : '';
      const base = portStr.replace(/\/(tcp|udp|sctp)$/i, '');
      const parts = base.split(':');
      if (parts.length === 1) {
        return `<span class="port-badge"><span class="port-container">${esc(parts[0])}</span>${proto ? `<span class="port-proto">${esc(proto)}</span>` : ''}</span>`;
      }
      const host = parts[0];
      const container = parts.slice(1).join(':');
      return `<span class="port-badge"><span class="port-host">${esc(host)}</span><span class="port-arrow">→</span><span class="port-container">${esc(container)}</span>${proto ? `<span class="port-proto">${esc(proto)}</span>` : ''}</span>`;
    };

    const renderVolBadge = (str: string) => {
      const colon1 = str.indexOf(':');
      if (colon1 < 0) return `<span class="volume-badge"><span class="vol-name">${esc(str)}</span></span>`;
      const host = str.slice(0, colon1);
      const rest = str.slice(colon1 + 1);
      const modeMatch = rest.match(/:?(ro|rw)$/);
      const mode = modeMatch ? modeMatch[1] : '';
      const container = mode ? rest.slice(0, rest.lastIndexOf(':')) : rest;
      const hostShort = host.length > 30 ? '…' + host.slice(host.lastIndexOf('/')) : host;
      return `<span class="volume-badge" title="${escAttr(str)}"><span class="vol-host">${esc(hostShort)}</span><span class="port-arrow">→</span><span class="vol-container">${esc(container)}</span>${mode ? `<span class="port-proto">${esc(mode)}</span>` : ''}</span>`;
    };

    if (isNginx && effType === 'port' && /^listen$/i.test(field.key)) {
      // nginx listen: parse port + SSL/http2 indicators
      fieldsHtml += `
        <div class="chunk-field-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-val">${renderListenBadge(displayVal)}</div>
          <div class="chunk-field-actions">${copyBtn}</div>
        </div>`;
    } else if (effType === 'port') {
      const portLines = (displayVal || '').split(/\n/).filter(Boolean).map(renderPortBadge).join('');
      fieldsHtml += `
        <div class="chunk-field-row multiline-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-actions">${copyBtn}</div>
          <div class="chunk-field-val port-list">${portLines || '<span style="color:var(--text3);font-size:10px">empty</span>'}</div>
        </div>`;
    } else if (effType === 'volume_mount') {
      const volLines = (displayVal || '').split(/\n/).filter(Boolean).map(renderVolBadge).join('');
      fieldsHtml += `
        <div class="chunk-field-row multiline-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-actions">${copyBtn}</div>
          <div class="chunk-field-val port-list">${volLines || '<span style="color:var(--text3);font-size:10px">empty</span>'}</div>
        </div>`;
    } else if (effType === 'subnet') {
      const cidrs = (displayVal || '').split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
      const badges = cidrs.map(c => `<span class="subnet-badge">${esc(c)}</span>`).join('');
      fieldsHtml += `
        <div class="chunk-field-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-val badge-list">${badges || '<span style="color:var(--text3);font-size:10px">empty</span>'}</div>
          <div class="chunk-field-actions">${copyBtn}</div>
        </div>`;
    } else if (isNginx && /^server_name$/i.test(field.key)) {
      // nginx server_name: each hostname as a badge
      fieldsHtml += `
        <div class="chunk-field-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-val badge-list">${renderServerNameBadges(displayVal)}</div>
          <div class="chunk-field-actions">${copyBtn}</div>
        </div>`;
    } else if (isNginx && /^return$/i.test(field.key)) {
      // nginx return: redirect badge — return has effType 'endpoint' from detection but handled here
      fieldsHtml += `
        <div class="chunk-field-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-val">${renderReturnBadge(displayVal)}</div>
          <div class="chunk-field-actions">${copyBtn}</div>
        </div>`;
    } else if (effType === 'ip') {
      const ips = (displayVal || '').split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
      const badges = ips.map(ip => `<span class="ip-badge">${esc(ip)}</span>`).join('');
      fieldsHtml += `
        <div class="chunk-field-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-val badge-list">${badges || '<span style="color:var(--text3);font-size:10px">empty</span>'}</div>
          <div class="chunk-field-actions">${copyBtn}</div>
        </div>`;
    } else if (effType === 'cert') {
      // SSL certificate / key: path + linked vault cert panel
      const isCertKey = /key/i.test(field.key);
      const linkedCert = findLinkedCert(field.value);
      const pathDisplay = refName ? `<span class="cert-ref-badge">${esc(displayVal)}</span>` : `<span class="chunk-field-val">${esc(displayVal)}</span>`;
      fieldsHtml += `
        <div class="chunk-field-row chunk-field-cert-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-val">${pathDisplay}</div>
          <div class="chunk-field-actions">${copyBtn}</div>
        </div>
        ${linkedCert ? renderCertPanel(linkedCert, isCertKey) : ''}`;
    } else if (effType === 'endpoint') {
      const lastColon = displayVal.lastIndexOf(':');
      const epHost = lastColon > 0 ? displayVal.slice(0, lastColon) : displayVal;
      const epPort = lastColon > 0 ? displayVal.slice(lastColon + 1) : '';
      const endpointBadge = `<span class="endpoint-badge"><span class="endpoint-host">${esc(epHost)}</span>${epPort ? `<span class="port-arrow">:</span><span class="endpoint-port">${esc(epPort)}</span>` : ''}</span>`;
      fieldsHtml += `
        <div class="chunk-field-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-val">${endpointBadge}</div>
          <div class="chunk-field-actions">${copyBtn}</div>
        </div>`;
    } else if (effType === 'list' && isDockerSvc && field.key === 'networks') {
      const nets = (displayVal || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
      const badges = nets.map(n => `<span class="net-badge">${esc(n)}</span>`).join('');
      fieldsHtml += `
        <div class="chunk-field-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-val badge-list">${badges || '<span style="color:var(--text3);font-size:10px">empty</span>'}</div>
          <div class="chunk-field-actions">${copyBtn}</div>
        </div>`;
    } else if (effType === 'list' && isDockerSvc && field.key === 'devices') {
      const devLines = (displayVal || '').split(/\n/).filter(Boolean).map(renderVolBadge).join('');
      fieldsHtml += `
        <div class="chunk-field-row multiline-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-actions">${copyBtn}</div>
          <div class="chunk-field-val port-list">${devLines || '<span style="color:var(--text3);font-size:10px">empty</span>'}</div>
        </div>`;
    } else if (effType === 'list' && isDockerSvc && field.key === 'cap_add') {
      const caps = (displayVal || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
      const badges = caps.map(c => `<span class="cap-badge">${esc(c)}</span>`).join('');
      fieldsHtml += `
        <div class="chunk-field-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-val badge-list">${badges || '<span style="color:var(--text3);font-size:10px">empty</span>'}</div>
          <div class="chunk-field-actions">${copyBtn}</div>
        </div>`;
    } else if (isJsonVal) {
      const formatted = JSON.stringify(parsedJson, null, 2);
      fieldsHtml += `
        <div class="chunk-field-row multiline-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-actions">${copyBtn}${envCopyBtn}</div>
          <pre class="${valClass} code-block">${esc(formatted)}</pre>
        </div>`;
    } else if (isMultiline) {
      fieldsHtml += `
        <div class="chunk-field-row multiline-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-actions">${copyBtn}</div>
          <pre class="${valClass} code-block">${esc(displayVal)}</pre>
        </div>`;
    } else if (isDockerSvc && field.key === 'image' && field.value && !isSecret && !refName) {
      const colonIdx = field.value.lastIndexOf(':');
      const hasTag = colonIdx > field.value.lastIndexOf('/');
      const tag = hasTag ? field.value.slice(colonIdx + 1) : '';
      const nameWithReg = hasTag ? field.value.slice(0, colonIdx) : field.value;
      const lastSlash = nameWithReg.lastIndexOf('/');
      const imgName = lastSlash >= 0 ? nameWithReg.slice(lastSlash + 1) : nameWithReg;
      const registry = lastSlash >= 0 ? nameWithReg.slice(0, lastSlash) : '';
      fieldsHtml += `
        <div class="chunk-field-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-val">
            <span class="image-badge">
              ${registry ? `<span class="img-registry">${esc(registry)}/</span>` : ''}<span class="img-name">${esc(imgName)}</span>${tag ? `<span class="img-tag">:${esc(tag)}</span>` : ''}
            </span>
          </div>
          <div class="chunk-field-actions">${copyBtn}</div>
        </div>`;
    } else {
      let extraBadge = '';
      if (field.field_type === 'user_id' && field.value && !refName) {
        const [uid, gid] = field.value.split(':');
        extraBadge = `<span class="user-id-badge">uid:${esc(uid)}${gid ? `·gid:${esc(gid)}` : ''}</span>`;
      }
      fieldsHtml += `
        <div class="chunk-field-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <span class="${valClass}">${esc(displayVal)} ${badgeHtml}${extraBadge}</span>
          <div class="chunk-field-actions">${copyBtn}${envCopyBtn}</div>
        </div>`;
    }
  }

  // Interface / nginx server / k8s deployment are "wide" chunks — span full grid width
  if (['wg_interface', 'nginx_server', 'k8s_deployment', 'traefik_router'].includes(chunk.chunk_type)) {
    card.classList.add('span-full');
  }

  // nginx_key: PEM certificate/key file — special display
  if (chunk.chunk_type === 'nginx_key') {
    const pathField    = chunk.fields.find(f => f.key === 'path');
    const contentField = chunk.fields.find(f => f.key === 'content');
    const pem = contentField?.value || '';
    const pemCerts = pem.split(/(?=-----BEGIN )/).map(s => s.trim()).filter(Boolean);
    const renderPemBlock = (raw: string) => {
      const header = raw.match(/^-----BEGIN ([^-]+)-----/)?.[1] ?? '';
      const cls = /CERTIFICATE/i.test(header) ? 'pem-cert' : /PRIVATE|RSA|EC/i.test(header) ? 'pem-key' : 'pem-other';
      return `<div class="pem-block ${cls}"><div class="pem-label">${esc(header || 'PEM Block')}</div><pre class="pem-pre">${esc(raw)}</pre></div>`;
    };
    const pemHtml = pemCerts.length ? pemCerts.map(renderPemBlock).join('') : '<div class="pem-empty">No PEM content — click Edit to paste certificate</div>';
    const headBtns = `<div style="display:flex;gap:4px;margin-left:auto">
      <button class="btn btn-ghost btn-sm" data-action="copy-chunk-full" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" title="Copy PEM content">Copy</button>
      <button class="btn btn-ghost btn-sm" data-action="chunk-up"   data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}">↑</button>
      <button class="btn btn-ghost btn-sm" data-action="chunk-down" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}">↓</button>
      <button class="btn btn-ghost btn-sm" data-action="edit-chunk" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}">Edit</button>
      <button class="btn btn-ghost btn-sm" data-action="delete-chunk" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" style="color:var(--price-paid)">Delete</button>
    </div>`;
    card.innerHTML = `
      <div class="chunk-card-head">
        <span class="chunk-card-title">${esc(chunk.name)}</span>
        <span class="chunk-type-badge">key file</span>
        ${headBtns}
      </div>
      ${pathField?.value ? `<div class="nginx-key-path">${esc(pathField.value)}</div>` : ''}
      <div class="nginx-key-body">${pemHtml}</div>
    `;
    return card;
  }

  card.innerHTML = `
    <div class="chunk-card-head">
      <span class="chunk-card-title">${esc(chunk.name)}</span>
      <span class="chunk-type-badge">${esc(typeLabel)}</span>
      <div style="display:flex;gap:4px;margin-left:auto">
        <button class="btn btn-ghost btn-sm" data-action="copy-chunk-full" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" title="Copy entire chunk in native format">Copy</button>
        ${chunk.chunk_type === 'env_file' ? `<button class="btn btn-ghost btn-sm" data-action="export-env-chunk" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}">Export .env</button>` : ''}
        ${hasChunkEnvRefs ? `<button class="btn btn-ghost btn-sm" data-action="copy-chunk-env" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" title="Copy env fields with resolved secret values">Copy (resolved)</button>` : ''}
        <button class="btn btn-ghost btn-sm" data-action="chunk-up" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" title="Move up">↑</button>
        <button class="btn btn-ghost btn-sm" data-action="chunk-down" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" title="Move down">↓</button>
        <button class="btn btn-ghost btn-sm" data-action="dup-chunk" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}">Dup</button>
        <button class="btn btn-ghost btn-sm" data-action="edit-chunk" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}">Edit</button>
        <button class="btn btn-ghost btn-sm" data-action="delete-chunk" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" style="color:var(--price-paid)">Delete</button>
      </div>
    </div>
    ${chunk.notes ? `<div class="chunk-notes">${esc(chunk.notes)}</div>` : ''}
    <div class="chunk-fields">${fieldsHtml || '<div class="chunk-no-fields">No fields</div>'}</div>
  `;
  return card;
}

// ── Chunk → string (copy-chunk-full) ──────────────────────────────────────

function serviceChunkToYaml(sc: SecretChunk): string {
  const yamlStr = (v: string): string => {
    if (!v) return '""';
    if (/[\s:#\[\]{},|>&*!'"@`]/.test(v)) return JSON.stringify(v);
    return v;
  };
  const quoteItem = (v: string): string => /\s/.test(v) ? JSON.stringify(v) : v;
  const svcName = sc.name.replace(/\s+/g, '_').toLowerCase();
  const out: string[] = [`${svcName}:`];

  const envFields: ChunkField[] = [];
  const portItems: string[] = [];
  const volumeItems: string[] = [];
  const listMap = new Map<string, string[]>();
  const scalars: [string, string][] = [];

  for (const f of sc.fields) {
    if (!f.key || f.key === 'restart') continue;
    if (f.description === 'env' || f.field_type === 'env_var') {
      envFields.push(f);
    } else if (f.key === 'ports' || f.field_type === 'port') {
      portItems.push(...f.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean));
    } else if (f.key === 'volumes' || f.field_type === 'volume_mount') {
      volumeItems.push(...f.value.split(/\n/).map(s => s.trim()).filter(Boolean));
    } else if (f.key === 'networks' || f.key === 'depends_on' || f.field_type === 'list') {
      if (!listMap.has(f.key)) listMap.set(f.key, []);
      listMap.get(f.key)!.push(...f.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean));
    } else if (f.value != null && f.value !== '') {
      scalars.push([f.key, f.value]);
    }
  }

  const PRIO = ['image', 'container_name', 'user', 'hostname', 'network_mode', 'pid', 'entrypoint', 'command'];
  const scalarMap = new Map(scalars);
  for (const k of PRIO) {
    if (scalarMap.has(k)) { out.push(`  ${k}: ${yamlStr(scalarMap.get(k)!)}`); scalarMap.delete(k); }
  }
  for (const [k, v] of scalarMap) out.push(`  ${k}: ${yamlStr(v)}`);

  if (portItems.length) {
    out.push('  ports:');
    for (const p of portItems) out.push(`    - ${JSON.stringify(p)}`);
  }
  if (envFields.length) {
    out.push('  environment:');
    for (const f of envFields) {
      const ref = f.ref_name || (f.value?.match(/^\$\{(.+)}$/) || [])[1];
      out.push(`    - ${f.key}=${ref ? `\${${ref}}` : (f.value ?? '')}`);
    }
  }
  if (volumeItems.length) {
    out.push('  volumes:');
    for (const v of volumeItems) out.push(`    - ${quoteItem(v)}`);
  }
  for (const [k, items] of listMap) {
    out.push(`  ${k}:`);
    for (const item of items) out.push(`    - ${yamlStr(item)}`);
  }
  const restartF = sc.fields.find(f => f.key === 'restart');
  out.push(`  restart: ${restartF?.value || 'unless-stopped'}`);
  return out.join('\n');
}

/** Format a single chunk as its native config text for clipboard copy. */
export function chunkToString(chunk: SecretChunk): string {
  const isWg  = chunk.chunk_type === 'wg_interface' || chunk.chunk_type === 'wg_peer';
  const isEnv = chunk.chunk_type === 'env_file';
  const isNginxBlock = ['nginx_server','nginx_location','nginx_upstream'].includes(chunk.chunk_type);
  if (chunk.chunk_type === 'nginx_key') {
    return chunk.fields.find(f => f.key === 'content')?.value ?? '';
  }
  const isTraefik    = ['traefik_router','traefik_service','traefik_middleware'].includes(chunk.chunk_type);
  const isK8s        = ['k8s_deployment','k8s_service','k8s_ingress','k8s_configmap'].includes(chunk.chunk_type);
  const isSsh        = chunk.chunk_type === 'ssh_host';

  if (isWg) {
    const header = chunk.chunk_type === 'wg_interface' ? '[Interface]' : '[Peer]';
    const lines  = [header];
    for (const f of chunk.fields) {
      // Keep ${REF} template — caller decides whether to resolve
      lines.push(`${f.key} = ${f.value ?? ''}`);
    }
    return lines.join('\n');
  }

  if (isEnv) {
    return chunk.fields
      .filter(f => f.key)
      .map(f => `${f.key}=${f.value ?? ''}`)
      .join('\n');
  }

  if (isNginxBlock) {
    const blockType = chunk.chunk_type === 'nginx_location' ? 'location' : 'server';
    const pathField = chunk.fields.find(f => f.key === 'path');
    const blockName = chunk.chunk_type === 'nginx_location'
      ? (pathField?.value ? ` ${pathField.value}` : '')
      : '';  // server block has no inline name
    const inner = chunk.fields
      .filter(f => f.key && f.key !== 'path' && f.value !== undefined)
      .map(f => `    ${f.key} ${f.value};`)
      .join('\n');
    return `${blockType}${blockName} {\n${inner}\n}`;
  }

  if (isSsh) {
    const lines = [`Host ${chunk.name}`];
    for (const f of chunk.fields) {
      if (f.key && f.value) lines.push(`    ${f.key} ${f.value}`);
    }
    return lines.join('\n');
  }

  if (isTraefik || isK8s) {
    // YAML-like key: value
    return chunk.fields
      .filter(f => f.key)
      .map(f => `${f.key}: ${f.value ?? ''}`)
      .join('\n');
  }

  if (chunk.chunk_type === 'docker_service') {
    return serviceChunkToYaml(chunk);
  }

  // Generic unknown: key: value
  return chunk.fields
    .filter(f => f.key)
    .map(f => `${f.key}: ${f.value ?? ''}`)
    .join('\n');
}

// ── Export functions ───────────────────────────────────────────────────────

export function exportWireGuard(project: Project): string {
  const chunks = project.chunks || [];
  const sections: string[] = [];
  for (const chunk of chunks) {
    const header = chunk.chunk_type === 'wg_interface' ? '[Interface]'
      : chunk.chunk_type === 'wg_peer' ? '[Peer]'
      : `# ${chunk.name}`;
    const lines = [header];
    for (const field of chunk.fields) {
      let val = field.value;
      if (!val) continue;
      const match = val.match(/^\$\{(.+)}$/);
      if (match) {
        const entry = st.vault.api_keys.find(e => e.provider === match[1]);
        if (entry) val = entry.api_key;
      }
      lines.push(`${field.key} = ${val}`);
    }
    sections.push(lines.join('\n'));
  }
  return sections.join('\n\n');
}

export function exportDockerCompose(project: Project): { yaml: string; envFile: string } {
  const chunks = project.chunks || [];
  const serviceChunks = chunks.filter(c => c.chunk_type === 'docker_service');
  const networkChunks = chunks.filter(c => c.chunk_type === 'docker_network');
  const volumeChunks  = chunks.filter(c => c.chunk_type === 'docker_volume');

  const out: string[] = ['# Generated by API Vault', ''];
  const envLines: string[] = [];

  const yamlStr = (v: string): string => {
    if (!v) return '""';
    if (/[\s:#\[\]{},|>&*!'"@`]/.test(v)) return JSON.stringify(v);
    return v;
  };
  const quoteItem = (v: string): string => /\s/.test(v) ? JSON.stringify(v) : v;

  if (networkChunks.length) {
    out.push('networks:');
    for (const nc of networkChunks) {
      for (const f of nc.fields) {
        if (!f.key) continue;
        out.push(`  ${f.key}:`);
        if (f.value) out.push(`    driver: ${f.value}`);
      }
      if (!nc.fields.length) out.push(`  ${nc.name}:`);
    }
    out.push('');
  }

  if (volumeChunks.length) {
    out.push('volumes:');
    for (const vc of volumeChunks) {
      for (const f of vc.fields) { if (f.key) out.push(`  ${f.key}:`); }
      if (!vc.fields.length) out.push(`  ${vc.name}:`);
    }
    out.push('');
  }

  if (serviceChunks.length) {
    out.push('services:');
    for (const sc of serviceChunks) {
      const svcName = sc.name.replace(/\s+/g, '_').toLowerCase();
      out.push(`  ${svcName}:`);

      const envFields: ChunkField[]   = [];
      const portItems: string[]       = [];
      const volumeItems: string[]     = [];
      const listMap = new Map<string, string[]>();
      const scalars: [string, string][] = [];

      for (const f of sc.fields) {
        if (!f.key || f.key === 'restart') continue;
        if (f.description === 'env' || f.field_type === 'env_var') {
          envFields.push(f);
        } else if (f.key === 'ports' || f.field_type === 'port') {
          portItems.push(...f.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean));
        } else if (f.key === 'volumes' || f.field_type === 'volume_mount') {
          volumeItems.push(...f.value.split(/\n/).map(s => s.trim()).filter(Boolean));
        } else if (f.key === 'networks' || f.key === 'depends_on' || f.field_type === 'list') {
          const key = f.key;
          if (!listMap.has(key)) listMap.set(key, []);
          listMap.get(key)!.push(...f.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean));
        } else if (f.value != null && f.value !== '') {
          scalars.push([f.key, f.value]);
        }
      }

      // Scalars — priority order
      const PRIO = ['image', 'container_name', 'user', 'hostname', 'network_mode', 'pid', 'entrypoint', 'command'];
      const scalarMap = new Map(scalars);
      for (const k of PRIO) {
        if (scalarMap.has(k)) { out.push(`    ${k}: ${yamlStr(scalarMap.get(k)!)}`); scalarMap.delete(k); }
      }
      for (const [k, v] of scalarMap) out.push(`    ${k}: ${yamlStr(v)}`);

      // Ports
      if (portItems.length) {
        out.push('    ports:');
        for (const p of portItems) out.push(`      - ${JSON.stringify(p)}`);
      }

      // Environment: - KEY=value format
      if (envFields.length) {
        out.push('    environment:');
        for (const f of envFields) {
          const ref = f.ref_name || (f.value?.match(/^\$\{(.+)}$/) || [])[1];
          if (ref) {
            out.push(`      - ${f.key}=\${${ref}}`);
            const entry = st.vault.api_keys.find(e => e.provider === ref);
            envLines.push(`${ref}=${entry ? entry.api_key : ''}`);
          } else {
            out.push(`      - ${f.key}=${f.value ?? ''}`);
          }
        }
      }

      // Volumes
      if (volumeItems.length) {
        out.push('    volumes:');
        for (const v of volumeItems) out.push(`      - ${quoteItem(v)}`);
      }

      // Networks, depends_on, and other lists
      for (const [k, items] of listMap) {
        out.push(`    ${k}:`);
        for (const item of items) out.push(`      - ${yamlStr(item)}`);
      }

      // Restart
      const restartF = sc.fields.find(f => f.key === 'restart');
      out.push(`    restart: ${restartF?.value || 'unless-stopped'}`);
      out.push('');
    }
  }

  return { yaml: out.join('\n'), envFile: envLines.join('\n') };
}

export function exportServicesSection(project: Project): string {
  const svcChunks = (project.chunks || []).filter(c => c.chunk_type === 'docker_service');
  if (!svcChunks.length) return '';
  const lines = ['services:'];
  for (const sc of svcChunks) {
    serviceChunkToYaml(sc).split('\n').forEach(l => lines.push('  ' + l));
    lines.push('');
  }
  return lines.join('\n');
}

export function renderDockerServicesCard(project: Project): HTMLElement {
  const pid = escAttr(project.id);
  const svcChunks = (project.chunks || []).filter(c => c.chunk_type === 'docker_service');

  const makeSubCard = (label: string, bodyHtml: string): string =>
    `<div class="docker-sub-card">
      <div class="docker-sub-card-label">${esc(label)}</div>
      <div class="docker-sub-card-body">${bodyHtml}</div>
    </div>`;

  const renderSvcCard = (sc: SecretChunk): string => {
    const cid = escAttr(sc.id);
    const envFields: ChunkField[] = [];
    const portItems: string[] = [];
    const volumeItems: string[] = [];
    const listMap = new Map<string, string[]>();
    const scalars: [string, string][] = [];

    for (const f of sc.fields) {
      if (!f.key) continue;
      if (f.description === 'env' || f.field_type === 'env_var') {
        envFields.push(f);
      } else if (f.key === 'ports' || f.field_type === 'port') {
        portItems.push(...f.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean));
      } else if (f.key === 'volumes' || f.field_type === 'volume_mount') {
        volumeItems.push(...f.value.split(/\n/).map(s => s.trim()).filter(Boolean));
      } else if (f.key === 'networks' || f.key === 'depends_on' || f.field_type === 'list') {
        if (!listMap.has(f.key)) listMap.set(f.key, []);
        listMap.get(f.key)!.push(...f.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean));
      } else if (f.value != null && f.value !== '') {
        scalars.push([f.key, f.value]);
      }
    }

    const PRIO = ['image', 'container_name', 'user', 'hostname', 'network_mode', 'pid', 'entrypoint', 'command', 'restart'];
    const scalarMap = new Map(scalars);
    let scalarsHtml = '';
    for (const k of PRIO) {
      if (scalarMap.has(k)) {
        scalarsHtml += `<div class="dsvc-field"><span class="dsvc-key">${esc(k)}</span><span class="dsvc-val">${esc(scalarMap.get(k)!)}</span></div>`;
        scalarMap.delete(k);
      }
    }
    for (const [k, v] of scalarMap) {
      scalarsHtml += `<div class="dsvc-field"><span class="dsvc-key">${esc(k)}</span><span class="dsvc-val">${esc(v)}</span></div>`;
    }

    let subCards = '';

    if (envFields.length) {
      let envBody = '';
      for (const f of envFields) {
        const { refName, unresolved, source } = resolveFieldRef(f.value);
        const valDisplay = refName ? (unresolved ? `\${${refName}}` : '••••••••') : (f.value ?? '');
        let badge = '';
        if (refName) {
          if (unresolved) {
            badge = `<span class="chunk-ref-badge chunk-ref-unresolved" title="Not linked — no vault entry or .env field named '${esc(refName!)}'">${esc(refName!)}</span>`;
          } else if (source === 'env_file') {
            badge = `<span class="chunk-ref-badge chunk-ref-env" title="Linked from .env: ${esc(refName!)}">→ .env</span>`;
          } else {
            badge = `<span class="chunk-ref-badge" title="Linked from vault: ${esc(refName!)}">→ vault</span>`;
          }
        }
        envBody += `<div class="dsvc-env-row"><span class="dsvc-env-key">${esc(f.key)}</span><span class="dsvc-env-eq">=</span><span class="dsvc-env-val">${esc(valDisplay)}</span>${badge ? `<span class="dsvc-env-badge">${badge}</span>` : ''}</div>`;
      }
      subCards += makeSubCard('environment', envBody);
    }

    if (portItems.length) {
      let portBody = '';
      for (const p of portItems) {
        const parts = p.split(':');
        const inner = parts.length >= 2
          ? `<span class="dsvc-port-host">${esc(parts[0])}</span><span class="dsvc-port-sep">→</span><span class="dsvc-port-cont">${esc(parts.slice(1).join(':'))}</span>`
          : `<span class="dsvc-port-cont">${esc(p)}</span>`;
        portBody += `<div class="dsvc-list-item"><span class="dsvc-port-badge">${inner}</span></div>`;
      }
      subCards += makeSubCard('ports', portBody);
    }

    if (volumeItems.length) {
      let volBody = '';
      for (const v of volumeItems) {
        const parts = v.split(':');
        const inner = parts.length >= 2
          ? `<span class="dsvc-vol-host">${esc(parts[0])}</span><span class="dsvc-vol-sep">:</span><span class="dsvc-vol-cont">${esc(parts.slice(1).join(':'))}</span>`
          : `<span class="dsvc-vol-host">${esc(v)}</span>`;
        volBody += `<div class="dsvc-list-item"><span class="dsvc-vol-badge">${inner}</span></div>`;
      }
      subCards += makeSubCard('volumes', volBody);
    }

    for (const [k, items] of listMap) {
      const listBody = items.map(item =>
        `<div class="dsvc-list-item"><span class="dsvc-net-badge">${esc(item)}</span></div>`
      ).join('');
      subCards += makeSubCard(k, listBody);
    }

    return `<div class="docker-service-card" data-chunk-id="${cid}">
      <div class="docker-service-header">
        <span class="docker-service-name">${esc(sc.name)}</span>
        <div class="docker-service-actions">
          <button class="btn btn-ghost btn-xs" data-action="copy-chunk-full" data-project-id="${pid}" data-chunk-id="${cid}" title="Copy YAML">${copySVG}</button>
          <button class="btn btn-ghost btn-xs" data-action="chunk-up"    data-project-id="${pid}" data-chunk-id="${cid}">↑</button>
          <button class="btn btn-ghost btn-xs" data-action="chunk-down"  data-project-id="${pid}" data-chunk-id="${cid}">↓</button>
          <button class="btn btn-ghost btn-xs" data-action="edit-chunk"  data-project-id="${pid}" data-chunk-id="${cid}">${editSVG}</button>
          <button class="btn btn-ghost btn-xs" data-action="delete-chunk" data-project-id="${pid}" data-chunk-id="${cid}" style="color:var(--price-paid)">${delSVG}</button>
        </div>
      </div>
      ${scalarsHtml ? `<div class="docker-service-scalars">${scalarsHtml}</div>` : ''}
      ${subCards  ? `<div class="docker-service-subcards">${subCards}</div>` : ''}
      ${!scalarsHtml && !subCards ? '<div class="dsvc-empty">No fields — click Edit to configure</div>' : ''}
    </div>`;
  };

  const card = document.createElement('div');
  card.className = 'chunk-card docker-services-card';
  card.innerHTML = `
    <div class="chunk-card-head">
      <span class="chunk-card-title">Services</span>
      ${svcChunks.length ? `<span class="chunk-type-badge">${svcChunks.length} service${svcChunks.length !== 1 ? 's' : ''}</span>` : ''}
      <div style="display:flex;gap:4px;margin-left:auto;flex-shrink:0">
        <button class="btn btn-ghost btn-sm" data-action="import-docker"          data-project-id="${pid}">Import</button>
        <button class="btn btn-ghost btn-sm" data-action="add-docker-service"     data-project-id="${pid}">+ Service</button>
        <button class="btn btn-ghost btn-sm" data-action="export-docker"          data-project-id="${pid}">Export</button>
        <button class="btn btn-ghost btn-sm" data-action="export-docker-services" data-project-id="${pid}" title="Copy services: block">${copySVG} All</button>
      </div>
    </div>
    <div class="docker-services-body">
      ${svcChunks.map(renderSvcCard).join('')}
      ${!svcChunks.length ? '<div class="chunk-no-fields">No services yet — click Import or + Service</div>' : ''}
    </div>
  `;
  return card;
}

export function getProjectTypeLabel(type: ProjectType): string {
  return ({
    wireguard: 'WireGuard', docker: 'Docker', nginx: 'Nginx',
    kubernetes: 'Kubernetes', ssh_config: 'SSH Config', traefik: 'Traefik',
    apache: 'Apache', haproxy: 'HAProxy', ansible: 'Ansible', postgres: 'PostgreSQL',
    generic: 'Generic',
  } as Record<string, string>)[type] ?? type;
}

export function makeConfigViewHeaderBtns(project: Project): string {
  const pid = escAttr(project.id);
  switch (project.project_type) {
    case 'wireguard':
      return `<button class="btn btn-ghost btn-sm" data-action="import-wg" data-project-id="${pid}">Import wg0.conf</button>
              <button class="btn btn-ghost btn-sm" data-action="add-wg-peer" data-project-id="${pid}">+ Add Peer</button>
              <button class="btn btn-ghost btn-sm" data-action="export-wg" data-project-id="${pid}">Export wg0.conf</button>`;
    case 'docker':
      return `<button class="btn btn-ghost btn-sm" data-action="add-docker-network" data-project-id="${pid}">+ Network</button>
              <button class="btn btn-ghost btn-sm" data-action="add-docker-volume" data-project-id="${pid}">+ Volume</button>`;
    case 'nginx':
      return `<button class="btn btn-ghost btn-sm" data-action="import-nginx" data-project-id="${pid}">Import site config</button>
              <button class="btn btn-ghost btn-sm" data-action="add-nginx-server" data-project-id="${pid}">+ Server</button>
              <button class="btn btn-ghost btn-sm" data-action="add-nginx-upstream" data-project-id="${pid}">+ Upstream</button>
              <button class="btn btn-ghost btn-sm" data-action="add-nginx-location" data-project-id="${pid}">+ Location</button>
              <button class="btn btn-ghost btn-sm" data-action="add-nginx-key" data-project-id="${pid}">+ Key File</button>
              <button class="btn btn-ghost btn-sm" data-action="export-nginx" data-project-id="${pid}">Export nginx.conf</button>`;
    case 'kubernetes':
      return `<button class="btn btn-ghost btn-sm" data-action="add-k8s-deployment" data-project-id="${pid}">+ Deploy</button>
              <button class="btn btn-ghost btn-sm" data-action="add-k8s-service" data-project-id="${pid}">+ Service</button>
              <button class="btn btn-ghost btn-sm" data-action="add-k8s-configmap" data-project-id="${pid}">+ ConfigMap</button>
              <button class="btn btn-ghost btn-sm" data-action="add-k8s-secret" data-project-id="${pid}">+ Secret</button>
              <button class="btn btn-ghost btn-sm" data-action="add-k8s-ingress" data-project-id="${pid}">+ Ingress</button>
              <button class="btn btn-ghost btn-sm" data-action="export-k8s" data-project-id="${pid}">Export YAML</button>`;
    case 'ssh_config':
      return `<button class="btn btn-ghost btn-sm" data-action="import-ssh" data-project-id="${pid}">Import Config</button>
              <button class="btn btn-ghost btn-sm" data-action="add-ssh-host" data-project-id="${pid}">+ Add Host</button>
              <button class="btn btn-ghost btn-sm" data-action="export-ssh" data-project-id="${pid}">Export ~/.ssh/config</button>`;
    case 'traefik':
      return `<button class="btn btn-ghost btn-sm" data-action="add-traefik-router" data-project-id="${pid}">+ Router</button>
              <button class="btn btn-ghost btn-sm" data-action="add-traefik-service" data-project-id="${pid}">+ Service</button>
              <button class="btn btn-ghost btn-sm" data-action="add-traefik-middleware" data-project-id="${pid}">+ Middleware</button>
              <button class="btn btn-ghost btn-sm" data-action="export-traefik" data-project-id="${pid}">Export traefik.yaml</button>`;
    case 'apache':
      return `<button class="btn btn-ghost btn-sm" data-action="import-apache" data-project-id="${pid}">Import httpd.conf</button>
              <button class="btn btn-ghost btn-sm" data-action="add-apache-vhost" data-project-id="${pid}">+ VirtualHost</button>
              <button class="btn btn-ghost btn-sm" data-action="add-apache-directory" data-project-id="${pid}">+ Directory</button>
              <button class="btn btn-ghost btn-sm" data-action="export-apache" data-project-id="${pid}">Export config</button>`;
    case 'haproxy':
      return `<button class="btn btn-ghost btn-sm" data-action="import-haproxy" data-project-id="${pid}">Import haproxy.cfg</button>
              <button class="btn btn-ghost btn-sm" data-action="add-haproxy-frontend" data-project-id="${pid}">+ Frontend</button>
              <button class="btn btn-ghost btn-sm" data-action="add-haproxy-backend" data-project-id="${pid}">+ Backend</button>
              <button class="btn btn-ghost btn-sm" data-action="export-haproxy" data-project-id="${pid}">Export haproxy.cfg</button>`;
    case 'ansible':
      return `<button class="btn btn-ghost btn-sm" data-action="add-ansible-vars" data-project-id="${pid}">+ vars</button>
              <button class="btn btn-ghost btn-sm" data-action="add-ansible-task" data-project-id="${pid}">+ task</button>
              <button class="btn btn-ghost btn-sm" data-action="export-ansible" data-project-id="${pid}">Export YAML</button>`;
    case 'postgres':
      return `<button class="btn btn-ghost btn-sm" data-action="add-pg-connection" data-project-id="${pid}">+ Connection</button>
              <button class="btn btn-ghost btn-sm" data-action="add-pg-role" data-project-id="${pid}">+ Role</button>
              <button class="btn btn-ghost btn-sm" data-action="export-postgres" data-project-id="${pid}">Export .pgpass</button>`;
    default:
      return '';
  }
}

export function exportNginx(project: Project): string {
  const chunks = project.chunks || [];
  const upstreams = chunks.filter(c => c.chunk_type === 'nginx_upstream');
  const servers   = chunks.filter(c => c.chunk_type === 'nginx_server');
  const locations = chunks.filter(c => c.chunk_type === 'nginx_location');
  const lines: string[] = ['# Generated by API Vault', ''];

  for (const u of upstreams) {
    lines.push(`upstream ${u.name} {`);
    for (const f of u.fields) {
      if (!f.value) continue;
      if (f.key === 'server') {
        for (const v of f.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)) lines.push(`    server ${v};`);
      } else {
        lines.push(`    ${f.key} ${f.value};`);
      }
    }
    lines.push('}', '');
  }

  for (const s of servers) {
    lines.push('server {');
    for (const f of s.fields) { if (f.value) lines.push(`    ${f.key} ${f.value};`); }
    if (locations.length) {
      lines.push('');
      for (const loc of locations) {
        const path = loc.fields.find(f => f.key === 'path')?.value || '/';
        lines.push(`    location ${path} {`);
        for (const f of loc.fields) { if (f.key !== 'path' && f.value) lines.push(`        ${f.key} ${f.value};`); }
        lines.push('    }');
      }
    }
    lines.push('}', '');
  }
  return lines.join('\n');
}

export function exportK8s(project: Project): string {
  const manifests: string[] = [];
  for (const chunk of project.chunks || []) {
    const name = chunk.fields.find(f => f.key === 'name')?.value || chunk.name;
    const ns   = chunk.fields.find(f => f.key === 'namespace')?.value || 'default';
    if (chunk.chunk_type === 'k8s_deployment') {
      const image = chunk.fields.find(f => f.key === 'image')?.value || 'nginx:latest';
      const replicas = chunk.fields.find(f => f.key === 'replicas')?.value || '1';
      const port = chunk.fields.find(f => f.key === 'containerPort')?.value || '80';
      const envFields = chunk.fields.filter(f => f.field_type === 'env_var' || f.field_type === 'secret');
      const envBlock = envFields.length
        ? '\n        env:' + envFields.map(f => `\n          - name: ${f.key}\n            value: ${JSON.stringify(f.value)}`).join('')
        : '';
      manifests.push(`apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: ${name}\n  namespace: ${ns}\nspec:\n  replicas: ${replicas}\n  selector:\n    matchLabels:\n      app: ${name}\n  template:\n    metadata:\n      labels:\n        app: ${name}\n    spec:\n      containers:\n        - name: ${name}\n          image: ${image}\n          ports:\n            - containerPort: ${port}${envBlock}`);
    } else if (chunk.chunk_type === 'k8s_service') {
      const port = chunk.fields.find(f => f.key === 'port')?.value || '80';
      const targetPort = chunk.fields.find(f => f.key === 'targetPort')?.value || '80';
      const type = chunk.fields.find(f => f.key === 'type')?.value || 'ClusterIP';
      manifests.push(`apiVersion: v1\nkind: Service\nmetadata:\n  name: ${name}\n  namespace: ${ns}\nspec:\n  selector:\n    app: ${name}\n  type: ${type}\n  ports:\n    - port: ${port}\n      targetPort: ${targetPort}`);
    } else if (chunk.chunk_type === 'k8s_configmap') {
      const dataFields = chunk.fields.filter(f => f.key !== 'name' && f.key !== 'namespace');
      manifests.push(`apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ${name}\n  namespace: ${ns}\ndata:\n${dataFields.map(f => `  ${f.key}: ${JSON.stringify(f.value)}`).join('\n')}`);
    } else if (chunk.chunk_type === 'k8s_secret') {
      const dataFields = chunk.fields.filter(f => f.key !== 'name' && f.key !== 'namespace');
      manifests.push(`apiVersion: v1\nkind: Secret\nmetadata:\n  name: ${name}\n  namespace: ${ns}\ntype: Opaque\ndata:\n${dataFields.map(f => `  ${f.key}: ${btoa(f.value)}`).join('\n')}`);
    } else if (chunk.chunk_type === 'k8s_ingress') {
      const host = chunk.fields.find(f => f.key === 'host')?.value || 'example.com';
      const svcName = chunk.fields.find(f => f.key === 'serviceName')?.value || name;
      const svcPort = chunk.fields.find(f => f.key === 'servicePort')?.value || '80';
      manifests.push(`apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: ${name}\n  namespace: ${ns}\nspec:\n  rules:\n    - host: ${host}\n      http:\n        paths:\n          - path: /\n            pathType: Prefix\n            backend:\n              service:\n                name: ${svcName}\n                port:\n                  number: ${svcPort}`);
    }
  }
  return manifests.join('\n---\n');
}

export function exportSshConfig(project: Project): string {
  const lines: string[] = ['# Generated by API Vault', ''];
  for (const chunk of project.chunks || []) {
    if (chunk.chunk_type !== 'ssh_host') continue;
    lines.push(`Host ${chunk.name}`);
    for (const f of chunk.fields) { if (f.value) lines.push(`    ${f.key} ${f.value}`); }
    lines.push('');
  }
  return lines.join('\n');
}

export function exportTraefik(project: Project): string {
  const chunks = project.chunks || [];
  const routers     = chunks.filter(c => c.chunk_type === 'traefik_router');
  const services    = chunks.filter(c => c.chunk_type === 'traefik_service');
  const middlewares = chunks.filter(c => c.chunk_type === 'traefik_middleware');
  const lines: string[] = ['# Generated by API Vault', 'http:'];

  if (routers.length) {
    lines.push('  routers:');
    for (const r of routers) {
      lines.push(`    ${r.name}:`);
      for (const f of r.fields) {
        if (!f.value) continue;
        if (f.field_type === 'list') {
          lines.push(`      ${f.key}:`);
          for (const item of f.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)) lines.push(`        - ${item}`);
        } else {
          lines.push(`      ${f.key}: ${JSON.stringify(f.value)}`);
        }
      }
    }
  }
  if (services.length) {
    lines.push('  services:');
    for (const s of services) {
      const url = s.fields.find(f => f.key === 'url')?.value || '';
      const passHost = s.fields.find(f => f.key === 'passHostHeader')?.value || 'true';
      lines.push(`    ${s.name}:`, `      loadBalancer:`, `        passHostHeader: ${passHost}`);
      if (url) { lines.push(`        servers:`, `          - url: ${JSON.stringify(url)}`); }
    }
  }
  if (middlewares.length) {
    lines.push('  middlewares:');
    for (const m of middlewares) {
      const type = m.fields.find(f => f.key === 'type')?.value || '';
      lines.push(`    ${m.name}:`);
      if (type) {
        lines.push(`      ${type}:`);
        for (const f of m.fields) { if (f.key !== 'type' && f.value) lines.push(`        ${f.key}: ${f.value}`); }
      }
    }
  }
  return lines.join('\n');
}

// ── Parsers ────────────────────────────────────────────────────────────────

export function parseWgConf(text: string): SecretChunk[] {
  const chunks: SecretChunk[] = [];
  let cur: SecretChunk | null = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line === '[Interface]') {
      cur = { id: crypto.randomUUID(), name: 'Interface', chunk_type: 'wg_interface', fields: [] };
      chunks.push(cur);
    } else if (line === '[Peer]') {
      const n = chunks.filter(c => c.chunk_type === 'wg_peer').length + 1;
      cur = { id: crypto.randomUUID(), name: `Peer ${n}`, chunk_type: 'wg_peer', fields: [] };
      chunks.push(cur);
    } else if (cur) {
      const eq = line.indexOf('=');
      if (eq < 0) continue;
      const key = line.slice(0, eq).trim();
      const val = line.slice(eq + 1).trim().replace(/\s+#.*$/, '');
      const isSecret = key === 'PrivateKey' || key === 'PresharedKey';
      const ft: ChunkFieldType = isSecret ? 'secret'
        : /^(Address|AllowedIPs)$/i.test(key) ? 'subnet'
        : /^DNS$/i.test(key) ? 'ip'
        : /^Endpoint$/i.test(key) ? 'endpoint'
        : /^ListenPort$/i.test(key) ? 'port'
        : /^(PostUp|PostDown|PreUp|PreDown)$/i.test(key) ? 'multiline'
        : 'var';
      cur.fields.push({ key, value: val, field_type: ft, secret: isSecret || undefined });
    }
  }
  return chunks;
}

export function parseDockerCompose(text: string): SecretChunk[] {
  const chunks: SecretChunk[] = [];
  const lines = text.split(/\r?\n/);

  let baseIndent = 0;
  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const ind = line.length - line.trimStart().length;
    if (ind > 0) { baseIndent = ind; break; }
  }
  if (baseIndent === 0) baseIndent = 2;

  type Top = 'none' | 'services' | 'networks' | 'volumes';
  type Ctx = 'none' | 'service' | 'env' | 'list';
  let top: Top = 'none', ctx: Ctx = 'none';
  let svc: SecretChunk | null = null;
  let listKey = '', listVals: string[] = [];
  let netChunk: SecretChunk | null = null;
  let volChunk: SecretChunk | null = null;

  const stripVal = (raw: string) =>
    raw.replace(/\s+#.*$/, '').trim().replace(/^["']+|["']+$/g, '');

  const flushList = () => {
    if (svc && listKey && listVals.length) {
      const ft: ChunkFieldType = listKey === 'ports' ? 'port' : listKey === 'volumes' ? 'volume_mount' : 'list';
      svc.fields.push({ key: listKey, value: listVals.join('\n'), field_type: ft });
    }
    listKey = ''; listVals = [];
  };

  const detectSvcFieldType = (key: string): ChunkFieldType => {
    if (/^user(_?id)?$/i.test(key)) return 'user_id';
    return 'var';
  };

  for (const raw of lines) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const ind   = raw.length - raw.trimStart().length;
    const level = Math.round(ind / baseIndent);

    if (level === 0) {
      flushList(); svc = null; ctx = 'none';
      const stripped = trimmed.split(/\s+#/)[0].trimEnd();
      top = stripped === 'services:' ? 'services'
          : stripped === 'networks:' ? 'networks'
          : stripped === 'volumes:'  ? 'volumes'
          : 'none';
    } else if (level === 1) {
      flushList(); ctx = 'none';
      const name = trimmed.split(':')[0].trim();
      if (!name) continue;
      if (top === 'services') {
        svc = { id: crypto.randomUUID(), name, chunk_type: 'docker_service', fields: [] };
        chunks.push(svc); ctx = 'service';
      } else if (top === 'networks') {
        if (!netChunk) {
          netChunk = { id: crypto.randomUUID(), name: 'networks', chunk_type: 'docker_network', fields: [] };
          chunks.push(netChunk);
        }
        netChunk.fields.push({ key: name, value: '', field_type: 'var' });
      } else if (top === 'volumes') {
        if (!volChunk) {
          volChunk = { id: crypto.randomUUID(), name: 'volumes', chunk_type: 'docker_volume', fields: [] };
          chunks.push(volChunk);
        }
        volChunk.fields.push({ key: name, value: '', field_type: 'var' });
      }
    } else if (level === 2 && svc) {
      flushList();
      if (trimmed === 'environment:') { ctx = 'env'; }
      else if (trimmed.endsWith(':') && !trimmed.includes(': ')) {
        listKey = trimmed.slice(0, -1); listVals = []; ctx = 'list';
      } else {
        ctx = 'service';
        const ci = trimmed.indexOf(': ');
        if (ci > 0) {
          const key = trimmed.slice(0, ci).trim();
          const val = stripVal(trimmed.slice(ci + 2));
          svc.fields.push({ key, value: val, field_type: detectSvcFieldType(key) });
        }
      }
    } else if (level >= 3 && svc) {
      if (ctx === 'env') {
        const envLine = trimmed.startsWith('- ') ? trimmed.slice(2) : trimmed;
        const ei  = envLine.indexOf('=');
        const ci2 = envLine.indexOf(': ');
        let key = '', val = '';
        if (ei > 0)       { key = envLine.slice(0, ei).trim();  val = stripVal(envLine.slice(ei + 1)); }
        else if (ci2 > 0) { key = envLine.slice(0, ci2).trim(); val = stripVal(envLine.slice(ci2 + 2)); }
        if (key) {
          const isRef = /^\$\{.+\}$/.test(val);
          const isSecret = !isRef && /pass(word)?|secret|key|token|cred/i.test(key) && val !== '';
          const ft: ChunkFieldType = isRef ? 'env_var' : (isSecret ? 'secret' : 'var');
          svc.fields.push({ key, value: val, field_type: ft, secret: isSecret || undefined, description: 'env' });
        }
      } else if (ctx === 'list' && trimmed.startsWith('- ')) {
        listVals.push(stripVal(trimmed.slice(2)));
      }
    }
  }
  flushList();
  return chunks;
}

export function parseSshConfig(text: string): SecretChunk[] {
  const chunks: SecretChunk[] = [];
  let cur: SecretChunk | null = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^(\S+)\s+(.+)$/);
    if (!m) continue;
    const [, key, val] = m;
    if (key.toLowerCase() === 'host') {
      cur = { id: crypto.randomUUID(), name: val.trim(), chunk_type: 'ssh_host', fields: [] };
      chunks.push(cur);
    } else if (cur) {
      cur.fields.push({ key, value: val.trim(), field_type: 'var' });
    }
  }
  return chunks;
}

export function parseNginxConf(text: string): SecretChunk[] {
  const chunks: SecretChunk[] = [];
  const toks: string[] = [];

  // Tokenize: strip # comments, split at ; { } respecting quoted strings
  {
    let buf = '', inSQ = false, inDQ = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (!inSQ && !inDQ && c === '#') { while (i < text.length && text[i] !== '\n') i++; continue; }
      if (c === "'" && !inDQ) { inSQ = !inSQ; buf += c; continue; }
      if (c === '"' && !inSQ) { inDQ = !inDQ; buf += c; continue; }
      if (!inSQ && !inDQ && (c === '{' || c === '}' || c === ';')) {
        if (buf.trim()) toks.push(buf.trim());
        toks.push(c);
        buf = '';
      } else if (!inSQ && !inDQ && /\s/.test(c)) {
        if (buf.length && !buf.endsWith(' ')) buf += ' ';
      } else {
        buf += c;
      }
    }
    if (buf.trim()) toks.push(buf.trim());
  }

  let pos = 0;
  const MULTI_ARG = /^(add_header|proxy_set_header|more_set_headers|fastcgi_param)$/i;

  function ftype(key: string): ChunkFieldType {
    const base = key.split(/\s+/)[0];
    if (/^listen$/i.test(base)) return 'port';
    if (/^(ssl_certificate|ssl_certificate_key|ssl_trusted_certificate)$/i.test(base)) return 'cert';
    if (/^(proxy_pass|fastcgi_pass|uwsgi_pass|grpc_pass)$/i.test(base)) return 'endpoint';
    if (MULTI_ARG.test(base)) return 'multiline';
    return 'var';
  }

  function parseToken(tok: string): { key: string; val: string } {
    const sp = tok.split(/\s+/);
    if (MULTI_ARG.test(sp[0]) && sp.length >= 3) {
      return { key: `${sp[0]} ${sp[1]}`, val: sp.slice(2).join(' ') };
    }
    return { key: sp[0], val: sp.slice(1).join(' ') };
  }

  function skipBlock() {
    let d = 1;
    while (pos < toks.length && d > 0) {
      if (toks[pos] === '{') d++;
      else if (toks[pos] === '}') d--;
      pos++;
    }
  }

  function parseDirectives(chunk: SecretChunk, locs?: SecretChunk[]) {
    while (pos < toks.length) {
      const tok = toks[pos];
      if (tok === '}') { pos++; return; }
      if (tok === ';') { pos++; continue; }
      pos++;
      const next = toks[pos] ?? '';
      if (next === '{') {
        pos++;
        const parts = tok.split(/\s+/);
        const bt = parts[0].toLowerCase();
        const ba = parts.slice(1).join(' ');
        if (bt === 'location' && locs) {
          const loc: SecretChunk = {
            id: crypto.randomUUID(),
            name: `location ${ba}`,
            chunk_type: 'nginx_location',
            fields: [{ key: 'path', value: ba, field_type: 'var' }],
          };
          parseDirectives(loc);
          locs.push(loc);
        } else {
          skipBlock();
        }
      } else if (next === ';') {
        pos++;
        const { key, val } = parseToken(tok);
        if (key) chunk.fields.push({ key, value: val, field_type: ftype(key) });
      }
    }
  }

  function nameServer(c: SecretChunk, n: number): string {
    const listen = c.fields.find(f => f.key === 'listen');
    const sname  = c.fields.find(f => f.key === 'server_name');
    const port   = listen?.value.match(/(\d+)/)?.[1] ?? '80';
    const domain = sname?.value.split(/\s+/).find(s => !s.startsWith('www.'))
      ?? sname?.value.split(/\s+/)[0];
    return domain ? `${domain}:${port}` : `server-${n}`;
  }

  function parseContainer() {
    while (pos < toks.length) {
      const tok = toks[pos];
      if (tok === '}') { pos++; return; }
      if (tok === ';') { pos++; continue; }
      pos++;
      const next = toks[pos] ?? '';
      if (next === '{') {
        pos++;
        const parts = tok.split(/\s+/);
        const bt = parts[0].toLowerCase();
        const ba = parts.slice(1).join(' ');
        if (bt === 'server') {
          const n = chunks.filter(c => c.chunk_type === 'nginx_server').length + 1;
          const sv: SecretChunk = {
            id: crypto.randomUUID(),
            name: `server-${n}`,
            chunk_type: 'nginx_server',
            fields: [],
          };
          const locs: SecretChunk[] = [];
          parseDirectives(sv, locs);
          sv.name = nameServer(sv, n);
          chunks.push(sv, ...locs);
        } else if (bt === 'upstream') {
          const up: SecretChunk = {
            id: crypto.randomUUID(),
            name: ba || 'upstream',
            chunk_type: 'nginx_upstream',
            fields: [],
          };
          parseDirectives(up);
          chunks.push(up);
        } else if (bt === 'http' || bt === 'stream') {
          parseContainer();
        } else {
          skipBlock();
        }
      } else if (next === ';') {
        pos++;
      }
    }
  }

  parseContainer();
  return chunks;
}

export function pickFileText(accept: string, cb: (text: string, name: string) => void | Promise<void>): void {
  const inp = document.createElement('input');
  inp.type = 'file';
  inp.accept = accept;
  document.body.appendChild(inp);
  let done = false;
  const cleanup = () => { if (done) return; done = true; if (document.body.contains(inp)) document.body.removeChild(inp); };
  inp.addEventListener('change', function () {
    const file = (this as HTMLInputElement).files?.[0];
    if (!file) { cleanup(); return; }
    const reader = new FileReader();
    reader.onload = ev => cb(ev.target!.result as string, file.name);
    reader.readAsText(file);
    cleanup();
  }, { once: true });
  inp.addEventListener('cancel', cleanup, { once: true });
  inp.click();
  setTimeout(() => window.addEventListener('focus', cleanup, { once: true }), 300);
}

// ── Chunk edit modal ───────────────────────────────────────────────────────

export function openChunkEditModal(project: Project, chunk: SecretChunk) {
  const overlay = document.getElementById('chunk-edit-overlay')!;
  (document.getElementById('chunk-edit-name') as HTMLInputElement).value = chunk.name;
  (document.getElementById('chunk-edit-notes') as HTMLInputElement).value = chunk.notes || '';
  (document.getElementById('chunk-edit-disabled') as HTMLInputElement).checked = !!chunk.disabled;
  (document.getElementById('chunk-edit-project-id') as HTMLInputElement).value = project.id;
  (document.getElementById('chunk-edit-chunk-id') as HTMLInputElement).value = chunk.id;
  renderChunkEditFields(chunk.fields);
  overlay.classList.add('open');
}

export function closeChunkEditModal() {
  document.getElementById('chunk-edit-overlay')!.classList.remove('open');
}

export function renderChunkEditFields(fields: ChunkField[]) {
  const container = document.getElementById('chunk-edit-fields')!;
  container.innerHTML = '';
  fields.forEach((field, i) => {
    const row = document.createElement('div');
    row.className = 'chunk-edit-row';
    row.dataset.idx = String(i);
    row.innerHTML = `
      <input class="form-input mono chunk-field-key-input" placeholder="Key" value="${escAttr(field.key)}" style="flex:0 0 140px">
      <input class="form-input mono chunk-field-val-input" placeholder="Value or \${REF}" value="${escAttr(field.value)}" style="flex:1">
      <select class="form-input chunk-field-type-select" style="flex:0 0 110px">
        <option value="var"${field.field_type === 'var' ? ' selected' : ''}>var</option>
        <option value="env_var"${field.field_type === 'env_var' ? ' selected' : ''}>env_var</option>
        <option value="secret"${field.field_type === 'secret' ? ' selected' : ''}>secret</option>
        <option value="list"${field.field_type === 'list' ? ' selected' : ''}>list</option>
        <option value="multiline"${field.field_type === 'multiline' ? ' selected' : ''}>multiline</option>
        <option value="port"${field.field_type === 'port' ? ' selected' : ''}>port</option>
        <option value="user_id"${field.field_type === 'user_id' ? ' selected' : ''}>user_id</option>
        <option value="subnet"${field.field_type === 'subnet' ? ' selected' : ''}>subnet</option>
        <option value="ip"${field.field_type === 'ip' ? ' selected' : ''}>ip</option>
        <option value="endpoint"${field.field_type === 'endpoint' ? ' selected' : ''}>endpoint</option>
        <option value="volume_mount"${field.field_type === 'volume_mount' ? ' selected' : ''}>volume_mount</option>
        <option value="cert"${field.field_type === 'cert' ? ' selected' : ''}>cert</option>
      </select>
      <button class="icon-btn sm danger chunk-field-delete" data-idx="${i}" title="Remove field">${delSVG}</button>
    `;
    container.appendChild(row);
  });

  container.querySelectorAll<HTMLButtonElement>('.chunk-field-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = parseInt(btn.dataset.idx!);
      const currentFields = readChunkEditFields();
      currentFields.splice(idx, 1);
      renderChunkEditFields(currentFields);
    });
  });
}

export function readChunkEditFields(): ChunkField[] {
  const rows = document.querySelectorAll<HTMLElement>('#chunk-edit-fields .chunk-edit-row');
  return Array.from(rows).map(row => ({
    key: (row.querySelector('.chunk-field-key-input') as HTMLInputElement).value.trim(),
    value: (row.querySelector('.chunk-field-val-input') as HTMLInputElement).value,
    field_type: (row.querySelector('.chunk-field-type-select') as HTMLSelectElement).value as ChunkFieldType,
    secret: (row.querySelector('.chunk-field-type-select') as HTMLSelectElement).value === 'secret',
  }));
}

export function saveChunkEdit() {
  const projId = (document.getElementById('chunk-edit-project-id') as HTMLInputElement).value;
  const chunkId = (document.getElementById('chunk-edit-chunk-id') as HTMLInputElement).value;
  const name = (document.getElementById('chunk-edit-name') as HTMLInputElement).value.trim();
  if (!name) { showToast('Chunk name is required', 'err'); return; }
  const project = st.vault.projects.find(p => p.id === projId);
  if (!project || !project.chunks) return;
  const chunk = project.chunks.find(c => c.id === chunkId);
  if (!chunk) return;
  chunk.name = name;
  chunk.notes = (document.getElementById('chunk-edit-notes') as HTMLInputElement).value.trim() || undefined;
  chunk.disabled = (document.getElementById('chunk-edit-disabled') as HTMLInputElement).checked || undefined;
  chunk.fields = readChunkEditFields();
  st.store.save(st.vault);
  closeChunkEditModal();
  triggerRender();
  showToast('Chunk saved', 'ok');
}
