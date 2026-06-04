/**
 * @file Chunk operations — starter chunks, chunk card rendering,
 *       config exporters/parsers, chunk edit modal.
 */

import type { Project, SecretChunk, ChunkField, ChunkFieldType, ProjectType, VaultEntry } from './types';
import { st, Settings, triggerRender } from './state';
import { esc, escAttr, copySVG, delSVG, showToast } from './utils';

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
      id: crypto.randomUUID(), name: 'server-80', chunk_type: 'nginx_server',
      fields: [
        { key: 'listen',      value: '80',                            field_type: 'var' },
        { key: 'server_name', value: 'example.com',                   field_type: 'var' },
        { key: 'root',        value: '/var/www/html',                  field_type: 'var' },
        { key: 'access_log',  value: '/var/log/nginx/access.log',      field_type: 'var' },
        { key: 'error_log',   value: '/var/log/nginx/error.log',       field_type: 'var' },
      ],
    },
    {
      id: crypto.randomUUID(), name: 'location-root', chunk_type: 'nginx_location',
      fields: [
        { key: 'path',                              value: '/',                              field_type: 'var' },
        { key: 'proxy_pass',                        value: 'http://app:8080',                field_type: 'var' },
        { key: 'proxy_set_header Host',             value: '$host',                          field_type: 'var' },
        { key: 'proxy_set_header X-Real-IP',        value: '$remote_addr',                   field_type: 'var' },
        { key: 'proxy_set_header X-Forwarded-For',  value: '$proxy_add_x_forwarded_for',     field_type: 'var' },
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

// ── Field resolution ───────────────────────────────────────────────────────

export function resolveFieldRef(value: string, useEnvCopyField = false): { resolved: string | null; refName: string | null; unresolved: boolean } {
  const match = value.match(/^\$\{(.+)}$/);
  if (!match) return { resolved: value, refName: null, unresolved: false };
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
    return { resolved, refName, unresolved: false };
  }

  for (const project of st.vault.projects) {
    for (const chunk of project.chunks || []) {
      if (chunk.chunk_type !== 'env_file') continue;
      const field = chunk.fields.find(f => f.key === refName);
      if (field) return { resolved: field.value, refName, unresolved: false };
    }
  }
  return { resolved: null, refName, unresolved: true };
}

// ── Chunk card renderer ────────────────────────────────────────────────────

export function renderChunkCard(chunk: SecretChunk, project: Project): HTMLElement {
  const card = document.createElement('div');
  card.className = 'chunk-card';
  const typeLabel = chunk.chunk_type.replace(/_/g, ' ');

  const isWg = chunk.chunk_type === 'wg_interface' || chunk.chunk_type === 'wg_peer';
  const isDockerSvc = chunk.chunk_type === 'docker_service';

  const chunkEnvFields = isDockerSvc ? chunk.fields.filter(f => f.description === 'env') : [];
  const hasChunkEnvFields = chunkEnvFields.length > 0;
  const hasChunkEnvRefs = chunkEnvFields.some(f => /^\$\{.+\}$/.test(f.value));

  let fieldsHtml = '';
  for (const field of chunk.fields) {
    const { resolved, refName, unresolved } = resolveFieldRef(field.value);
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
      if (isDockerSvc && field.field_type === 'list') {
        if (field.key === 'volumes') effType = 'volume_mount';
      }
    }

    let displayVal = '';
    let badgeHtml = '';

    if (refName) {
      if (unresolved) {
        displayVal = `\${${refName}}`;
        badgeHtml = `<span class="chunk-ref-badge chunk-ref-unresolved" title="No vault entry found for '${esc(refName)}'">unresolved: ${esc(refName)}</span>`;
      } else {
        displayVal = '••••••••';
        badgeHtml = `<span class="chunk-ref-badge" title="Linked from vault entry '${esc(refName)}'">linked: ${esc(refName)}</span>`;
      }
    } else if (isSecret && field.value) {
      displayVal = '••••••••';
    } else {
      displayVal = field.value || '';
    }

    const isEnvField = isDockerSvc && field.description === 'env';
    const envCopyResolved = (isEnvField && refName) ? resolveFieldRef(field.value, true).resolved : null;
    const valClass = `chunk-field-val${isSecret && field.value ? ' masked' : ''}`;
    const copyData = isEnvField
      ? `${field.key}=${field.value}`
      : (isSecret || refName) ? (resolved ?? field.value)
      : field.value;
    const isMultiline = (effType === 'multiline' || effType === 'list') && !isSecret && !refName;
    const copyBtn = copyData ? `<button class="icon-btn sm" data-action="chunk-copy" data-value="${escAttr(copyData)}" title="Copy">${copySVG}</button>` : '';
    const envCopyBtn = envCopyResolved !== null
      ? `<button class="btn btn-ghost btn-xs" data-action="chunk-copy" data-value="${escAttr(`${field.key}=${envCopyResolved}`)}" title="Copy resolved (.env)">.env</button>`
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

    if (effType === 'port') {
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
    } else if (effType === 'ip') {
      const ips = (displayVal || '').split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
      const badges = ips.map(ip => `<span class="ip-badge">${esc(ip)}</span>`).join('');
      fieldsHtml += `
        <div class="chunk-field-row">
          <span class="chunk-field-key">${esc(field.key)}</span>
          <div class="chunk-field-val badge-list">${badges || '<span style="color:var(--text3);font-size:10px">empty</span>'}</div>
          <div class="chunk-field-actions">${copyBtn}</div>
        </div>`;
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

  card.innerHTML = `
    <div class="chunk-card-head">
      <span class="chunk-card-title">${esc(chunk.name)}</span>
      <span class="chunk-type-badge">${esc(typeLabel)}</span>
      <div style="display:flex;gap:4px;margin-left:auto">
        ${chunk.chunk_type === 'env_file' ? `<button class="btn btn-ghost btn-sm" data-action="export-env-chunk" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}">Export .env</button>` : ''}
        ${hasChunkEnvFields ? `<button class="btn btn-ghost btn-sm" data-action="copy-chunk-raw" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" title="Copy all env fields as KEY=value">Copy</button>` : ''}
        ${hasChunkEnvRefs ? `<button class="btn btn-ghost btn-sm" data-action="copy-chunk-env" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" title="Copy env fields with resolved values">Copy .env</button>` : ''}
        <button class="btn btn-ghost btn-sm" data-action="chunk-up" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" title="Move up">↑</button>
        <button class="btn btn-ghost btn-sm" data-action="chunk-down" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" title="Move down">↓</button>
        <button class="btn btn-ghost btn-sm" data-action="dup-chunk" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}">Dup</button>
        <button class="btn btn-ghost btn-sm" data-action="edit-chunk" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}">Edit</button>
        <button class="btn btn-ghost btn-sm" data-action="delete-chunk" data-project-id="${escAttr(project.id)}" data-chunk-id="${escAttr(chunk.id)}" style="color:var(--price-paid)">Delete</button>
      </div>
    </div>
    <div class="chunk-fields">${fieldsHtml || '<div class="chunk-no-fields">No fields</div>'}</div>
  `;
  return card;
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

  const lines: string[] = ['# Generated by API Vault', ''];
  const envLines: string[] = [];

  if (networkChunks.length) {
    lines.push('networks:');
    for (const nc of networkChunks) {
      if (nc.fields.length > 0) {
        for (const f of nc.fields) {
          if (!f.key) continue;
          lines.push(`  ${f.key}:`);
          if (f.value) lines.push(`    driver: ${f.value}`);
        }
      } else {
        lines.push(`  ${nc.name}:`);
      }
    }
    lines.push('');
  }

  if (volumeChunks.length) {
    lines.push('volumes:');
    for (const vc of volumeChunks) {
      if (vc.fields.length > 0) {
        for (const f of vc.fields) {
          if (!f.key) continue;
          lines.push(`  ${f.key}:`);
        }
      } else {
        lines.push(`  ${vc.name}:`);
      }
    }
    lines.push('');
  }

  if (serviceChunks.length) {
    lines.push('services:');
    for (const sc of serviceChunks) {
      const svcName = sc.name.replace(/\s+/g, '_').toLowerCase();
      lines.push(`  ${svcName}:`);
      const envFields  = sc.fields.filter(f => f.description === 'env' || f.field_type === 'env_var');
      const portFields = sc.fields.filter(f => f.field_type === 'port' && f.description !== 'env');
      const listFields = sc.fields.filter(f => (f.field_type === 'list' || f.field_type === 'volume_mount') && f.description !== 'env');
      const varFields  = sc.fields.filter(f =>
        f.description !== 'env' && f.field_type !== 'env_var' &&
        f.field_type !== 'port' && f.field_type !== 'list' && f.field_type !== 'volume_mount' &&
        f.field_type !== 'subnet' && f.field_type !== 'ip' && f.field_type !== 'endpoint' &&
        f.key !== 'restart'
      );

      const scalarFields = [...varFields, ...sc.fields.filter(f =>
        (f.field_type === 'subnet' || f.field_type === 'ip' || f.field_type === 'endpoint') && f.description !== 'env'
      )];
      for (const f of scalarFields) {
        if (f.value == null || f.value === '') continue;
        lines.push(`    ${f.key}: ${JSON.stringify(f.value)}`);
      }

      for (const f of portFields) {
        if (!f.value) continue;
        const items = f.value.split(/\n/).map(s => s.trim()).filter(Boolean);
        lines.push(`    ports:`);
        for (const item of items) lines.push(`      - ${JSON.stringify(item)}`);
      }

      for (const f of listFields) {
        if (!f.value) continue;
        const items = f.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
        lines.push(`    ${f.key}:`);
        for (const item of items) lines.push(`      - ${JSON.stringify(item)}`);
      }

      if (envFields.length) {
        lines.push('    environment:');
        for (const f of envFields) {
          const ref = f.ref_name || (f.value.match(/^\$\{(.+)}$/) || [])[1];
          if (ref) {
            lines.push(`      ${f.key}: "\${${ref}}"`);
            const entry = st.vault.api_keys.find(e => e.provider === ref);
            envLines.push(`${ref}=${entry ? entry.api_key : ''}`);
          } else {
            lines.push(`      ${f.key}: ${JSON.stringify(f.value)}`);
          }
        }
      }

      const restartF = sc.fields.find(f => f.key === 'restart');
      lines.push(`    restart: ${restartF?.value || 'unless-stopped'}`);
      lines.push('');
    }
  }

  return { yaml: lines.join('\n'), envFile: envLines.join('\n') };
}

export function getProjectTypeLabel(type: ProjectType): string {
  return ({ wireguard: 'WireGuard', docker: 'Docker', nginx: 'Nginx', kubernetes: 'Kubernetes', ssh_config: 'SSH Config', traefik: 'Traefik', generic: 'Generic' } as Record<string, string>)[type] ?? type;
}

export function makeConfigViewHeaderBtns(project: Project): string {
  const pid = escAttr(project.id);
  switch (project.project_type) {
    case 'wireguard':
      return `<button class="btn btn-ghost btn-sm" data-action="import-wg" data-project-id="${pid}">Import wg0.conf</button>
              <button class="btn btn-ghost btn-sm" data-action="add-wg-peer" data-project-id="${pid}">+ Add Peer</button>
              <button class="btn btn-ghost btn-sm" data-action="export-wg" data-project-id="${pid}">Export wg0.conf</button>`;
    case 'docker':
      return `<button class="btn btn-ghost btn-sm" data-action="import-docker" data-project-id="${pid}">Import Compose</button>
              <button class="btn btn-ghost btn-sm" data-action="add-docker-service" data-project-id="${pid}">+ Service</button>
              <button class="btn btn-ghost btn-sm" data-action="add-docker-network" data-project-id="${pid}">+ Network</button>
              <button class="btn btn-ghost btn-sm" data-action="add-docker-volume" data-project-id="${pid}">+ Volume</button>
              <button class="btn btn-ghost btn-sm" data-action="export-docker" data-project-id="${pid}">Export Compose</button>`;
    case 'nginx':
      return `<button class="btn btn-ghost btn-sm" data-action="add-nginx-server" data-project-id="${pid}">+ Server</button>
              <button class="btn btn-ghost btn-sm" data-action="add-nginx-upstream" data-project-id="${pid}">+ Upstream</button>
              <button class="btn btn-ghost btn-sm" data-action="add-nginx-location" data-project-id="${pid}">+ Location</button>
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
  chunk.fields = readChunkEditFields();
  st.store.save(st.vault);
  closeChunkEditModal();
  triggerRender();
  showToast('Chunk saved', 'ok');
}
