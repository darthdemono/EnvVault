/**
 * @file
 * Config-file parsers — turn a pasted or imported config
 * (wg0.conf, docker-compose.yml, nginx site, Apache vhost, HAProxy,
 * ssh_config) into structured `SecretChunk`s.
 *
 * All hand-written line scanners: deliberately lenient, ignoring what they do
 * not understand rather than failing the whole import.
 */

import type { SecretChunk, ChunkField, ChunkFieldType, ChunkType } from '../types';
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

    const openM = /^<(\w+)\s*(.*)>$/.exec(line);
    const closeM = /^<\/(\w+)>$/.exec(line);

    if (openM) {
      depth++;
      blockType = openM[1].toLowerCase();
      blockArg = openM[2].trim();
      if (depth === 1) {
        const chunkType: ChunkType =
          blockType === 'virtualhost' ? 'apache_vhost' : 'apache_directory';
        const n = chunks.filter((c) => c.chunk_type === chunkType).length + 1;
        cur = {
          id: crypto.randomUUID(),
          name: `${blockType}-${n}`,
          chunk_type: chunkType,
          fields: [],
        };
        if (blockType === 'directory') {
          cur.fields.push({ key: 'path', value: blockArg, field_type: 'var' });
        }
        chunks.push(cur);
      }
    } else if (closeM) {
      // Clamp at zero. An unbalanced closing tag drove depth negative, and the
      // next opening tag then only brought it back to 0 — so `depth === 1`
      // never held again and every directive in the rest of the file was
      // silently dropped.
      depth = Math.max(0, depth - 1);
      if (depth === 0) {
        cur = null;
        blockType = '';
        blockArg = '';
      }
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

    // `\s*` let the keyword match a prefix of a longer word, so a directive
    // like `backend_name x` opened a spurious section. Require a word boundary.
    const sectionM = /^(global|defaults|frontend|backend|listen)(?:\s+(.*))?$/.exec(line);
    if (sectionM) {
      const stype = sectionM[1];
      const sname = (sectionM[2] ?? '').trim() || stype;
      const chunkType: ChunkType =
        stype === 'frontend'
          ? 'haproxy_frontend'
          : stype === 'backend'
            ? 'haproxy_backend'
            : 'haproxy_global';
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
      const n = chunks.filter((c) => c.chunk_type === 'wg_peer').length + 1;
      cur = { id: crypto.randomUUID(), name: `Peer ${n}`, chunk_type: 'wg_peer', fields: [] };
      chunks.push(cur);
    } else if (cur) {
      const eq = line.indexOf('=');
      if (eq < 0) continue;
      const key = line.slice(0, eq).trim();
      const val = line
        .slice(eq + 1)
        .trim()
        .replace(/\s+#.*$/, '');
      // Case-insensitive, like every other key test in this function and like
      // wg-quick itself. Exact-match comparison meant a config written
      // `privatekey = …` — which WireGuard accepts — imported the private key
      // as an ordinary field: shown in clear in the UI and copied in clear on
      // export, with nothing marking it as a secret.
      const isSecret = /^(PrivateKey|PresharedKey)$/i.test(key);
      const ft: ChunkFieldType = isSecret
        ? 'secret'
        : /^(Address|AllowedIPs)$/i.test(key)
          ? 'subnet'
          : /^DNS$/i.test(key)
            ? 'ip'
            : /^Endpoint$/i.test(key)
              ? 'endpoint'
              : /^ListenPort$/i.test(key)
                ? 'port'
                : /^(PostUp|PostDown|PreUp|PreDown)$/i.test(key)
                  ? 'multiline'
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
    if (ind > 0) {
      baseIndent = ind;
      break;
    }
  }
  if (baseIndent === 0) baseIndent = 2;

  type Top = 'none' | 'services' | 'networks' | 'volumes';
  type Ctx = 'none' | 'service' | 'env' | 'list';
  let top: Top = 'none',
    ctx: Ctx = 'none';
  let svc: SecretChunk | null = null;
  let listKey = '',
    listVals: string[] = [];
  let netChunk: SecretChunk | null = null;
  let volChunk: SecretChunk | null = null;

  const stripVal = (raw: string) =>
    raw
      .replace(/\s+#.*$/, '')
      .trim()
      .replace(/^["']+|["']+$/g, '');

  const flushList = () => {
    if (svc && listKey && listVals.length) {
      const ft: ChunkFieldType =
        listKey === 'ports' ? 'port' : listKey === 'volumes' ? 'volume_mount' : 'list';
      svc.fields.push({ key: listKey, value: listVals.join('\n'), field_type: ft });
    }
    listKey = '';
    listVals = [];
  };

  const detectSvcFieldType = (key: string): ChunkFieldType => {
    if (/^user(_?id)?$/i.test(key)) return 'user_id';
    return 'var';
  };

  for (const raw of lines) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const ind = raw.length - raw.trimStart().length;
    const level = Math.round(ind / baseIndent);

    if (level === 0) {
      flushList();
      svc = null;
      ctx = 'none';
      const stripped = trimmed.split(/\s+#/)[0].trimEnd();
      top =
        stripped === 'services:'
          ? 'services'
          : stripped === 'networks:'
            ? 'networks'
            : stripped === 'volumes:'
              ? 'volumes'
              : 'none';
    } else if (level === 1) {
      flushList();
      ctx = 'none';
      const name = trimmed.split(':')[0].trim();
      if (!name) continue;
      if (top === 'services') {
        svc = { id: crypto.randomUUID(), name, chunk_type: 'docker_service', fields: [] };
        chunks.push(svc);
        ctx = 'service';
      } else if (top === 'networks') {
        if (!netChunk) {
          netChunk = {
            id: crypto.randomUUID(),
            name: 'networks',
            chunk_type: 'docker_network',
            fields: [],
          };
          chunks.push(netChunk);
        }
        netChunk.fields.push({ key: name, value: '', field_type: 'var' });
      } else if (top === 'volumes') {
        if (!volChunk) {
          volChunk = {
            id: crypto.randomUUID(),
            name: 'volumes',
            chunk_type: 'docker_volume',
            fields: [],
          };
          chunks.push(volChunk);
        }
        volChunk.fields.push({ key: name, value: '', field_type: 'var' });
      }
    } else if (level === 2 && svc) {
      flushList();
      if (trimmed === 'environment:') {
        ctx = 'env';
      } else if (trimmed.endsWith(':') && !trimmed.includes(': ')) {
        listKey = trimmed.slice(0, -1);
        listVals = [];
        ctx = 'list';
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
        const ei = envLine.indexOf('=');
        const ci2 = envLine.indexOf(': ');
        let key = '',
          val = '';
        if (ei > 0) {
          key = envLine.slice(0, ei).trim();
          val = stripVal(envLine.slice(ei + 1));
        } else if (ci2 > 0) {
          key = envLine.slice(0, ci2).trim();
          val = stripVal(envLine.slice(ci2 + 2));
        }
        if (key) {
          const isRef = /^\$\{.+\}$/.test(val);
          const isSecret = !isRef && /pass(word)?|secret|key|token|cred/i.test(key) && val !== '';
          const ft: ChunkFieldType = isRef ? 'env_var' : isSecret ? 'secret' : 'var';
          svc.fields.push({
            key,
            value: val,
            field_type: ft,
            secret: isSecret || undefined,
            description: 'env',
          });
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
    const m = /^(\S+)\s+(.+)$/.exec(line);
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
    let buf = '',
      inSQ = false,
      inDQ = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (!inSQ && !inDQ && c === '#') {
        while (i < text.length && text[i] !== '\n') i++;
        continue;
      }
      if (c === "'" && !inDQ) {
        inSQ = !inSQ;
        buf += c;
        continue;
      }
      if (c === '"' && !inSQ) {
        inDQ = !inDQ;
        buf += c;
        continue;
      }
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
    if (/^(ssl_certificate|ssl_certificate_key|ssl_trusted_certificate)$/i.test(base))
      return 'cert';
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
      if (tok === '}') {
        pos++;
        return;
      }
      if (tok === ';') {
        pos++;
        continue;
      }
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
    const listen = c.fields.find((f) => f.key === 'listen');
    const sname = c.fields.find((f) => f.key === 'server_name');
    const port = listen?.value.match(/(\d+)/)?.[1] ?? '80';
    const domain =
      sname?.value.split(/\s+/).find((s) => !s.startsWith('www.')) ?? sname?.value.split(/\s+/)[0];
    return domain ? `${domain}:${port}` : `server-${n}`;
  }

  function parseContainer() {
    while (pos < toks.length) {
      const tok = toks[pos];
      if (tok === '}') {
        pos++;
        return;
      }
      if (tok === ';') {
        pos++;
        continue;
      }
      pos++;
      const next = toks[pos] ?? '';
      if (next === '{') {
        pos++;
        const parts = tok.split(/\s+/);
        const bt = parts[0].toLowerCase();
        const ba = parts.slice(1).join(' ');
        if (bt === 'server') {
          const n = chunks.filter((c) => c.chunk_type === 'nginx_server').length + 1;
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
