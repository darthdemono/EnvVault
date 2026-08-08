/**
 * Config-file parsers.
 *
 * These consume whole files the user pastes or imports, so the interesting
 * cases are the ones a real config throws at them: unusual casing, unbalanced
 * blocks, comments, quoting. They are lenient by design — the bar is that being
 * lenient never loses data silently and never downgrades a secret.
 */
import { describe, it, expect } from 'vitest';
import {
  parseWgConf, parseApacheConf, parseHaproxyConf,
  parseDockerCompose, parseSshConfig, parseNginxConf,
} from '../src/ts/chunks/parsers';

const field = (c: any, key: string) => c.fields.find((f: any) => f.key.toLowerCase() === key.toLowerCase());

describe('parseWgConf', () => {
  const CONF = `
[Interface]
PrivateKey = aGVsbG8gd29ybGQgcHJpdmF0ZSBrZXk=
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = cHVibGljIGtleSB2YWx1ZQ==
PresharedKey = cHJlc2hhcmVkIGtleSB2YWx1ZQ==
AllowedIPs = 10.0.0.2/32
Endpoint = vpn.example.com:51820
`;

  it('splits interface and peers into chunks', () => {
    const chunks = parseWgConf(CONF);
    expect(chunks.map(c => c.chunk_type)).toEqual(['wg_interface', 'wg_peer']);
    expect(chunks[1].name).toBe('Peer 1');
  });

  it('marks the private and preshared keys as secret', () => {
    const chunks = parseWgConf(CONF);
    expect(field(chunks[0], 'PrivateKey').secret).toBe(true);
    expect(field(chunks[1], 'PresharedKey').secret).toBe(true);
  });

  it('marks them secret whatever case the file uses', () => {
    // wg-quick accepts any casing, and every other key test here is already
    // case-insensitive. Exact-match comparison imported `privatekey = …` as an
    // ordinary field — shown and exported in clear, flagged as nothing.
    const chunks = parseWgConf('[Interface]\nprivatekey = abc\n[Peer]\nPRESHAREDKEY = def\n');
    expect(field(chunks[0], 'privatekey').secret).toBe(true);
    expect(field(chunks[0], 'privatekey').field_type).toBe('secret');
    expect(field(chunks[1], 'PRESHAREDKEY').secret).toBe(true);
  });

  it('does not mark the public key secret', () => {
    const chunks = parseWgConf(CONF);
    expect(field(chunks[1], 'PublicKey').secret).toBeUndefined();
  });

  it('types the well-known fields', () => {
    const chunks = parseWgConf(CONF);
    expect(field(chunks[0], 'Address').field_type).toBe('subnet');
    expect(field(chunks[0], 'ListenPort').field_type).toBe('port');
    expect(field(chunks[1], 'Endpoint').field_type).toBe('endpoint');
  });

  it('keeps a base64 value containing = intact', () => {
    const chunks = parseWgConf('[Interface]\nPrivateKey = abc123==\n');
    expect(field(chunks[0], 'PrivateKey').value).toBe('abc123==');
  });

  it('strips a trailing comment but not a value', () => {
    const chunks = parseWgConf('[Interface]\nAddress = 10.0.0.1/24 # home net\n');
    expect(field(chunks[0], 'Address').value).toBe('10.0.0.1/24');
  });

  it('ignores lines before any section header', () => {
    expect(parseWgConf('stray = 1\n')).toEqual([]);
  });

  it('numbers multiple peers', () => {
    const chunks = parseWgConf('[Peer]\nPublicKey = a\n[Peer]\nPublicKey = b\n');
    expect(chunks.map(c => c.name)).toEqual(['Peer 1', 'Peer 2']);
  });
});

describe('parseApacheConf', () => {
  it('reads a vhost and its directives', () => {
    const chunks = parseApacheConf(`
<VirtualHost *:443>
  ServerName example.com
  SSLCertificateFile /etc/ssl/cert.pem
</VirtualHost>
`);
    expect(chunks).toHaveLength(1);
    expect(chunks[0].chunk_type).toBe('apache_vhost');
    expect(field(chunks[0], 'ServerName').value).toBe('example.com');
    expect(field(chunks[0], 'SSLCertificateFile').field_type).toBe('cert');
  });

  it('records the path of a Directory block', () => {
    const chunks = parseApacheConf('<Directory /var/www>\n  Require all granted\n</Directory>\n');
    expect(field(chunks[0], 'path').value).toBe('/var/www');
  });

  it('does not lose the rest of the file after an unbalanced close tag', () => {
    // A stray close drove depth to -1; the next open only brought it back to 0,
    // so `depth === 1` never held again and everything after was dropped.
    const chunks = parseApacheConf(`
</VirtualHost>
<VirtualHost *:80>
  ServerName recovered.example.com
</VirtualHost>
`);
    expect(chunks).toHaveLength(1);
    expect(field(chunks[0], 'ServerName').value).toBe('recovered.example.com');
  });

  it('parses several vhosts in one file', () => {
    const chunks = parseApacheConf(`
<VirtualHost *:80>
  ServerName a.example.com
</VirtualHost>
<VirtualHost *:443>
  ServerName b.example.com
</VirtualHost>
`);
    expect(chunks.map(c => field(c, 'ServerName').value)).toEqual(['a.example.com', 'b.example.com']);
  });

  it('returns nothing for an empty or comment-only file', () => {
    expect(parseApacheConf('# just a comment\n\n')).toEqual([]);
  });
});

describe('parseHaproxyConf', () => {
  it('splits sections by type', () => {
    const chunks = parseHaproxyConf(`
global
  maxconn 4096

frontend www
  bind *:80

backend servers
  server s1 10.0.0.1:80
`);
    expect(chunks.map(c => c.chunk_type)).toEqual(['haproxy_global', 'haproxy_frontend', 'haproxy_backend']);
    expect(chunks.map(c => c.name)).toEqual(['global', 'www', 'servers']);
  });

  it('does not throw on a bare section keyword with no name', () => {
    expect(() => parseHaproxyConf('global\n  maxconn 1\n')).not.toThrow();
    expect(parseHaproxyConf('global\n  maxconn 1\n')[0].name).toBe('global');
  });

  it('does not open a section on a directive that merely starts with a keyword', () => {
    // `\s*` allowed the keyword to match a prefix, so `backend_name x` opened a
    // spurious section and swallowed the directives that followed.
    const chunks = parseHaproxyConf(`
frontend www
  backend_name something
  bind *:80
`);
    expect(chunks).toHaveLength(1);
    expect(chunks[0].chunk_type).toBe('haproxy_frontend');
    expect(field(chunks[0], 'bind')).toBeDefined();
  });

  it('types bind and server as endpoints', () => {
    const chunks = parseHaproxyConf('frontend www\n  bind *:80\n');
    expect(field(chunks[0], 'bind').field_type).toBe('endpoint');
  });
});

describe('parseDockerCompose', () => {
  const COMPOSE = `
version: "3.8"
services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    environment:
      - DB_PASSWORD=s3cret
      - PUBLIC_URL=https://example.com
      - FROM_REF=\${DB_URL}
    volumes:
      - ./html:/usr/share/nginx/html:ro
  db:
    image: postgres:16
networks:
  frontnet:
volumes:
  pgdata:
`;

  it('creates a chunk per service', () => {
    const chunks = parseDockerCompose(COMPOSE);
    const svcs = chunks.filter(c => c.chunk_type === 'docker_service');
    expect(svcs.map(c => c.name)).toEqual(['web', 'db']);
  });

  it('reads scalar service fields', () => {
    const web = parseDockerCompose(COMPOSE)[0];
    expect(field(web, 'image').value).toBe('nginx:alpine');
  });

  it('collects list values into one field', () => {
    const web = parseDockerCompose(COMPOSE)[0];
    expect(field(web, 'ports').value).toBe('80:80\n443:443');
    expect(field(web, 'ports').field_type).toBe('port');
  });

  it('marks a credential-looking env var as secret', () => {
    const web = parseDockerCompose(COMPOSE)[0];
    expect(field(web, 'DB_PASSWORD').secret).toBe(true);
    expect(field(web, 'DB_PASSWORD').value).toBe('s3cret');
  });

  it('leaves a plainly non-secret env var alone', () => {
    const web = parseDockerCompose(COMPOSE)[0];
    expect(field(web, 'PUBLIC_URL').secret).toBeUndefined();
  });

  it('treats a ${...} env value as a reference, not a secret', () => {
    const web = parseDockerCompose(COMPOSE)[0];
    expect(field(web, 'FROM_REF').field_type).toBe('env_var');
    expect(field(web, 'FROM_REF').secret).toBeUndefined();
  });

  it('picks up networks and volumes', () => {
    const chunks = parseDockerCompose(COMPOSE);
    expect(chunks.find(c => c.chunk_type === 'docker_network')!.fields[0].key).toBe('frontnet');
    expect(chunks.find(c => c.chunk_type === 'docker_volume')!.fields[0].key).toBe('pgdata');
  });

  it('returns nothing for a file with no services', () => {
    expect(parseDockerCompose('version: "3"\n')).toEqual([]);
  });
});

describe('parseSshConfig', () => {
  it('creates a chunk per Host block', () => {
    const chunks = parseSshConfig(`
Host prod
  HostName 10.0.0.1
  User deploy
  IdentityFile ~/.ssh/id_ed25519

Host staging
  HostName 10.0.0.2
`);
    expect(chunks.map(c => c.name)).toEqual(['prod', 'staging']);
    expect(field(chunks[0], 'User').value).toBe('deploy');
  });

  it('skips comments and blank lines', () => {
    const chunks = parseSshConfig('# comment\n\nHost a\n  User u\n');
    expect(chunks).toHaveLength(1);
    expect(chunks[0].fields).toHaveLength(1);
  });

  it('ignores directives before the first Host', () => {
    const chunks = parseSshConfig('ServerAliveInterval 60\nHost a\n  User u\n');
    expect(chunks).toHaveLength(1);
    expect(field(chunks[0], 'ServerAliveInterval')).toBeUndefined();
  });
});

describe('parseNginxConf', () => {
  const CONF = `
http {
  upstream backend {
    server 10.0.0.1:8080;
    server 10.0.0.2:8080;
  }

  server {
    listen 443 ssl http2;
    server_name example.com www.example.com;
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    add_header X-Frame-Options "SAMEORIGIN" always;

    location /api {
      proxy_pass http://backend;
    }
  }
}
`;

  it('extracts server, upstream and location blocks', () => {
    const chunks = parseNginxConf(CONF);
    expect(chunks.map(c => c.chunk_type).sort())
      .toEqual(['nginx_location', 'nginx_server', 'nginx_upstream']);
  });

  it('names a server from its domain and port', () => {
    const server = parseNginxConf(CONF).find(c => c.chunk_type === 'nginx_server')!;
    expect(server.name).toBe('example.com:443');
  });

  it('types certificate and proxy directives', () => {
    const chunks = parseNginxConf(CONF);
    const server = chunks.find(c => c.chunk_type === 'nginx_server')!;
    const loc = chunks.find(c => c.chunk_type === 'nginx_location')!;
    expect(field(server, 'ssl_certificate').field_type).toBe('cert');
    expect(field(server, 'listen').field_type).toBe('port');
    expect(field(loc, 'proxy_pass').field_type).toBe('endpoint');
  });

  it('keeps the header name as part of a multi-argument directive key', () => {
    const server = parseNginxConf(CONF).find(c => c.chunk_type === 'nginx_server')!;
    const hdr = server.fields.find(f => f.key.startsWith('add_header'))!;
    expect(hdr.key).toBe('add_header X-Frame-Options');
    expect(hdr.value).toBe('"SAMEORIGIN" always');
  });

  it('records the location path', () => {
    const loc = parseNginxConf(CONF).find(c => c.chunk_type === 'nginx_location')!;
    expect(field(loc, 'path').value).toBe('/api');
  });

  it('does not treat a # inside a quoted value as a comment', () => {
    const chunks = parseNginxConf('server {\n  add_header X-Colour "#ff0000" always;\n}\n');
    const hdr = chunks[0].fields.find(f => f.key.startsWith('add_header'))!;
    expect(hdr.value).toContain('#ff0000');
  });

  it('strips a real comment', () => {
    const chunks = parseNginxConf('server {\n  listen 80; # plain http\n}\n');
    expect(field(chunks[0], 'listen').value).toBe('80');
  });

  it('handles a server block with no http wrapper', () => {
    const chunks = parseNginxConf('server {\n  listen 80;\n  server_name a.example.com;\n}\n');
    expect(chunks).toHaveLength(1);
    expect(chunks[0].name).toBe('a.example.com:80');
  });

  it('returns nothing for an empty file', () => {
    expect(parseNginxConf('')).toEqual([]);
  });
});
