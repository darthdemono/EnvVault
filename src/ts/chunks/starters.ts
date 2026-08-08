/**
 * @file Starter chunk templates — the initial set of config sections created
 *       when a new typed project (WireGuard, Docker, nginx, k8s, …) is added.
 *
 * Pure factories: they take no input and depend on nothing but the chunk types.
 */

import type { SecretChunk } from '../types';
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
