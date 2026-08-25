//! Starter chunks for a newly created typed project — the Rust twin of
//! `src/ts/chunks/starters.ts`.
//!
//! Only the four stable project types are ported. The experimental types can
//! still be created with `--experimental`, but they come up empty here rather
//! than with a second, drifting copy of templates the UI owns; add their chunks
//! in the app, or with `envv project chunk add`.

use serde_json::{json, Value};

fn chunk(name: &str, chunk_type: &str, fields: Vec<Value>) -> Value {
    json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "name": name,
        "chunk_type": chunk_type,
        "fields": fields,
    })
}

fn f(key: &str, value: &str, field_type: &str) -> Value {
    json!({ "key": key, "value": value, "field_type": field_type })
}

fn fs(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": value, "field_type": "secret", "secret": true })
}

fn fd(key: &str, value: &str, field_type: &str, description: &str) -> Value {
    json!({ "key": key, "value": value, "field_type": field_type, "description": description })
}

pub fn starter_chunks(ptype: &str) -> Option<Vec<Value>> {
    match ptype {
        "wireguard" => Some(vec![
            chunk(
                "Interface",
                "wg_interface",
                vec![
                    fs("PrivateKey", ""),
                    f("Address", "", "var"),
                    f("MTU", "", "var"),
                    f("Table", "", "var"),
                    f("DNS", "", "var"),
                    f("PostUp", "", "multiline"),
                    f("PostDown", "", "multiline"),
                    f("ListenPort", "", "var"),
                ],
            ),
            chunk(
                "Peer",
                "wg_peer",
                vec![
                    f("PublicKey", "", "var"),
                    f("AllowedIPs", "", "var"),
                    f("Endpoint", "", "var"),
                    f("PersistentKeepalive", "", "var"),
                    fs("PresharedKey", ""),
                ],
            ),
        ]),
        "docker" => Some(vec![
            chunk("service-1", "docker_service", vec![]),
            chunk("networks", "docker_network", vec![]),
            chunk("volumes", "docker_volume", vec![]),
        ]),
        "nginx" => Some(vec![
            chunk(
                "HTTP :80 redirect",
                "nginx_server",
                vec![
                    f("listen", "80", "port"),
                    fd("listen", "[::]:80", "port", "ipv6"),
                    f("server_name", "example.com www.example.com", "var"),
                    f("return", "301 https://example.com$request_uri", "var"),
                ],
            ),
            chunk(
                "HTTPS www redirect",
                "nginx_server",
                vec![
                    f("listen", "443 ssl http2", "port"),
                    fd("listen", "[::]:443 ssl http2", "port", "ipv6"),
                    f("server_name", "www.example.com", "var"),
                    f("ssl_certificate", "${example_cert}", "cert"),
                    f("ssl_certificate_key", "${example_cert_key}", "cert"),
                    f("return", "301 https://example.com$request_uri", "var"),
                ],
            ),
            chunk(
                "HTTPS :443 main",
                "nginx_server",
                vec![
                f("listen", "443 ssl http2", "port"),
                fd("listen", "[::]:443 ssl http2", "port", "ipv6"),
                f("server_name", "example.com", "var"),
                f("ssl_certificate", "${example_cert}", "cert"),
                f("ssl_certificate_key", "${example_cert_key}", "cert"),
                f("root", "/var/www/html", "var"),
                f("index", "index.php index.html", "var"),
                f("access_log", "/var/log/nginx/access.log", "var"),
                f("error_log", "/var/log/nginx/error.log", "var"),
                f("add_header X-Frame-Options", "\"SAMEORIGIN\" always", "var"),
                f("add_header X-Content-Type-Options", "\"nosniff\" always", "var"),
                f(
                    "add_header Strict-Transport-Security",
                    "\"max-age=31536000; includeSubDomains; preload\" always",
                    "var",
                ),
                f("gzip", "on", "var"),
                f(
                    "gzip_types",
                    "text/plain text/css text/javascript application/javascript application/json",
                    "var",
                ),
            ],
            ),
            chunk(
                "location /",
                "nginx_location",
                vec![
                    f("path", "/", "var"),
                    f("try_files", "$uri $uri/ $uri.php?$args", "var"),
                ],
            ),
            chunk(
                "location ~ .php",
                "nginx_location",
                vec![
                    f("path", "~ \\.php$", "var"),
                    f("include", "snippets/fastcgi-php.conf", "var"),
                    f("fastcgi_pass", "unix:/run/php/php8.1-fpm.sock", "endpoint"),
                ],
            ),
            chunk(
                "location ~ assets",
                "nginx_location",
                vec![
                    f(
                        "path",
                        "~* \\.(jpg|jpeg|png|gif|webp|ico|css|js|svg|woff2)$",
                        "var",
                    ),
                    f("expires", "30d", "var"),
                    f("add_header Cache-Control", "\"public, immutable\"", "var"),
                    f("access_log", "off", "var"),
                ],
            ),
        ]),
        _ => None,
    }
}
