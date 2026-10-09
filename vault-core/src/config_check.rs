//! Cross-chunk, cross-format checks for a project (Phase 29, "the config compiler"; ADR-0137).
//!
//! Phase 18's validation matrix runs each generated file past its own tool
//! (`nginx -t`, `wg-quick strip`), which can only ever see one format. The
//! mistakes that bite sit between chunks: a `proxy_pass` naming a service the
//! project does not define, two WireGuard peers claiming one address.
//!
//! **Eight rule ids over the six designed checks, hand-written, and no rule language**
//! (WireGuard and Kubernetes each split into an error case and a softer one). A false positive costs far
//! more than a missing check: a validator that cries wolf gets switched off and
//! then protects nothing. So every rule fires only on positive evidence that the
//! project means to define the thing (a rule about Docker services stays silent in
//! a project with no `docker_service` chunk), and anything that could be resolved
//! somewhere this function cannot see — a `name@provider` Traefik reference, a
//! `${bundle:…}` reference, a hostname with a dot — is skipped, not guessed at.
//!
//! The functions are pure over the project JSON, so the CLI (`unv check`) and the
//! desktop app (over IPC) cannot disagree about what a project means. Messages
//! carry names and never values: a finding must be safe to print, and a hostname
//! or chunk name is not a secret where a field value might be.

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// One finding. `severity` is `"error"` (the generated config is wrong) or
/// `"warning"` (probably wrong; could be satisfied somewhere this cannot see).
pub struct Finding {
    pub rule: &'static str,
    pub severity: &'static str,
    pub chunk_id: String,
    pub chunk_name: String,
    pub chunk_type: String,
    pub field: String,
    pub message: String,
    /// Other chunks involved, by name.
    pub related: Vec<String>,
}

impl Finding {
    pub fn to_json(&self) -> Value {
        json!({
            "rule": self.rule,
            "severity": self.severity,
            "chunk_id": self.chunk_id,
            "chunk": self.chunk_name,
            "chunk_type": self.chunk_type,
            "field": self.field,
            "message": self.message,
            "related": self.related,
        })
    }
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn fields(chunk: &Value) -> Vec<&Value> {
    chunk
        .get("fields")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

/// First non-empty value of `key`, trimmed.
fn field<'a>(chunk: &'a Value, key: &str) -> &'a str {
    fields(chunk)
        .into_iter()
        .find(|f| s(f, "key") == key && !s(f, "value").trim().is_empty())
        .map(|f| s(f, "value").trim())
        .unwrap_or("")
}

/// Every non-empty value of `key` (a key may repeat, e.g. `listen`).
fn field_all<'a>(chunk: &'a Value, key: &str) -> Vec<&'a str> {
    fields(chunk)
        .into_iter()
        .filter(|f| s(f, "key") == key)
        .map(|f| s(f, "value").trim())
        .filter(|v| !v.is_empty())
        .collect()
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect()
}

/// A disabled chunk is excluded from exports, so it is excluded here too.
fn active_chunks(project: &Value) -> Vec<&Value> {
    project
        .get("chunks")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|c| !c.get("disabled").and_then(Value::as_bool).unwrap_or(false))
                .collect()
        })
        .unwrap_or_default()
}

fn of_type<'a>(chunks: &[&'a Value], t: &str) -> Vec<&'a Value> {
    chunks
        .iter()
        .copied()
        .filter(|c| s(c, "chunk_type") == t)
        .collect()
}

fn finding(
    rule: &'static str,
    severity: &'static str,
    chunk: &Value,
    field: &str,
    message: String,
    related: Vec<String>,
) -> Finding {
    Finding {
        rule,
        severity,
        chunk_id: s(chunk, "id").to_string(),
        chunk_name: s(chunk, "name").to_string(),
        chunk_type: s(chunk, "chunk_type").to_string(),
        field: field.to_string(),
        message,
        related,
    }
}

/// Compose names a service the way the exporter does: whitespace to `_`, lowercase.
fn service_name(chunk: &Value) -> String {
    s(chunk, "name")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
        .to_lowercase()
}

/// Every name a service answers to on a Docker network.
fn service_aliases(chunk: &Value) -> Vec<String> {
    let mut v = vec![service_name(chunk)];
    let cn = field(chunk, "container_name").to_lowercase();
    if !cn.is_empty() {
        v.push(cn);
    }
    v
}

fn norm(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn is_ref(v: &str) -> bool {
    v.contains("${")
}

// ── Rule 1: nginx proxy_pass → a Docker service the project does not define ──

fn rule_nginx_proxy_pass(chunks: &[&Value], elsewhere: &[String], out: &mut Vec<Finding>) {
    let services = of_type(chunks, "docker_service");
    if services.is_empty() && elsewhere.is_empty() {
        return; // no evidence this project (or, with --all-projects, any) defines services
    }
    let mut known: HashSet<String> = services.iter().flat_map(|c| service_aliases(c)).collect();
    known.extend(elsewhere.iter().cloned());
    for u in of_type(chunks, "nginx_upstream") {
        known.insert(s(u, "name").to_lowercase());
    }
    for t in ["nginx_location", "nginx_server"] {
        for c in of_type(chunks, t) {
            for target in field_all(c, "proxy_pass") {
                let Some(host) = proxy_host(target) else {
                    continue;
                };
                if !known.contains(&host) {
                    out.push(finding(
                        "nginx-proxy-pass-unknown-service",
                        "warning",
                        c,
                        "proxy_pass",
                        format!(
                            "proxy_pass names `{host}`, which is neither a Docker service nor an upstream defined in this project"
                        ),
                        services.iter().map(|x| service_name(x)).collect(),
                    ));
                }
            }
        }
    }
}

/// The bare host of a `proxy_pass` target, or `None` when it is not a service-style
/// name (an IP, a dotted hostname, `localhost`, a variable, a unix socket, a ref).
fn proxy_host(target: &str) -> Option<String> {
    if is_ref(target) || target.contains('$') || target.starts_with("unix:") {
        return None;
    }
    let rest = target.split_once("://").map(|(_, r)| r).unwrap_or(target);
    if rest.starts_with("unix:") {
        return None;
    }
    let host = rest.split(['/', ':']).next().unwrap_or("").to_lowercase();
    if host.is_empty()
        || host == "localhost"
        || host.contains('.')
        || host.contains('[')
        || host.parse::<IpAddr>().is_ok()
    {
        return None;
    }
    Some(host)
}

// ── Rule 2: two WireGuard peers with the same AllowedIPs network ─────────────

/// `10.0.0.5/24` → the masked network `10.0.0.0/24`; `None` if unparseable.
fn network(cidr: &str) -> Option<(u8, u128, u8)> {
    let (addr, len) = match cidr.split_once('/') {
        Some((a, l)) => (a, Some(l.parse::<u8>().ok()?)),
        None => (cidr, None),
    };
    match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => {
            let len = len.unwrap_or(32);
            if len > 32 {
                return None;
            }
            let bits = u32::from(a) as u128;
            let mask = if len == 0 {
                0
            } else {
                (!0u32 << (32 - len)) as u128
            };
            Some((4, bits & mask, len))
        }
        IpAddr::V6(a) => {
            let len = len.unwrap_or(128);
            if len > 128 {
                return None;
            }
            let bits = u128::from(a);
            let mask = if len == 0 { 0 } else { !0u128 << (128 - len) };
            Some((6, bits & mask, len))
        }
    }
}

/// `a` strictly contains `b` (same family, shorter prefix, same leading bits).
fn contains(a: (u8, u128, u8), b: (u8, u128, u8)) -> bool {
    if a.0 != b.0 || a.2 >= b.2 {
        return false;
    }
    let width: u32 = if a.0 == 4 { 32 } else { 128 };
    let shift = width - a.2 as u32;
    // For IPv4 the address sits in the low 32 bits of the u128.
    if a.2 == 0 {
        return true;
    }
    (a.1 >> shift) == (b.1 >> shift)
}

/// Two peers claiming the *same* network is always wrong: the kernel silently
/// moves it to whichever peer was added last (an error). One peer's network
/// *containing* another's is how WireGuard expresses a split route, since it routes
/// by longest prefix, so it is only a warning, and a default route (`/0`) beside
/// host routes, the standard full-tunnel pattern, is not reported at all.
fn rule_wireguard_allowed_ips(chunks: &[&Value], out: &mut Vec<Finding>) {
    let peers = of_type(chunks, "wg_peer");
    let mut seen: HashMap<(u8, u128, u8), &Value> = HashMap::new();
    let mut nets: Vec<((u8, u128, u8), String, &Value)> = Vec::new();
    for p in peers {
        let mut mine: HashSet<(u8, u128, u8)> = HashSet::new();
        for raw in field_all(p, "AllowedIPs") {
            if is_ref(raw) {
                continue;
            }
            for item in split_list(raw) {
                let Some(net) = network(&item) else { continue };
                if !mine.insert(net) {
                    continue;
                }
                if let Some(other) = seen.get(&net) {
                    out.push(finding(
                        "wireguard-allowed-ips-duplicate",
                        "error",
                        p,
                        "AllowedIPs",
                        format!(
                            "AllowedIPs `{item}` is also claimed by peer `{}`; WireGuard gives the address to only one of them",
                            s(other, "name")
                        ),
                        vec![s(other, "name").to_string()],
                    ));
                } else {
                    seen.insert(net, p);
                    nets.push((net, item.clone(), p));
                }
            }
        }
    }
    // Strict containment between different peers, excluding default routes.
    for (outer, outer_text, op) in &nets {
        if outer.2 == 0 {
            continue;
        }
        for (inner, inner_text, ip) in &nets {
            if std::ptr::eq(*op, *ip) || !contains(*outer, *inner) {
                continue;
            }
            out.push(finding(
                "wireguard-allowed-ips-overlap",
                "warning",
                ip,
                "AllowedIPs",
                format!(
                    "AllowedIPs `{inner_text}` sits inside `{outer_text}` claimed by peer `{}`; WireGuard sends it to this peer (longest prefix), so the wider peer never sees it",
                    s(op, "name")
                ),
                vec![s(op, "name").to_string()],
            ));
        }
    }
}

// ── Rule 3: a Traefik router naming a middleware that does not exist ────────

fn rule_traefik_middleware(chunks: &[&Value], out: &mut Vec<Finding>) {
    let defined: HashSet<String> = of_type(chunks, "traefik_middleware")
        .iter()
        .map(|m| s(m, "name").to_lowercase())
        .collect();
    for router in of_type(chunks, "traefik_router") {
        for raw in field_all(router, "middlewares") {
            if is_ref(raw) {
                continue;
            }
            for name in split_list(raw) {
                // `name@provider` lives in another provider; not ours to judge.
                if name.contains('@') || defined.contains(&name.to_lowercase()) {
                    continue;
                }
                out.push(finding(
                    "traefik-middleware-missing",
                    "warning",
                    router,
                    "middlewares",
                    format!(
                        "router uses middleware `{name}`, which no traefik_middleware chunk defines (write `{name}@file` if it lives in another file)"
                    ),
                    vec![],
                ));
            }
        }
    }
}

// ── Rule 4: a Deployment consuming a Secret no chunk creates ─────────────────
//
// A Deployment names Secrets in `secretEnv` (list) and `secretMounts`
// (`secret:/path` list); the exporters turn them into `envFrom` and a volume.
// Silent when the project has no `k8s_secret` chunk at all: the Secret may be
// created by another manifest set, and a rule that fires there is a rule that
// gets switched off. The same family also checks an Ingress's Service.

fn split_list_k8s(raw: &str) -> Vec<String> {
    split_list(raw)
}

fn rule_k8s_secrets(chunks: &[&Value], out: &mut Vec<Finding>) {
    let secrets = of_type(chunks, "k8s_secret");
    if secrets.is_empty() {
        return;
    }
    let defined: HashSet<(String, String)> =
        secrets.iter().map(|c| (k8s_name(c), k8s_ns(c))).collect();
    for dep in of_type(chunks, "k8s_deployment") {
        let ns = k8s_ns(dep);
        let mut wanted: Vec<(&str, String)> = Vec::new();
        for raw in field_all(dep, "secretEnv") {
            for n in split_list_k8s(raw) {
                wanted.push(("secretEnv", n));
            }
        }
        for raw in field_all(dep, "secretMounts") {
            for m in split_list_k8s(raw) {
                if let Some(i) = m.find(':').filter(|i| *i > 0 && *i < m.len() - 1) {
                    wanted.push(("secretMounts", m[..i].to_string()));
                }
            }
        }
        let mut reported: HashSet<String> = HashSet::new();
        for (key, n) in wanted {
            if is_ref(&n)
                || defined.contains(&(n.clone(), ns.clone()))
                || !reported.insert(n.clone())
            {
                continue;
            }
            out.push(finding(
                "k8s-deployment-secret-missing",
                "error",
                dep,
                key,
                format!("Deployment uses Secret `{n}` in namespace `{ns}`, which no k8s_secret chunk creates; the Pod will not start"),
                secrets.iter().map(|c| k8s_name(c)).collect(),
            ));
        }
    }
}

// ── Rule 4b: a Kubernetes Ingress backed by a Service no chunk defines ───────

fn k8s_name(chunk: &Value) -> String {
    let n = field(chunk, "name");
    if n.is_empty() { s(chunk, "name") } else { n }.to_string()
}

fn k8s_ns(chunk: &Value) -> String {
    let n = field(chunk, "namespace");
    if n.is_empty() { "default" } else { n }.to_string()
}

fn rule_k8s_ingress(chunks: &[&Value], out: &mut Vec<Finding>) {
    let services = of_type(chunks, "k8s_service");
    if services.is_empty() {
        return;
    }
    let defined: HashSet<(String, String)> =
        services.iter().map(|c| (k8s_name(c), k8s_ns(c))).collect();
    for ing in of_type(chunks, "k8s_ingress") {
        let svc = {
            let v = field(ing, "serviceName");
            if v.is_empty() {
                k8s_name(ing)
            } else {
                v.to_string()
            }
        };
        if is_ref(&svc) {
            continue;
        }
        let ns = k8s_ns(ing);
        if !defined.contains(&(svc.clone(), ns.clone())) {
            out.push(finding(
                "k8s-ingress-service-missing",
                "warning",
                ing,
                "serviceName",
                format!("Ingress routes to Service `{svc}` in namespace `{ns}`, which no k8s_service chunk defines"),
                services.iter().map(|c| k8s_name(c)).collect(),
            ));
        }
    }
}

// ── Rule 5: a Compose service reading a variable nothing provides ───────────
//
// Compose substitutes `${NAME}` anywhere in a service from the `.env` beside the
// file and the shell. In this model that `.env` is built from the vault references
// the exporter derives (one per environment field holding a reference) and from
// env_file chunks. So a `${NAME}` in any service value (image tag, port, command,
// an environment value) must be a key some env_file chunk sets, or a vault entry.
// `${NAME:-default}` and the other operator forms carry their own fallback and
// are not reported; `$${NAME}` is an escaped literal.

/// `${NAME}` tokens in `value` whose body is a plain name or `Provider/field`,
/// with no operator, skipping `$${…}` escapes.
fn compose_tokens(value: &str) -> Vec<String> {
    let b = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'$' && b[i + 1] == b'$' {
            i += 2;
            continue;
        }
        if b[i] == b'$' && b[i + 1] == b'{' {
            if let Some(end) = value[i + 2..].find('}') {
                let body = &value[i + 2..i + 2 + end];
                if !body.is_empty()
                    && !body.contains(":-")
                    && !body.contains(":?")
                    && !body.contains('-')
                    && !body.contains('?')
                    && !body.contains('+')
                {
                    out.push(body.to_string());
                }
                i += 2 + end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// `known` is the vault's entry names (provider, and `provider_keyid`).
fn rule_compose_env(chunks: &[&Value], known: &[String], out: &mut Vec<Finding>) {
    let env_keys: HashSet<String> = of_type(chunks, "env_file")
        .iter()
        .flat_map(|c| fields(c))
        .map(|f| norm(s(f, "key")))
        .collect();
    let providers: Vec<String> = known.iter().map(|k| norm(k)).collect();
    let resolves = |name: &str| -> bool {
        if name.starts_with("chunk:") || name.starts_with("bundle:") {
            return true; // resolved by machinery this module does not duplicate
        }
        let head = name.split('/').next().unwrap_or(name);
        let n = norm(head);
        env_keys.contains(&n)
            || providers
                .iter()
                .any(|p| !p.is_empty() && (n == *p || n.starts_with(&format!("{p}_"))))
    };
    for svc in of_type(chunks, "docker_service") {
        for f in fields(svc) {
            let raw = s(f, "value");
            let mut names: Vec<String> = Vec::new();
            if !s(f, "ref_name").is_empty() {
                names.push(s(f, "ref_name").to_string());
            }
            names.extend(compose_tokens(raw));
            let mut reported: HashSet<String> = HashSet::new();
            for name in names {
                if resolves(&name) || !reported.insert(name.clone()) {
                    continue;
                }
                out.push(finding(
                    "compose-env-ref-unresolved",
                    "warning",
                    svc,
                    s(f, "key"),
                    format!(
                        "`{}` reads `${{{name}}}`, which is neither a vault entry nor a key in an env_file chunk",
                        s(f, "key")
                    ),
                    vec![],
                ));
            }
        }
    }
}

// ── Rule 6: a pg_connection host on a network its caller is not attached to ─

fn networks_of(svc: &Value) -> Option<HashSet<String>> {
    // `network_mode` replaces networking altogether; nothing to compare.
    if !field(svc, "network_mode").is_empty() {
        return None;
    }
    let listed: HashSet<String> = field_all(svc, "networks")
        .iter()
        .flat_map(|v| split_list(v))
        .collect();
    Some(if listed.is_empty() {
        HashSet::from(["default".to_string()])
    } else {
        listed
    })
}

fn mentions(svc: &Value, name: &str) -> bool {
    if field_all(svc, "depends_on")
        .iter()
        .flat_map(|v| split_list(v))
        .any(|d| d.to_lowercase() == name)
    {
        return true;
    }
    fields(svc)
        .into_iter()
        .filter(|f| s(f, "description") == "env" || s(f, "field_type") == "env_var")
        .any(|f| {
            s(f, "value")
                .to_lowercase()
                .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
                .any(|tok| tok == name)
        })
}

/// A service that reads the connection through `${chunk:<pg chunk>/…}` consumes it
/// even though no env value spells the host.
fn reads_chunk(svc: &Value, pg_name: &str) -> bool {
    let needle = format!("chunk:{}", pg_name.to_lowercase());
    fields(svc).into_iter().any(|f| {
        let v = s(f, "value").to_lowercase();
        let r = s(f, "ref_name").to_lowercase();
        v.contains(&needle) || r.contains(&needle)
    })
}

fn rule_pg_network(chunks: &[&Value], out: &mut Vec<Finding>) {
    let services = of_type(chunks, "docker_service");
    for pg in of_type(chunks, "pg_connection") {
        let host = field(pg, "host").to_lowercase();
        if host.is_empty() || is_ref(&host) {
            continue;
        }
        let Some(db) = services.iter().find(|c| service_aliases(c).contains(&host)) else {
            continue;
        };
        let Some(db_nets) = networks_of(db) else {
            continue;
        };
        for c in &services {
            if std::ptr::eq(*c, *db) {
                continue;
            }
            let Some(c_nets) = networks_of(c) else {
                continue;
            };
            let reaches =
                service_aliases(db).iter().any(|a| mentions(c, a)) || reads_chunk(c, s(pg, "name"));
            if reaches && c_nets.is_disjoint(&db_nets) {
                out.push(finding(
                    "pg-host-network-unreachable",
                    "warning",
                    pg,
                    "host",
                    format!(
                        "host `{host}` is Docker service `{}`, but service `{}` uses it and shares no network with it",
                        service_name(db),
                        service_name(c)
                    ),
                    vec![service_name(db), service_name(c)],
                ));
            }
        }
    }
}

// ── Phase 29.1 rules ──────────────────────────────────────────────────────────
//
// Each fires only on positive evidence the project defines the thing it checks
// against, and stays silent on anything that could live somewhere unseen.

/// A Traefik router naming a `service` no `traefik_service` chunk defines.
/// Silent when the project defines no service chunk at all (Traefik can build one
/// from labels or another file), and for `name@provider` references.
fn rule_traefik_service(chunks: &[&Value], out: &mut Vec<Finding>) {
    let defined: HashSet<String> = of_type(chunks, "traefik_service")
        .iter()
        .map(|c| s(c, "name").to_lowercase())
        .collect();
    if defined.is_empty() {
        return;
    }
    for router in of_type(chunks, "traefik_router") {
        for raw in field_all(router, "service") {
            if is_ref(raw) || raw.contains('@') || defined.contains(&raw.to_lowercase()) {
                continue;
            }
            out.push(finding(
                "traefik-service-missing",
                "warning",
                router,
                "service",
                format!(
                    "router names service `{raw}`, which no traefik_service chunk defines (write `{raw}@file` if it lives in another file)"
                ),
                vec![],
            ));
        }
    }
}

/// An `nginx_upstream` no `proxy_pass` in this project names. Silent when the
/// project has no server or location chunk (the upstream may be used by a
/// config this project does not hold).
fn rule_nginx_upstream_unused(chunks: &[&Value], out: &mut Vec<Finding>) {
    let users: Vec<&Value> = ["nginx_location", "nginx_server"]
        .iter()
        .flat_map(|t| of_type(chunks, t))
        .collect();
    if users.is_empty() {
        return;
    }
    let mut used = HashSet::new();
    for c in &users {
        for target in field_all(c, "proxy_pass") {
            if is_ref(target) {
                return; // a reference could name any upstream: cannot judge
            }
            if let Some(h) = proxy_host(target) {
                used.insert(h);
            }
        }
    }
    for u in of_type(chunks, "nginx_upstream") {
        let name = s(u, "name").to_lowercase();
        if !name.is_empty() && !used.contains(&name) {
            out.push(finding(
                "nginx-upstream-unused",
                "warning",
                u,
                "name",
                format!("upstream `{name}` is not named by any proxy_pass in this project"),
                vec![],
            ));
        }
    }
}

/// `depends_on` naming a service the project does not define. Silent with no
/// `docker_service` chunk, and for references.
fn rule_compose_depends_on(chunks: &[&Value], out: &mut Vec<Finding>) {
    let services = of_type(chunks, "docker_service");
    if services.is_empty() {
        return;
    }
    let known: HashSet<String> = services.iter().flat_map(|c| service_aliases(c)).collect();
    for svc in &services {
        for raw in field_all(svc, "depends_on") {
            if is_ref(raw) {
                continue;
            }
            for dep in split_list(raw) {
                if !known.contains(&dep.to_lowercase()) {
                    out.push(finding(
                        "compose-depends-on-unknown-service",
                        "error",
                        svc,
                        "depends_on",
                        format!("depends_on names `{dep}`, which is not a service in this project"),
                        vec![],
                    ));
                }
            }
        }
    }
}

/// `(ip, port, proto)` of a published port mapping, or `None` for a container-only
/// port, a range, a reference or anything unreadable.
fn published(spec: &str) -> Option<(String, String, String)> {
    if is_ref(spec) {
        return None;
    }
    let (body, proto) = spec.split_once('/').unwrap_or((spec, "tcp"));
    let parts: Vec<&str> = body.split(':').collect();
    let (ip, host) = match parts.as_slice() {
        [host, _container] => ("", *host),
        [ip, host, _container] => (*ip, *host),
        _ => return None,
    };
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let ip = if ip == "0.0.0.0" { "" } else { ip };
    Some((ip.to_string(), host.to_string(), proto.to_lowercase()))
}

/// Two services publishing the same host port. Compose refuses to start the second.
fn rule_compose_port_clash(chunks: &[&Value], out: &mut Vec<Finding>) {
    let services = of_type(chunks, "docker_service");
    let mut seen: Vec<((String, String, String), &Value)> = Vec::new();
    for svc in &services {
        for raw in field_all(svc, "ports") {
            for spec in split_list(raw) {
                let Some(p) = published(&spec) else {
                    continue;
                };
                let clash = seen.iter().find(|(q, other)| {
                    !std::ptr::eq(*other, *svc)
                        && q.1 == p.1
                        && q.2 == p.2
                        && (q.0 == p.0 || q.0.is_empty() || p.0.is_empty())
                });
                if let Some((_, other)) = clash {
                    out.push(finding(
                        "compose-port-clash",
                        "error",
                        svc,
                        "ports",
                        format!(
                            "host port {}/{} is also published by service `{}`",
                            p.1,
                            p.2,
                            service_name(other)
                        ),
                        vec![service_name(other)],
                    ));
                }
                seen.push((p, svc));
            }
        }
    }
}

// ── Rule: a service on a network no docker_network chunk declares ───────────
//
// Silent unless the project declares at least one network (positive evidence the
// author manages them here); `default` always exists in Compose.

fn rule_compose_network(chunks: &[&Value], out: &mut Vec<Finding>) {
    let nets = of_type(chunks, "docker_network");
    if nets.is_empty() {
        return;
    }
    let mut declared: HashSet<String> = HashSet::from(["default".to_string()]);
    for n in &nets {
        let keys: Vec<String> = fields(n)
            .into_iter()
            .map(|f| s(f, "key").to_lowercase())
            .filter(|k| !k.is_empty())
            .collect();
        if keys.is_empty() {
            declared.insert(s(n, "name").to_lowercase());
        }
        declared.extend(keys);
    }
    for svc in of_type(chunks, "docker_service") {
        for raw in field_all(svc, "networks") {
            if is_ref(raw) {
                continue;
            }
            for net in split_list(raw) {
                if !declared.contains(&net.to_lowercase()) {
                    out.push(finding(
                        "compose-network-undeclared",
                        "error",
                        svc,
                        "networks",
                        format!(
                            "Service joins network `{net}`, which no docker_network chunk declares"
                        ),
                        vec![],
                    ));
                }
            }
        }
    }
}

// ── Rule: a k8s Service whose selector matches no Deployment ────────────────
//
// The starters generate `selector: app: <name>` and a Deployment's pod label
// `app: <name>`, so the selector matches exactly the Deployment of the same name
// and namespace. Silent when the project has no Deployment at all.

fn rule_k8s_service_selector(chunks: &[&Value], out: &mut Vec<Finding>) {
    let deps = of_type(chunks, "k8s_deployment");
    if deps.is_empty() {
        return;
    }
    let defined: HashSet<(String, String)> =
        deps.iter().map(|c| (k8s_name(c), k8s_ns(c))).collect();
    for svc in of_type(chunks, "k8s_service") {
        let (n, ns) = (k8s_name(svc), k8s_ns(svc));
        if is_ref(&n) || n.is_empty() || defined.contains(&(n.clone(), ns.clone())) {
            continue;
        }
        out.push(finding(
            "k8s-service-selector-unmatched",
            "warning",
            svc,
            "name",
            format!("Service `{n}` selects `app: {n}` in namespace `{ns}`, which no k8s_deployment chunk labels; it will have no endpoints"),
            deps.iter().map(|c| k8s_name(c)).collect(),
        ));
    }
}

/// Run every rule over one project. `vault_names` are the vault's entry names
/// (provider, and `provider_keyid`) so a `${…}` reference to a real entry is not
/// reported; pass an empty slice to skip nothing and report every non-env_file ref.
pub fn check_project(project: &Value, vault_names: &[String]) -> Vec<Finding> {
    check_project_scoped(project, vault_names, &[])
}

/// Every Compose service name (and `container_name`) any of `projects` defines,
/// lowercased. Passed to [`check_project_scoped`] as `elsewhere` so a `proxy_pass`
/// is resolved against the whole stack, which is how people split one.
pub fn services_of(projects: &[Value]) -> Vec<String> {
    let mut v: Vec<String> = projects
        .iter()
        .flat_map(|p| {
            let chunks = active_chunks(p);
            of_type(&chunks, "docker_service")
                .into_iter()
                .flat_map(service_aliases)
                .collect::<Vec<_>>()
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// As [`check_project`], with `elsewhere` (see [`services_of`]) widening what an
/// nginx `proxy_pass` host may resolve to. Off by default because it widens the
/// evidence a rule may use: a name another project defines is not wired to this one.
pub fn check_project_scoped(
    project: &Value,
    vault_names: &[String],
    elsewhere: &[String],
) -> Vec<Finding> {
    let chunks = active_chunks(project);
    let mut out = Vec::new();
    rule_nginx_proxy_pass(&chunks, elsewhere, &mut out);
    rule_wireguard_allowed_ips(&chunks, &mut out);
    rule_traefik_middleware(&chunks, &mut out);
    rule_k8s_secrets(&chunks, &mut out);
    rule_k8s_ingress(&chunks, &mut out);
    rule_compose_env(&chunks, vault_names, &mut out);
    rule_pg_network(&chunks, &mut out);
    rule_traefik_service(&chunks, &mut out);
    rule_nginx_upstream_unused(&chunks, &mut out);
    rule_compose_depends_on(&chunks, &mut out);
    rule_compose_port_clash(&chunks, &mut out);
    rule_compose_network(&chunks, &mut out);
    rule_k8s_service_selector(&chunks, &mut out);
    // A stack integration (Phase 38) brings its own rules in its descriptor.
    if let Some(a) = crate::stack::adapter(s(project, "project_type")) {
        out.extend(crate::stack::check(a, project, vault_names));
    }
    out
}

/// The push gate: the error-severity findings that must stop a node from writing
/// this project's config to a live host. Empty means go. A warning never gates.
pub fn gate(project: &Value, vault_names: &[String]) -> Vec<Finding> {
    check_project(project, vault_names)
        .into_iter()
        .filter(|f| f.severity == "error")
        .collect()
}

/// The rule ids, in the order they run — `unv describe` and the panel list them.
pub const RULES: [&str; 14] = [
    "nginx-proxy-pass-unknown-service",
    "wireguard-allowed-ips-duplicate",
    "wireguard-allowed-ips-overlap",
    "traefik-middleware-missing",
    "k8s-deployment-secret-missing",
    "k8s-ingress-service-missing",
    "compose-env-ref-unresolved",
    "pg-host-network-unreachable",
    "traefik-service-missing",
    "nginx-upstream-unused",
    "compose-depends-on-unknown-service",
    "compose-port-clash",
    "compose-network-undeclared",
    "k8s-service-selector-unmatched",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn f(key: &str, value: &str) -> Value {
        json!({"key": key, "value": value, "field_type": "var"})
    }
    fn chunk(name: &str, t: &str, fields: Vec<Value>) -> Value {
        json!({"id": format!("id-{name}"), "name": name, "chunk_type": t, "fields": fields})
    }
    fn project(chunks: Vec<Value>) -> Value {
        json!({"id": "p", "name": "p", "chunks": chunks})
    }
    fn rules(p: &Value, names: &[&str]) -> Vec<&'static str> {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        check_project(p, &names).iter().map(|x| x.rule).collect()
    }

    #[test]
    fn proxy_pass_to_an_undefined_service_is_flagged_but_only_when_services_exist() {
        let loc = |t: &str| {
            chunk(
                "loc",
                "nginx_location",
                vec![f("path", "/"), f("proxy_pass", t)],
            )
        };
        let svc = chunk("web app", "docker_service", vec![f("image", "x")]);
        assert_eq!(
            rules(&project(vec![loc("http://api:8080"), svc.clone()]), &[]),
            ["nginx-proxy-pass-unknown-service"]
        );
        // The service the project does define, under the name Compose gives it.
        assert!(rules(
            &project(vec![loc("http://web_app:8080/x"), svc.clone()]),
            &[]
        )
        .is_empty());
        // No docker_service chunk at all: no evidence, no finding.
        assert!(rules(&project(vec![loc("http://api:8080")]), &[]).is_empty());
        // Not service-style names: dotted, IP, localhost, variable.
        for t in [
            "http://api.example.com",
            "http://10.0.0.5:80",
            "http://localhost:3000",
            "http://$backend",
            "http://unix:/run/x.sock",
        ] {
            assert!(
                rules(&project(vec![loc(t), svc.clone()]), &[]).is_empty(),
                "{t}"
            );
        }
    }

    #[test]
    fn an_upstream_defined_in_the_project_satisfies_proxy_pass() {
        let up = chunk(
            "backend",
            "nginx_upstream",
            vec![f("server", "10.0.0.1:80")],
        );
        let loc = chunk(
            "loc",
            "nginx_location",
            vec![f("proxy_pass", "http://backend")],
        );
        let svc = chunk("web", "docker_service", vec![]);
        assert!(rules(&project(vec![up, loc, svc]), &[]).is_empty());
    }

    #[test]
    fn two_peers_with_the_same_network_are_an_error_but_nesting_is_fine() {
        let peer = |n: &str, ips: &str| chunk(n, "wg_peer", vec![f("AllowedIPs", ips)]);
        assert_eq!(
            rules(
                &project(vec![peer("a", "10.0.0.2/32"), peer("b", "10.0.0.2")]),
                &[]
            ),
            ["wireguard-allowed-ips-duplicate"]
        );
        // Host bits are ignored: 10.0.0.5/24 and 10.0.0.9/24 are one network.
        assert_eq!(
            rules(
                &project(vec![peer("a", "10.0.0.5/24"), peer("b", "10.0.0.9/24")]),
                &[]
            )
            .len(),
            1
        );
        // Longest-prefix routing makes a catch-all beside a host route valid.
        assert!(rules(
            &project(vec![peer("a", "0.0.0.0/0, ::/0"), peer("b", "10.0.0.2/32")]),
            &[]
        )
        .is_empty());
        // One peer repeating itself is its own business; references are skipped.
        assert!(rules(&project(vec![peer("a", "10.0.0.2/32, 10.0.0.2/32")]), &[]).is_empty());
        assert!(rules(&project(vec![peer("a", "${X}"), peer("b", "${X}")]), &[]).is_empty());
    }

    #[test]
    fn a_disabled_peer_is_not_in_the_export_and_is_not_checked() {
        let mut b = chunk("b", "wg_peer", vec![f("AllowedIPs", "10.0.0.2/32")]);
        b["disabled"] = json!(true);
        let a = chunk("a", "wg_peer", vec![f("AllowedIPs", "10.0.0.2/32")]);
        assert!(rules(&project(vec![a, b]), &[]).is_empty());
    }

    #[test]
    fn traefik_middleware_must_exist_unless_it_names_another_provider() {
        let router = |m: &str| chunk("r", "traefik_router", vec![f("middlewares", m)]);
        let mw = chunk("auth", "traefik_middleware", vec![f("type", "basicAuth")]);
        assert_eq!(
            rules(&project(vec![router("auth, gone"), mw.clone()]), &[]),
            ["traefik-middleware-missing"]
        );
        assert!(rules(&project(vec![router("AUTH"), mw.clone()]), &[]).is_empty());
        assert!(rules(&project(vec![router("sso@docker, api@internal")]), &[]).is_empty());
    }

    #[test]
    fn an_ingress_needs_a_service_in_the_same_namespace_but_only_when_services_exist() {
        let svc = chunk(
            "s",
            "k8s_service",
            vec![f("name", "my-app"), f("namespace", "prod")],
        );
        let ing = |n: &str, ns: &str| {
            chunk(
                "i",
                "k8s_ingress",
                vec![f("serviceName", n), f("namespace", ns)],
            )
        };
        assert!(rules(&project(vec![svc.clone(), ing("my-app", "prod")]), &[]).is_empty());
        assert_eq!(
            rules(&project(vec![svc.clone(), ing("my-app", "default")]), &[]),
            ["k8s-ingress-service-missing"]
        );
        assert_eq!(
            rules(&project(vec![svc, ing("other", "prod")]), &[]),
            ["k8s-ingress-service-missing"]
        );
        assert!(rules(&project(vec![ing("anything", "prod")]), &[]).is_empty());
    }

    #[test]
    fn a_compose_env_ref_must_resolve_to_a_vault_entry_or_an_env_file_key() {
        let env = |v: &str| json!({"key": "DB_PASS", "value": v, "field_type": "env_var", "description": "env"});
        let svc = |v: &str| chunk("web", "docker_service", vec![env(v)]);
        assert_eq!(
            rules(&project(vec![svc("${NOPE}")]), &["GitHub"]),
            ["compose-env-ref-unresolved"]
        );
        assert!(rules(&project(vec![svc("${GitHub/key}")]), &["GitHub"]).is_empty());
        assert!(rules(&project(vec![svc("${GITHUB_PROD}")]), &["GitHub"]).is_empty());
        let envf = chunk("e", "env_file", vec![f("NOPE", "1")]);
        assert!(rules(&project(vec![svc("${NOPE}"), envf]), &[]).is_empty());
        assert!(rules(&project(vec![svc("${chunk:x/y}")]), &[]).is_empty());
        assert!(rules(&project(vec![svc("plain")]), &[]).is_empty());
    }

    #[test]
    fn a_pg_host_service_must_share_a_network_with_the_service_that_uses_it() {
        let pg = chunk("p", "pg_connection", vec![f("host", "db")]);
        let db = |nets: &str| chunk("db", "docker_service", vec![f("networks", nets)]);
        let app = |nets: &str| {
            chunk(
                "app",
                "docker_service",
                vec![f("networks", nets), f("depends_on", "db")],
            )
        };
        assert_eq!(
            rules(&project(vec![pg.clone(), db("back"), app("front")]), &[]),
            ["pg-host-network-unreachable"]
        );
        assert!(rules(
            &project(vec![pg.clone(), db("back"), app("front, back")]),
            &[]
        )
        .is_empty());
        // Both on the implicit default network.
        assert!(rules(&project(vec![pg.clone(), db(""), app("")]), &[]).is_empty());
        // Nothing uses the db: nothing to say.
        let idle = chunk("idle", "docker_service", vec![f("networks", "front")]);
        assert!(rules(&project(vec![pg.clone(), db("back"), idle]), &[]).is_empty());
        // network_mode opts out of comparison.
        let host_mode = chunk(
            "app",
            "docker_service",
            vec![f("network_mode", "host"), f("depends_on", "db")],
        );
        assert!(rules(&project(vec![pg, db("back"), host_mode]), &[]).is_empty());
    }

    #[test]
    fn findings_carry_names_and_never_field_values_that_could_be_secret() {
        let pg = chunk(
            "p",
            "pg_connection",
            vec![
                f("host", "db"),
                json!({"key":"password","value":"hunter2-SECRET","field_type":"secret"}),
            ],
        );
        let db = chunk("db", "docker_service", vec![f("networks", "back")]);
        let app = chunk(
            "app",
            "docker_service",
            vec![f("networks", "front"), f("depends_on", "db")],
        );
        let out = check_project(&project(vec![pg, db, app]), &[]);
        let text =
            serde_json::to_string(&out.iter().map(Finding::to_json).collect::<Vec<_>>()).unwrap();
        assert!(!text.contains("hunter2"));
    }

    #[test]
    fn nested_allowed_ips_are_a_warning_and_a_default_route_is_not_reported() {
        let peer = |n: &str, ips: &str| chunk(n, "wg_peer", vec![f("AllowedIPs", ips)]);
        assert_eq!(
            rules(
                &project(vec![peer("a", "10.0.0.0/24"), peer("b", "10.0.0.7/32")]),
                &[]
            ),
            ["wireguard-allowed-ips-overlap"]
        );
        // Disjoint networks, and a catch-all beside host routes, are fine.
        assert!(rules(
            &project(vec![peer("a", "10.0.0.0/24"), peer("b", "10.0.1.7/32")]),
            &[]
        )
        .is_empty());
        assert!(rules(
            &project(vec![peer("a", "0.0.0.0/0"), peer("b", "10.0.0.7/32")]),
            &[]
        )
        .is_empty());
        // Different families never nest.
        assert!(rules(
            &project(vec![peer("a", "10.0.0.0/8"), peer("b", "fd00::1/128")]),
            &[]
        )
        .is_empty());
        // IPv6 nesting.
        assert_eq!(
            rules(
                &project(vec![peer("a", "fd00::/64"), peer("b", "fd00::5/128")]),
                &[]
            ),
            ["wireguard-allowed-ips-overlap"]
        );
    }

    #[test]
    fn a_deployment_must_use_secrets_some_chunk_creates() {
        let secret = chunk(
            "app-secrets",
            "k8s_secret",
            vec![f("name", "app-secrets"), f("namespace", "prod")],
        );
        let dep = |env: &str, mounts: &str, ns: &str| {
            chunk(
                "web",
                "k8s_deployment",
                vec![
                    f("secretEnv", env),
                    f("secretMounts", mounts),
                    f("namespace", ns),
                ],
            )
        };
        assert!(rules(
            &project(vec![
                secret.clone(),
                dep("app-secrets", "app-secrets:/etc/a", "prod")
            ]),
            &[]
        )
        .is_empty());
        assert_eq!(
            rules(&project(vec![secret.clone(), dep("gone", "", "prod")]), &[]),
            ["k8s-deployment-secret-missing"]
        );
        assert_eq!(
            rules(
                &project(vec![secret.clone(), dep("", "gone:/x", "prod")]),
                &[]
            ),
            ["k8s-deployment-secret-missing"]
        );
        // Wrong namespace is a missing Secret.
        assert_eq!(
            rules(
                &project(vec![secret.clone(), dep("app-secrets", "", "default")]),
                &[]
            ),
            ["k8s-deployment-secret-missing"]
        );
        // Named twice, reported once. A malformed mount (no path) names nothing.
        assert_eq!(
            rules(
                &project(vec![
                    secret.clone(),
                    dep("gone gone", "gone:/x, nopath:", "prod")
                ]),
                &[]
            )
            .len(),
            1
        );
        // No k8s_secret chunk at all: another manifest set may create it.
        assert!(rules(&project(vec![dep("gone", "gone:/x", "prod")]), &[]).is_empty());
    }

    #[test]
    fn compose_substitution_tokens_anywhere_in_a_service_must_resolve() {
        let svc = |fields: Vec<Value>| chunk("web", "docker_service", fields);
        // An image tag reading ${TAG} that nothing sets.
        assert_eq!(
            rules(&project(vec![svc(vec![f("image", "app:${TAG}")])]), &[]),
            ["compose-env-ref-unresolved"]
        );
        // Set by an env_file chunk, case-insensitively.
        let envf = chunk("e", "env_file", vec![f("tag", "1")]);
        assert!(rules(
            &project(vec![svc(vec![f("image", "app:${TAG}")]), envf]),
            &[]
        )
        .is_empty());
        // Defaults, escapes and operators are the author's own fallback.
        for v in [
            "app:${TAG:-latest}",
            "app:${TAG-latest}",
            "$${TAG}",
            "app:${TAG:?need it}",
            "a:${TAG+x}",
        ] {
            assert!(
                rules(&project(vec![svc(vec![f("image", v)])]), &[]).is_empty(),
                "{v}"
            );
        }
        // Two tokens in one value, one reported per unknown name.
        assert_eq!(
            rules(
                &project(vec![svc(vec![f("command", "run ${A} ${B} ${A}")])]),
                &[]
            )
            .len(),
            2
        );
    }

    #[test]
    fn a_service_that_reads_the_pg_chunk_by_reference_is_a_consumer() {
        let pg = chunk("primary", "pg_connection", vec![f("host", "db")]);
        let db = chunk("db", "docker_service", vec![f("networks", "back")]);
        let env = json!({"key":"DB","value":"${chunk:primary/host}","field_type":"env_var","description":"env"});
        let app = chunk("app", "docker_service", vec![f("networks", "front"), env]);
        let got = rules(&project(vec![pg, db, app]), &[]);
        assert!(got.contains(&"pg-host-network-unreachable"), "{got:?}");
    }
    // ── Phase 29.1 ────────────────────────────────────────────────────────────

    #[test]
    fn traefik_service_missing_fires_and_stays_silent() {
        let router = |svc: &str| {
            chunk(
                "r",
                "traefik_router",
                vec![f("rule", "Host(`a`)"), f("service", svc)],
            )
        };
        let svc = chunk("api", "traefik_service", vec![f("url", "http://x")]);
        assert_eq!(
            rules(&project(vec![router("web"), svc.clone()]), &[]),
            ["traefik-service-missing"]
        );
        assert!(rules(&project(vec![router("API"), svc.clone()]), &[]).is_empty());
        assert!(rules(&project(vec![router("web@docker"), svc.clone()]), &[]).is_empty());
        assert!(rules(&project(vec![router("${svc}"), svc]), &[]).is_empty());
        // No service chunk at all: no evidence.
        assert!(rules(&project(vec![router("web")]), &[]).is_empty());
    }

    #[test]
    fn an_unused_upstream_fires_only_when_proxy_passes_can_be_read() {
        let up = chunk("backend", "nginx_upstream", vec![f("server", "x:1")]);
        let loc = |t: &str| {
            chunk(
                "l",
                "nginx_location",
                vec![f("path", "/"), f("proxy_pass", t)],
            )
        };
        assert_eq!(
            rules(&project(vec![up.clone(), loc("http://other")]), &[]),
            ["nginx-upstream-unused"]
        );
        assert!(rules(&project(vec![up.clone(), loc("http://backend/")]), &[]).is_empty());
        // A reference could name anything.
        assert!(rules(&project(vec![up.clone(), loc("${x}")]), &[]).is_empty());
        // No server/location chunk: the upstream may be used elsewhere.
        assert!(rules(&project(vec![up]), &[]).is_empty());
    }

    #[test]
    fn depends_on_an_unknown_service_is_an_error_but_not_without_services_or_for_refs() {
        let svc = |n: &str, dep: &str| {
            chunk(
                n,
                "docker_service",
                vec![f("image", "x"), f("depends_on", dep)],
            )
        };
        let db = chunk("db", "docker_service", vec![f("image", "pg")]);
        assert_eq!(
            rules(&project(vec![svc("web", "db, cache"), db.clone()]), &[]),
            ["compose-depends-on-unknown-service"]
        );
        assert!(rules(&project(vec![svc("web", "DB"), db.clone()]), &[]).is_empty());
        assert!(rules(&project(vec![svc("web", "${deps}"), db]), &["deps"]).is_empty());
    }

    #[test]
    fn a_published_port_two_services_bind_is_an_error() {
        let svc =
            |n: &str, p: &str| chunk(n, "docker_service", vec![f("image", "x"), f("ports", p)]);
        assert_eq!(
            rules(
                &project(vec![svc("a", "8080:80"), svc("b", "8080:3000")]),
                &[]
            ),
            ["compose-port-clash"]
        );
        // Different protocol, different host ip, container-only, range, one service twice.
        assert!(rules(
            &project(vec![svc("a", "8080:80"), svc("b", "8080:80/udp")]),
            &[]
        )
        .is_empty());
        assert!(rules(
            &project(vec![
                svc("a", "127.0.0.1:8080:80"),
                svc("b", "127.0.0.2:8080:80")
            ]),
            &[]
        )
        .is_empty());
        assert_eq!(
            rules(
                &project(vec![
                    svc("a", "127.0.0.1:8080:80"),
                    svc("b", "0.0.0.0:8080:80")
                ]),
                &[]
            ),
            ["compose-port-clash"]
        );
        assert!(rules(&project(vec![svc("a", "80"), svc("b", "80")]), &[]).is_empty());
        assert!(rules(
            &project(vec![svc("a", "8000-8010:80"), svc("b", "8000-8010:80")]),
            &[]
        )
        .is_empty());
        assert!(rules(&project(vec![svc("a", "8080:80, 9090:80")]), &[]).is_empty());
    }

    #[test]
    fn a_service_network_must_be_declared_once_networks_are_managed_here() {
        let svc = |n: &str| chunk("web", "docker_service", vec![f("networks", n)]);
        let net = chunk("n", "docker_network", vec![f("backend", "bridge")]);
        assert!(rules(&project(vec![svc("backend"), net.clone()]), &[]).is_empty());
        assert!(rules(&project(vec![svc("default, backend"), net.clone()]), &[]).is_empty());
        assert_eq!(
            rules(&project(vec![svc("backend, other"), net]), &[]),
            ["compose-network-undeclared"]
        );
        assert!(rules(&project(vec![svc("anything")]), &[]).is_empty());
    }

    #[test]
    fn a_k8s_service_needs_the_deployment_its_selector_names() {
        let dep = chunk(
            "d",
            "k8s_deployment",
            vec![f("name", "app"), f("namespace", "prod")],
        );
        let svc =
            |n: &str, ns: &str| chunk("s", "k8s_service", vec![f("name", n), f("namespace", ns)]);
        assert!(rules(&project(vec![dep.clone(), svc("app", "prod")]), &[]).is_empty());
        assert_eq!(
            rules(&project(vec![dep.clone(), svc("app", "dev")]), &[]),
            ["k8s-service-selector-unmatched"]
        );
        assert_eq!(
            rules(&project(vec![dep, svc("web", "prod")]), &[]),
            ["k8s-service-selector-unmatched"]
        );
        assert!(rules(&project(vec![svc("web", "prod")]), &[]).is_empty());
    }

    #[test]
    fn a_proxy_pass_host_may_be_a_service_of_another_project_only_in_wide_scope() {
        let web = project(vec![chunk(
            "n",
            "nginx_location",
            vec![f("proxy_pass", "http://api:8080")],
        )]);
        let own = chunk("web", "docker_service", vec![]);
        let other = project(vec![chunk("api", "docker_service", vec![])]);
        // Alone, the only evidence is this project's own service: `api` is unknown.
        let alone = project(vec![
            chunk(
                "n",
                "nginx_location",
                vec![f("proxy_pass", "http://api:8080")],
            ),
            own,
        ]);
        assert_eq!(
            check_project(&alone, &[])
                .iter()
                .map(|x| x.rule)
                .collect::<Vec<_>>(),
            ["nginx-proxy-pass-unknown-service"]
        );
        let els = services_of(&[other]);
        assert_eq!(els, ["api"]);
        assert!(check_project_scoped(&alone, &[], &els).is_empty());
        // With no service in this project, the other projects are the evidence.
        assert!(check_project_scoped(&web, &[], &els).is_empty());
        assert!(
            check_project(&web, &[]).is_empty(),
            "no evidence, no finding"
        );
        // A name nobody defines is still reported in wide scope.
        let missing = project(vec![chunk(
            "n",
            "nginx_location",
            vec![f("proxy_pass", "http://ghost:1")],
        )]);
        assert_eq!(check_project_scoped(&missing, &[], &els).len(), 1);
    }

    #[test]
    fn the_gate_lets_warnings_through_and_stops_errors() {
        let net = chunk("web", "docker_service", vec![f("networks", "nope")]);
        let decl = chunk("n", "docker_network", vec![f("backend", "bridge")]);
        assert_eq!(gate(&project(vec![net, decl]), &[]).len(), 1);
        let warn = project(vec![
            chunk(
                "n",
                "nginx_location",
                vec![f("proxy_pass", "http://ghost:1")],
            ),
            chunk("web", "docker_service", vec![]),
        ]);
        assert_eq!(check_project(&warn, &[]).len(), 1);
        assert!(gate(&warn, &[]).is_empty());
    }
}
