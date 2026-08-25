//! `envv enrich` — fill in an entry's metadata without reading its secret.
//!
//! A vault filled by importing `.env` files is mostly bare: everything is an
//! `env_var` called `DATABASE_URL` with no type, no environment, no description
//! and no icon. Sorting that out by hand means opening each entry and looking at
//! the secret — exactly the thing an orchestrator must not do.
//!
//! So the inference works from two sources that are safe to look at:
//!
//! - **The name.** `STRIPE_LIVE_KEY` says who issued it and where it runs.
//! - **The secret's *prefix*.** `ghp_`, `sk-ant-`, `AKIA`, `xoxb-` and friends
//!   are public, documented, deliberately recognisable issuer markers. Matching
//!   one reads the first few characters of a credential and nothing else — never
//!   the entropy, never the whole value, and nothing is ever echoed back.
//!
//! Proposals are printed with fingerprints, never values, and applied only with
//! `--apply`.

use crate::access::Access;
use crate::data::{self, entries_mut};
use crate::error::CliResult;
use crate::out;
use serde_json::{json, Value};

/// One issuer signature: a prefix, and what it implies.
struct Signature {
    /// Prefix of the stored secret. Public issuer markers only.
    prefix: &'static str,
    /// Display name of the issuing service.
    issuer: &'static str,
    /// `secretType` this implies.
    secret_type: &'static str,
    /// Simple Icons slug for the card.
    icon: &'static str,
    /// API base URL, when the issuer has exactly one.
    api_url: Option<&'static str>,
    /// Deployment context the prefix itself proves (Stripe's live/test keys).
    environment: Option<&'static str>,
}

const fn sig(
    prefix: &'static str,
    issuer: &'static str,
    secret_type: &'static str,
    icon: &'static str,
    api_url: Option<&'static str>,
    environment: Option<&'static str>,
) -> Signature {
    Signature {
        prefix,
        issuer,
        secret_type,
        icon,
        api_url,
        environment,
    }
}

/// Documented, public issuer prefixes.
///
/// Ordered longest-first where prefixes nest (`sk-ant-` before `sk-`), because
/// the first match wins and the more specific one is the more useful answer.
const SIGNATURES: &[Signature] = &[
    sig(
        "github_pat_",
        "GitHub",
        "api_key",
        "github",
        Some("https://api.github.com"),
        None,
    ),
    sig(
        "ghp_",
        "GitHub",
        "api_key",
        "github",
        Some("https://api.github.com"),
        None,
    ),
    sig(
        "gho_",
        "GitHub",
        "api_key",
        "github",
        Some("https://api.github.com"),
        None,
    ),
    sig(
        "ghs_",
        "GitHub",
        "api_key",
        "github",
        Some("https://api.github.com"),
        None,
    ),
    sig(
        "glpat-",
        "GitLab",
        "api_key",
        "gitlab",
        Some("https://gitlab.com/api/v4"),
        None,
    ),
    sig(
        "sk-ant-",
        "Anthropic",
        "api_key",
        "anthropic",
        Some("https://api.anthropic.com"),
        None,
    ),
    sig(
        "sk-proj-",
        "OpenAI",
        "api_key",
        "openai",
        Some("https://api.openai.com/v1"),
        None,
    ),
    sig(
        "sk-",
        "OpenAI",
        "api_key",
        "openai",
        Some("https://api.openai.com/v1"),
        None,
    ),
    sig(
        "xai-",
        "xAI",
        "api_key",
        "x",
        Some("https://api.x.ai/v1"),
        None,
    ),
    sig(
        "hf_",
        "HuggingFace",
        "api_key",
        "huggingface",
        Some("https://huggingface.co/api"),
        None,
    ),
    sig("AKIA", "AWS", "api_key", "amazonaws", None, None),
    sig("ASIA", "AWS", "api_key", "amazonaws", None, None),
    sig("AIza", "Google", "api_key", "google", None, None),
    sig("ya29.", "Google", "api_key", "google", None, None),
    sig(
        "xoxb-",
        "Slack",
        "api_key",
        "slack",
        Some("https://slack.com/api"),
        None,
    ),
    sig(
        "xoxp-",
        "Slack",
        "api_key",
        "slack",
        Some("https://slack.com/api"),
        None,
    ),
    sig(
        "xapp-",
        "Slack",
        "api_key",
        "slack",
        Some("https://slack.com/api"),
        None,
    ),
    sig(
        "sk_live_",
        "Stripe",
        "api_key",
        "stripe",
        Some("https://api.stripe.com"),
        Some("production"),
    ),
    sig(
        "sk_test_",
        "Stripe",
        "api_key",
        "stripe",
        Some("https://api.stripe.com"),
        Some("testing"),
    ),
    sig(
        "pk_live_",
        "Stripe",
        "api_key",
        "stripe",
        Some("https://api.stripe.com"),
        Some("production"),
    ),
    sig(
        "pk_test_",
        "Stripe",
        "api_key",
        "stripe",
        Some("https://api.stripe.com"),
        Some("testing"),
    ),
    sig(
        "rk_live_",
        "Stripe",
        "api_key",
        "stripe",
        Some("https://api.stripe.com"),
        Some("production"),
    ),
    sig("shpat_", "Shopify", "api_key", "shopify", None, None),
    sig(
        "dop_v1_",
        "DigitalOcean",
        "api_key",
        "digitalocean",
        Some("https://api.digitalocean.com/v2"),
        None,
    ),
    sig(
        "doo_v1_",
        "DigitalOcean",
        "api_key",
        "digitalocean",
        Some("https://api.digitalocean.com/v2"),
        None,
    ),
    sig(
        "dckr_pat_",
        "Docker Hub",
        "api_key",
        "docker",
        Some("https://hub.docker.com/v2"),
        None,
    ),
    sig(
        "npm_",
        "npm",
        "api_key",
        "npm",
        Some("https://registry.npmjs.org"),
        None,
    ),
    sig(
        "pypi-",
        "PyPI",
        "api_key",
        "pypi",
        Some("https://upload.pypi.org/legacy/"),
        None,
    ),
    sig(
        "SG.",
        "SendGrid",
        "api_key",
        "sendgrid",
        Some("https://api.sendgrid.com/v3"),
        None,
    ),
    sig(
        "key-",
        "Mailgun",
        "api_key",
        "mailgun",
        Some("https://api.mailgun.net/v3"),
        None,
    ),
    sig("tvly-", "Tavily", "api_key", "tavily", None, None),
    sig(
        "fig_",
        "Figma",
        "api_key",
        "figma",
        Some("https://api.figma.com/v1"),
        None,
    ),
    sig(
        "atlasv1.",
        "MongoDB Atlas",
        "api_key",
        "mongodb",
        None,
        None,
    ),
    sig(
        "lin_api_",
        "Linear",
        "api_key",
        "linear",
        Some("https://api.linear.app/graphql"),
        None,
    ),
    sig(
        "ntn_",
        "Notion",
        "api_key",
        "notion",
        Some("https://api.notion.com/v1"),
        None,
    ),
    sig(
        "secret_",
        "Notion",
        "api_key",
        "notion",
        Some("https://api.notion.com/v1"),
        None,
    ),
    sig("nvapi-", "NVIDIA", "api_key", "nvidia", None, None),
    sig(
        "gsk_",
        "Groq",
        "api_key",
        "groq",
        Some("https://api.groq.com/openai/v1"),
        None,
    ),
    sig(
        "r8_",
        "Replicate",
        "api_key",
        "replicate",
        Some("https://api.replicate.com/v1"),
        None,
    ),
    sig("pcsk_", "Pinecone", "api_key", "pinecone", None, None),
];

/// Structural shapes that name a *kind* of secret rather than an issuer.
fn structural_type(secret: &str) -> Option<(&'static str, &'static str)> {
    let t = secret.trim();
    if t.starts_with("-----BEGIN CERTIFICATE") {
        return Some(("certificate", "PEM certificate block"));
    }
    if t.starts_with("-----BEGIN") && t.contains("PRIVATE KEY") {
        return Some(("ssh_key", "PEM private key block"));
    }
    if t.starts_with("ssh-rsa ") || t.starts_with("ssh-ed25519 ") || t.starts_with("ecdsa-sha2-") {
        return Some(("ssh_key", "OpenSSH public key"));
    }
    // A JWT is three base64url segments separated by dots, and the header always
    // encodes to `eyJ`. Matching the shape says "this is a token", not what is in it.
    if t.starts_with("eyJ") && t.matches('.').count() == 2 {
        return Some(("api_key", "JWT (three base64url segments)"));
    }
    for scheme in [
        "postgres://",
        "postgresql://",
        "mysql://",
        "mongodb://",
        "mongodb+srv://",
        "redis://",
        "rediss://",
        "amqp://",
        "amqps://",
        "mssql://",
        "clickhouse://",
    ] {
        if t.starts_with(scheme) {
            return Some(("connection_string", "database URI scheme"));
        }
    }
    None
}

/// What a name suggests about where a credential runs.
fn environment_from_name(name: &str) -> Option<&'static str> {
    let n = name.to_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|w| n.contains(w));
    if has(&["_prod", "prod_", "-prod", "production", "live"]) {
        Some("production")
    } else if has(&["_stag", "stag", "staging", "preprod"]) {
        Some("staging")
    } else if has(&["_test", "test_", "-test", "testing", "sandbox"]) {
        Some("testing")
    } else if has(&["_dev", "dev_", "-dev", "development", "local"]) {
        Some("development")
    } else {
        None
    }
}

/// A single proposed field change.
#[derive(Clone)]
pub struct Proposal {
    pub field: String,
    pub value: Value,
    pub reason: String,
}

/// Everything inferred for one entry.
pub struct EntryPlan {
    pub provider: String,
    pub fingerprint: String,
    pub proposals: Vec<Proposal>,
}

fn is_blank(entry: &Value, field: &str) -> bool {
    // `secretType` is never absent — every writer stamps `api_key`, the
    // documented default for legacy entries. Treating that as "set" meant a
    // `postgres://` URL stayed classified as an API key forever, which is the
    // single most common thing an imported `.env` gets wrong.
    if field == "secretType" {
        return matches!(
            entry.get(field).and_then(|v| v.as_str()),
            None | Some("") | Some("api_key")
        );
    }
    match entry.get(field) {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.is_empty(),
        Some(Value::Array(a)) => a.is_empty(),
        _ => false,
    }
}

/// Infer metadata for one entry.
///
/// Only ever *fills gaps*: a field the user already set is never overwritten,
/// because a wrong guess that silently replaces a deliberate choice is worse
/// than no guess at all. `force` relaxes that for a re-classification pass.
pub fn plan_entry(entry: &Value, force: bool) -> EntryPlan {
    let provider = data::provider_of(entry).to_string();
    let secret = entry.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
    let mut proposals: Vec<Proposal> = Vec::new();
    // A closure would borrow `proposals` for the whole function, and the tags
    // branch below needs it too.
    macro_rules! propose {
        ($field:expr, $value:expr, $reason:expr) => {
            if force || is_blank(entry, $field) {
                proposals.push(Proposal {
                    field: $field.to_string(),
                    value: $value,
                    reason: $reason,
                });
            }
        };
    }

    let matched = SIGNATURES.iter().find(|s| secret.starts_with(s.prefix));

    if let Some(s) = matched {
        let why = format!(
            "secret carries the public `{}` prefix used by {}",
            s.prefix, s.issuer
        );
        propose!("secretType", json!(s.secret_type), why.clone());
        propose!("custom_icon", json!(s.icon), why.clone());
        if let Some(url) = s.api_url {
            propose!("api_url", json!(url), why.clone());
        }
        if let Some(env) = s.environment {
            propose!(
                "environment",
                json!(env),
                format!("`{}` is {env}-only at {}", s.prefix, s.issuer)
            );
        }
        propose!(
            "api_description",
            json!(format!("{} credential", s.issuer)),
            why.clone()
        );
        // A tag is the cheapest way to make a hundred imported variables
        // navigable, and it is derived, so re-running does not multiply it.
        let issuer_tag = s.issuer.to_lowercase().replace(' ', "-");
        let existing_tags: Vec<String> = entry
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|t| t.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !existing_tags.iter().any(|t| t == &issuer_tag) {
            let mut next = existing_tags.clone();
            next.push(issuer_tag.clone());
            proposals.push(Proposal {
                field: "tags".into(),
                value: json!(next),
                reason: format!("issuer recognised as {}", s.issuer),
            });
        }
    } else if let Some((kind, why)) = structural_type(secret) {
        propose!("secretType", json!(kind), format!("value shape: {why}"));
    }

    if let Some(env) = environment_from_name(&provider) {
        propose!(
            "environment",
            json!(env),
            format!("name contains a {env} marker")
        );
    }

    // An imported `.env` variable is named like a shell variable, and that name
    // is the natural env-var prefix for anything consuming it.
    if provider.contains('_') && provider.to_uppercase() == provider {
        let head = provider.split('_').next().unwrap_or("");
        if head.len() >= 2 {
            propose!(
                "env_prefixes",
                json!([head]),
                format!("`{provider}` reads as a shell variable in the `{head}_` namespace")
            );
        }
    }

    // The prefix and the name can both speak to `environment`. The first
    // proposal is the better-evidenced one (a `sk_live_` prefix *proves* what a
    // name only hints at), so later duplicates are dropped rather than shown.
    let mut seen: Vec<String> = Vec::new();
    proposals.retain(|p| {
        if seen.iter().any(|f| f == &p.field) {
            false
        } else {
            seen.push(p.field.clone());
            true
        }
    });

    EntryPlan {
        provider,
        fingerprint: out::fingerprint(secret),
        proposals,
    }
}

// ── Live enrichment ───────────────────────────────────────────────────────────

/// How to ask an issuer who a credential belongs to.
struct Probe {
    /// Prefixes this probe applies to.
    prefixes: &'static [&'static str],
    issuer: &'static str,
    url: &'static str,
    /// How the credential is presented. Each issuer picked its own convention.
    auth: Auth,
}

enum Auth {
    Bearer,
    /// GitLab's own header.
    PrivateToken,
    /// Anthropic's `x-api-key` plus its required version header.
    AnthropicKey,
    /// Stripe uses HTTP basic with the key as the username.
    BasicUser,
}

const PROBES: &[Probe] = &[
    Probe {
        prefixes: &["ghp_", "github_pat_", "gho_", "ghs_"],
        issuer: "GitHub",
        url: "https://api.github.com/user",
        auth: Auth::Bearer,
    },
    Probe {
        prefixes: &["glpat-"],
        issuer: "GitLab",
        url: "https://gitlab.com/api/v4/user",
        auth: Auth::PrivateToken,
    },
    Probe {
        prefixes: &["xoxb-", "xoxp-", "xapp-"],
        issuer: "Slack",
        url: "https://slack.com/api/auth.test",
        auth: Auth::Bearer,
    },
    Probe {
        prefixes: &["sk_live_", "sk_test_", "rk_live_"],
        issuer: "Stripe",
        url: "https://api.stripe.com/v1/account",
        auth: Auth::BasicUser,
    },
    Probe {
        prefixes: &["dop_v1_"],
        issuer: "DigitalOcean",
        url: "https://api.digitalocean.com/v2/account",
        auth: Auth::Bearer,
    },
    Probe {
        prefixes: &["npm_"],
        issuer: "npm",
        url: "https://registry.npmjs.org/-/whoami",
        auth: Auth::Bearer,
    },
    Probe {
        prefixes: &["sk-proj-", "sk-"],
        issuer: "OpenAI",
        url: "https://api.openai.com/v1/models",
        auth: Auth::Bearer,
    },
    Probe {
        prefixes: &["sk-ant-"],
        issuer: "Anthropic",
        url: "https://api.anthropic.com/v1/models",
        auth: Auth::AnthropicKey,
    },
];

/// What an online probe learned.
pub struct Live {
    pub issuer: &'static str,
    /// `ok`, `rejected` (the issuer says this credential is not valid) or
    /// `unreachable`.
    pub status: &'static str,
    pub detail: String,
    pub proposals: Vec<Proposal>,
}

/// Pull the first string found at any of `paths` in a JSON body.
fn pick(body: &Value, paths: &[&str]) -> Option<String> {
    for path in paths {
        let mut cur = body;
        for part in path.split('.') {
            cur = cur.get(part)?;
        }
        if let Some(s) = cur.as_str() {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Ask the issuer about one credential.
///
/// **This sends the secret over TLS to the service that issued it** — the only
/// party that already has it — and to nowhere else. It is behind `--online` for
/// exactly that reason: a command that reads a vault should not start making
/// network calls because someone ran it out of habit.
pub fn probe_entry(entry: &Value, timeout_secs: u64, force: bool) -> Option<Live> {
    let secret = entry.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
    let probe = PROBES
        .iter()
        .find(|p| p.prefixes.iter().any(|pre| secret.starts_with(pre)))?;

    // Deliberately a *public* client: these are the issuers' own endpoints, so
    // they get ordinary CA validation and never the pin configured for
    // --server. Some of these APIs reject a request with no user agent outright.
    let client = crate::tls::build_public_client(
        std::time::Duration::from_secs(timeout_secs),
        concat!("envv/", env!("CARGO_PKG_VERSION")),
    )
    .ok()?;

    let mut req = client.get(probe.url);
    req = match probe.auth {
        Auth::Bearer => req.bearer_auth(secret),
        Auth::PrivateToken => req.header("PRIVATE-TOKEN", secret),
        Auth::AnthropicKey => req
            .header("x-api-key", secret)
            .header("anthropic-version", "2023-06-01"),
        Auth::BasicUser => req.basic_auth(secret, None::<&str>),
    };

    let resp = match req.send() {
        Ok(r) => r,
        Err(e) => {
            return Some(Live {
                issuer: probe.issuer,
                status: "unreachable",
                // The error can contain the URL but never the credential.
                detail: e.to_string(),
                proposals: Vec::new(),
            });
        }
    };

    let status = resp.status();
    let headers = resp.headers().clone();
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .filter(|s| !s.is_empty())
    };

    if !status.is_success() {
        return Some(Live {
            issuer: probe.issuer,
            status: "rejected",
            detail: format!("{} answered {status}", probe.issuer),
            proposals: Vec::new(),
        });
    }

    let body: Value = resp.json().unwrap_or(Value::Null);
    // Slack answers 200 with `{"ok": false}` when the token is bad.
    if body.get("ok").and_then(|v| v.as_bool()) == Some(false) {
        let why = pick(&body, &["error"]).unwrap_or_else(|| "not accepted".into());
        return Some(Live {
            issuer: probe.issuer,
            status: "rejected",
            detail: format!("{} answered ok=false ({why})", probe.issuer),
            proposals: Vec::new(),
        });
    }

    let mut proposals: Vec<Proposal> = Vec::new();
    let mut push = |field: &str, value: Value, reason: String| {
        if force || is_blank(entry, field) {
            proposals.push(Proposal {
                field: field.to_string(),
                value,
                reason,
            });
        }
    };

    let identity = pick(
        &body,
        &[
            "login",
            "username",
            "user",
            "email",
            "account.email",
            "business_profile.name",
            "id",
        ],
    );
    if let Some(who) = &identity {
        push(
            "account_name",
            json!(who),
            format!("{} says this credential belongs to {who}", probe.issuer),
        );
    }

    // Scopes and expiry are the two facts a stored credential cannot tell you
    // about itself, and both are what a rotation policy actually needs.
    if let Some(scopes) = header("x-oauth-scopes") {
        let list: Vec<String> = scopes
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.is_empty() {
            push(
                "scopes",
                json!(list),
                format!("{} reported the token's scopes", probe.issuer),
            );
        }
    }
    if let Some(exp) = header("github-authentication-token-expiration") {
        let day: String = exp.chars().take(10).collect();
        push(
            "expires_at",
            json!(day),
            "GitHub reported the token's expiry".into(),
        );
    }
    if let Some(limit) = header("x-ratelimit-limit") {
        push(
            "rate_limit",
            json!(format!("{limit} req/hour")),
            format!(
                "{} reported the rate limit for this credential",
                probe.issuer
            ),
        );
    }

    let desc = match &identity {
        Some(who) => format!("{} credential — verified, {who}", probe.issuer),
        None => format!(
            "{} credential — verified {}",
            probe.issuer,
            vault_core::iso_now().chars().take(10).collect::<String>()
        ),
    };
    push(
        "api_description",
        json!(desc),
        format!("confirmed live against {}", probe.url),
    );

    Some(Live {
        issuer: probe.issuer,
        status: "ok",
        detail: identity.unwrap_or_else(|| "accepted".into()),
        proposals,
    })
}

pub struct EnrichOpts<'a> {
    pub apply: bool,
    pub force: bool,
    pub only: Option<&'a str>,
    /// Ask each issuer about its own credential. Sends the secret to the service
    /// that issued it, over TLS, and nowhere else.
    pub online: bool,
    pub timeout_secs: u64,
}

pub fn cmd_enrich(access: &Access, opts: &EnrichOpts<'_>) -> CliResult {
    let (apply, force, only) = (opts.apply, opts.force, opts.only);
    let mut vault = access.load_vault()?;
    let entries = data::entries(&vault);

    let mut plans: Vec<EntryPlan> = Vec::new();
    let mut live_rows: Vec<Value> = Vec::new();
    for entry in &entries {
        if let Some(q) = only {
            if !data::provider_of(entry)
                .to_lowercase()
                .contains(&q.to_lowercase())
            {
                continue;
            }
        }
        let mut plan = plan_entry(entry, force);

        if opts.online {
            if let Some(live) = probe_entry(entry, opts.timeout_secs, force) {
                live_rows.push(json!({
                    "provider": plan.provider,
                    "issuer": live.issuer,
                    "status": live.status,
                    "detail": live.detail,
                }));
                // Live facts win over guesses: the issuer knows, the prefix
                // table only infers. Anything the probe returned replaces the
                // offline proposal for the same field.
                for p in live.proposals {
                    plan.proposals.retain(|existing| existing.field != p.field);
                    plan.proposals.push(p);
                }
            }
        }

        if !plan.proposals.is_empty() {
            plans.push(plan);
        }
    }

    let changed_entries = plans.len();
    let changed_fields: usize = plans.iter().map(|p| p.proposals.len()).sum();

    if apply && !plans.is_empty() {
        for plan in &plans {
            let idx = match data::find_entry_index(&vault, &plan.provider) {
                Ok(i) => i,
                // Two entries can share a provider name; skip rather than guess
                // which one the plan was for.
                Err(_) => continue,
            };
            let list = entries_mut(&mut vault);
            for p in &plan.proposals {
                list[idx][&p.field] = p.value.clone();
            }
        }
        access.save(&vault)?;
    }

    let data_json = json!({
        "applied": apply,
        "online": opts.online,
        "probed": live_rows,
        "entries_matched": changed_entries,
        "fields": changed_fields,
        "plans": plans
            .iter()
            .map(|p| json!({
                "provider": p.provider,
                // The fingerprint, never the value — the whole point of a command
                // that reads secrets is that its output does not contain them.
                "fingerprint": p.fingerprint,
                "proposals": p.proposals.iter().map(|x| json!({
                    "field": x.field, "value": x.value, "reason": x.reason,
                })).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
    });

    out::ok("enrich", data_json, || {
        for row in &live_rows {
            let status = row["status"].as_str().unwrap_or("");
            // A rejected credential is the most valuable thing this command can
            // find: it is dead, and nothing in the vault would ever have said so.
            let mark = match status {
                "ok" => "live",
                "rejected" => "REJECTED",
                _ => "unreachable",
            };
            println!(
                "{:<8} {:<24} {}",
                mark,
                row["provider"].as_str().unwrap_or(""),
                row["detail"].as_str().unwrap_or("")
            );
        }
        if !live_rows.is_empty() {
            println!();
        }
        if plans.is_empty() {
            println!("Nothing to enrich — every entry already carries what could be inferred.");
            return;
        }
        for plan in &plans {
            println!("{} ({})", plan.provider, plan.fingerprint);
            for p in &plan.proposals {
                let shown = match &p.value {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                println!("  {:<16} {:<28} {}", p.field, shown, p.reason);
            }
        }
        println!(
            "\n{changed_fields} field(s) across {changed_entries} entr{}",
            if changed_entries == 1 { "y" } else { "ies" }
        );
        if apply {
            println!("Applied.");
        } else {
            println!("Nothing written — re-run with --apply.");
        }
    });
    Ok(())
}
