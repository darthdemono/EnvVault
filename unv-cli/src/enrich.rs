//! `unv enrich` — fill in an entry's metadata without reading its secret.
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

/// A matched issuer, owned so a catalogue entry and a compiled one look alike.
struct Hit {
    prefix: String,
    issuer: String,
    secret_type: String,
    icon: String,
    api_url: Option<String>,
    environment: Option<String>,
    acts_as: Option<String>,
    exposure: Option<String>,
    console_url: Option<String>,
}

/// The verified, cached provider catalogue (Phase 31), loaded once per process.
fn catalogue() -> Option<&'static vault_core::catalogue::Catalogue> {
    static C: std::sync::OnceLock<Option<vault_core::catalogue::Catalogue>> =
        std::sync::OnceLock::new();
    C.get_or_init(vault_core::catalogue::load_cached).as_ref()
}

/// Longest matching prefix across the catalogue and the compiled table. A tie
/// goes to the catalogue, which is the newer of the two.
fn lookup(secret: &str) -> Option<Hit> {
    let fresh = catalogue().and_then(|c| {
        c.providers
            .iter()
            .filter(|p| secret.starts_with(p.prefix.as_str()))
            .max_by_key(|p| p.prefix.len())
    });
    let built = SIGNATURES.iter().find(|s| secret.starts_with(s.prefix));
    match (fresh, built) {
        (Some(p), b) if b.is_none_or(|b| p.prefix.len() >= b.prefix.len()) => Some(Hit {
            prefix: p.prefix.clone(),
            issuer: p.issuer.clone(),
            secret_type: p.secret_type.clone(),
            icon: p.icon.clone(),
            api_url: p.api_url.clone(),
            environment: p.environment.clone(),
            acts_as: p.acts_as.clone(),
            exposure: p.exposure.clone(),
            console_url: p.console_url.clone(),
        }),
        (_, Some(s)) => Some(Hit {
            prefix: s.prefix.into(),
            issuer: s.issuer.into(),
            secret_type: s.secret_type.into(),
            icon: s.icon.into(),
            api_url: s.api_url.map(Into::into),
            environment: s.environment.map(Into::into),
            // Compiled signatures keep their axes in AXIS_SIGNATURES.
            acts_as: None,
            exposure: None,
            console_url: None,
        }),
        _ => None,
    }
}

/// The compiled table as catalogue providers, for `catalogue export`/`diff`.
pub fn bundled_providers() -> Vec<vault_core::catalogue::Provider> {
    SIGNATURES
        .iter()
        .map(|s| vault_core::catalogue::Provider {
            prefix: s.prefix.into(),
            issuer: s.issuer.into(),
            secret_type: s.secret_type.into(),
            icon: s.icon.into(),
            api_url: s.api_url.map(Into::into),
            environment: s.environment.map(Into::into),
            acts_as: AXIS_SIGNATURES
                .iter()
                .find(|a| a.prefix == s.prefix)
                .and_then(|a| a.acts_as.map(Into::into)),
            exposure: AXIS_SIGNATURES
                .iter()
                .find(|a| a.prefix == s.prefix)
                .and_then(|a| a.exposure.map(Into::into)),
            console_url: None,
            docs_url: None,
            rotate_url: None,
            revoke_url: None,
            verified_on: None,
            source_url: None,
        })
        .collect()
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
    // Must precede the bare `sk-` fallback below — `find()` takes the first
    // match, and both of these start with `sk-` too.
    sig(
        "sk-svcacct-",
        "OpenAI",
        "api_key",
        "openai",
        Some("https://api.openai.com/v1"),
        None,
    ),
    sig(
        "sk-admin-",
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
    // Phase 24.5's taxonomy needs prefixes SIGNATURES did not previously carry
    // on their own, because each names a *different* secret_type or acts_as
    // than its sibling prefixes at the same issuer.
    sig(
        "ghu_",
        "GitHub",
        "api_key",
        "github",
        Some("https://api.github.com"),
        None,
    ),
    // A GitHub App *refresh* token, not an access token — `unv-cli`'s own
    // `oauth_client` type is where a refresh token belongs (E7's two-lifetime
    // shape), never `api_key`.
    sig("ghr_", "GitHub", "oauth_client", "github", None, None),
    // A Slack app-level refresh token — same reasoning as `ghr_`.
    sig("xoxe-", "Slack", "oauth_client", "slack", None, None),
    // The browser-session half of Slack's `xoxc-`/`d`-cookie pair. Recognised
    // alone since `unv enrich` sees one value at a time; the design's fuller
    // rule (xoxc- is only complete paired with the `d` cookie) needs a second
    // value this scan does not have.
    sig("xoxc-", "Slack", "cookie", "slack", None, None),
    sig(
        "rk_test_",
        "Stripe",
        "api_key",
        "stripe",
        Some("https://api.stripe.com"),
        Some("testing"),
    ),
    // A webhook signing secret verifies an incoming request; it is never sent
    // anywhere, which is the opposite of every other Stripe key here.
    sig("whsec_", "Stripe", "api_key", "stripe", None, None),
];

/// One issuer prefix's claim about the API-key taxonomy axes (Phase 24.5) —
/// `acts_as` and `exposure`, layered on top of `SIGNATURES` rather than
/// added to it: most of the sixty-odd prefixes above have no useful axis
/// claim (a bare API key `is_blank` axis-wise is not wrong, just unknown),
/// and folding three more optional fields into every `sig(...)` call would
/// touch every existing row for the handful that actually need one.
///
/// **These are claims, never enforcement** — `exposure: "publishable"`
/// *suggests* `primary_public`, it never sets it. A misdetected prefix must
/// not be able to make redaction print less; `primary_public` stays the only
/// switch redaction reads, exactly as the design requires.
struct AxisSignature {
    prefix: &'static str,
    acts_as: Option<&'static str>,
    exposure: Option<&'static str>,
}

const AXIS_SIGNATURES: &[AxisSignature] = &[
    AxisSignature {
        prefix: "github_pat_",
        acts_as: Some("user"),
        exposure: None,
    },
    AxisSignature {
        prefix: "ghp_",
        acts_as: Some("user"),
        exposure: None,
    },
    AxisSignature {
        prefix: "gho_",
        acts_as: Some("user"),
        exposure: None,
    },
    AxisSignature {
        prefix: "ghu_",
        acts_as: Some("user"),
        exposure: None,
    },
    AxisSignature {
        prefix: "ghs_",
        acts_as: Some("installation"),
        exposure: None,
    },
    AxisSignature {
        prefix: "sk-proj-",
        acts_as: Some("user"),
        exposure: None,
    },
    AxisSignature {
        prefix: "sk-svcacct-",
        acts_as: Some("service"),
        exposure: None,
    },
    AxisSignature {
        prefix: "sk-admin-",
        acts_as: Some("admin"),
        exposure: None,
    },
    AxisSignature {
        prefix: "xoxb-",
        acts_as: Some("bot"),
        exposure: None,
    },
    AxisSignature {
        prefix: "xoxp-",
        acts_as: Some("user"),
        exposure: None,
    },
    AxisSignature {
        prefix: "xapp-",
        acts_as: Some("installation"),
        exposure: None,
    },
    AxisSignature {
        prefix: "pk_live_",
        acts_as: None,
        exposure: Some("publishable"),
    },
    AxisSignature {
        prefix: "pk_test_",
        acts_as: None,
        exposure: Some("publishable"),
    },
    AxisSignature {
        prefix: "sk_live_",
        acts_as: None,
        exposure: Some("server_only"),
    },
    AxisSignature {
        prefix: "sk_test_",
        acts_as: None,
        exposure: Some("server_only"),
    },
    AxisSignature {
        prefix: "rk_live_",
        acts_as: None,
        exposure: Some("server_only"),
    },
    AxisSignature {
        prefix: "rk_test_",
        acts_as: None,
        exposure: Some("server_only"),
    },
    AxisSignature {
        prefix: "whsec_",
        acts_as: None,
        exposure: Some("verify_only"),
    },
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

    let matched = lookup(secret);

    if let Some(s) = matched.as_ref() {
        let why = format!(
            "secret carries the public `{}` prefix used by {}",
            s.prefix, s.issuer
        );
        propose!("secretType", json!(s.secret_type), why.clone());
        propose!("custom_icon", json!(s.icon), why.clone());
        if let Some(url) = &s.api_url {
            propose!("api_url", json!(url), why.clone());
        }
        if let Some(env) = &s.environment {
            propose!(
                "environment",
                json!(env),
                format!("`{}` is {env}-only at {}", s.prefix, s.issuer)
            );
        }
        // Every issuer in `SIGNATURES` is a hosted cloud service — there is no
        // `self_hosted` or `local` prefix table, because those types are set
        // structurally (`secretType == "local_service"`), not sniffed from a
        // value's first few characters.
        propose!("issuer_kind", json!("saas"), why.clone());
        // The catalogue's own axes win; a compiled signature carries none on the
        // Hit and falls through to AXIS_SIGNATURES.
        let axis = AXIS_SIGNATURES
            .iter()
            .find(|a| a.prefix == s.prefix.as_str());
        let acts_as = s
            .acts_as
            .clone()
            .or_else(|| axis.and_then(|a| a.acts_as.map(String::from)));
        let exposure = s
            .exposure
            .clone()
            .or_else(|| axis.and_then(|a| a.exposure.map(String::from)));
        if let Some(v) = acts_as {
            propose!(
                "acts_as",
                json!(v),
                format!("`{}` is {}'s {v} prefix", s.prefix, s.issuer)
            );
        }
        if let Some(v) = exposure {
            propose!(
                "exposure",
                json!(v),
                format!("`{}` is {}'s {v} prefix", s.prefix, s.issuer)
            );
        }
        if let Some(url) = &s.console_url {
            propose!("console_url", json!(url), why.clone());
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
/// The issuer `--online` would send this entry's secret to, or `None` when it
/// would contact no one (no recognised prefix, or a cookie, which is never
/// probed). Lets the app name every recipient on its consent screen before any
/// request is made.
pub fn issuer_for(entry: &Value) -> Option<String> {
    if data::secret_type_of(entry) == "cookie" {
        return None;
    }
    let secret = entry.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
    if let Some(base) = grafana_base(entry) {
        // A self-hosted service: name the host, because the host is the recipient.
        return Some(format!("Grafana at {}", host_of(&base)));
    }
    PROBES
        .iter()
        .find(|p| p.prefixes.iter().any(|pre| secret.starts_with(pre)))
        .map(|p| p.issuer.to_string())
}

// ── Self-hosted Grafana (Phase 38.1, ADR-0148) ──────────────────────────────────────────
//
// Every other probe talks to the issuer's own public host. Grafana is run by the
// user, so the host is the entry's `api_url` - which in an imported or shared
// vault is attacker-controlled text. The rules that make sending a token there
// acceptable: the prefix must be a Grafana service-account token (`glsa_`), the
// URL must be a plain origin with no userinfo or query, `https` goes anywhere, and
// plain `http` only to a name that cannot be reached from the public internet.

fn host_of(base: &str) -> String {
    reqwest::Url::parse(base)
        .ok()
        .map(|u| match (u.host_str(), u.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_string(),
            _ => String::new(),
        })
        .unwrap_or_default()
}

/// A host a plain-`http` request cannot leave the local network to reach.
fn private_host(host: &str) -> bool {
    use std::net::IpAddr;
    let h = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_lowercase();
    if let Ok(ip) = h.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local(),
            IpAddr::V6(v) => {
                v.is_loopback()
                    || (v.segments()[0] & 0xfe00) == 0xfc00
                    || (v.segments()[0] & 0xffc0) == 0xfe80
            }
        };
    }
    !h.contains('.')
        || [".local", ".lan", ".home.arpa", ".internal"]
            .iter()
            .any(|suffix| h.ends_with(suffix))
}

/// The base URL to probe for a Grafana service-account token, or `None`.
pub fn grafana_base(entry: &Value) -> Option<String> {
    let secret = entry.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
    if !secret.starts_with("glsa_") || data::secret_type_of(entry) == "cookie" {
        return None;
    }
    let raw = entry.get("api_url").and_then(|v| v.as_str())?.trim();
    let url = reqwest::Url::parse(raw).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = url.host_str()?;
    match url.scheme() {
        "https" => {}
        "http" if private_host(host) => {}
        _ => return None,
    }
    Some(raw.trim_end_matches('/').to_string())
}

/// Ask a Grafana who a service-account token is and which organisation it acts in.
///
/// Checked against Grafana 11.2: `/api/user` names the service account, and
/// `/api/org` the organisation. `/api/user/orgs` (which carries a role) answers a
/// service-account token with "Endpoint only available for users", and
/// `/api/serviceaccounts/{id}` needs a permission an ordinary token lacks, so the
/// role is not available and is not guessed.
fn probe_grafana(
    entry: &Value,
    base: &str,
    secret: &str,
    timeout_secs: u64,
    force: bool,
) -> Option<Live> {
    let client = crate::tls::build_public_client(
        std::time::Duration::from_secs(timeout_secs),
        concat!("envv/", env!("CARGO_PKG_VERSION")),
    )
    .ok()?;
    let issuer = "Grafana";
    let who = client
        .get(format!("{base}/api/user"))
        .bearer_auth(secret)
        .send();
    let resp = match who {
        Ok(r) => r,
        Err(e) => {
            return Some(Live {
                issuer,
                status: "unreachable",
                detail: e.to_string(),
                proposals: Vec::new(),
            })
        }
    };
    if !resp.status().is_success() {
        return Some(Live {
            issuer,
            status: "rejected",
            detail: format!("Grafana at {} answered {}", host_of(base), resp.status()),
            proposals: Vec::new(),
        });
    }
    let body: Value = resp.json().unwrap_or(Value::Null);
    let login = pick(&body, &["login", "name"]);
    // A failure here only costs the organisation name.
    let org = client
        .get(format!("{base}/api/org"))
        .bearer_auth(secret)
        .send()
        .ok()
        .filter(|r| r.status().is_success())
        .and_then(|r| r.json::<Value>().ok())
        .and_then(|v| pick(&v, &["name"]));

    let mut proposals = Vec::new();
    let mut push = |field: &str, value: Value, reason: String| {
        if force || is_blank(entry, field) {
            proposals.push(Proposal {
                field: field.to_string(),
                value,
                reason,
            });
        }
    };
    if let Some(l) = &login {
        push(
            "account_name",
            json!(l),
            format!("Grafana says this token belongs to {l}"),
        );
    }
    push(
        "api_description",
        json!(format!(
            "Grafana service account token{} - verified {}",
            org.as_deref()
                .map(|o| format!(" for {o}"))
                .unwrap_or_default(),
            vault_core::iso_now().chars().take(10).collect::<String>()
        )),
        format!("confirmed live against {}", host_of(base)),
    );
    Some(Live {
        issuer,
        status: "ok",
        detail: login.unwrap_or_else(|| "accepted".into()),
        proposals,
    })
}

pub fn probe_entry(entry: &Value, timeout_secs: u64, force: bool) -> Option<Live> {
    let secret = entry.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
    if let Some(base) = grafana_base(entry) {
        return probe_grafana(entry, &base, secret, timeout_secs, force);
    }
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

        // **A session cookie is never probed** (Phase 23, E11).
        //
        // `--online` exists to ask an *issuer* about its own credential, which
        // is a defensible thing to do with an API key. Replaying a session
        // cookie from a desktop app is a different act with different risk: it
        // is indistinguishable, at the far end, from the session hijack the
        // cookie exists to prevent, and it can trip fraud detection on an
        // account the user still needs.
        //
        // Skipped with a **named reason** rather than silently, so the report's
        // counts add up and nobody discovers six months later that a whole class
        // of entry was never touched.
        //
        // (The signature table is matched with `starts_with`, never a substring,
        // so an `sk-…` embedded inside a jar could not misfire even if this
        // check were removed — see `plan_entry`. Both halves of E11, and the
        // second one holds for every type.)
        if opts.online && data::secret_type_of(entry) == "cookie" {
            live_rows.push(json!({
                "provider": plan.provider,
                "issuer": "",
                "status": "skipped",
                "detail": "a session cookie is not sent anywhere by enrich —                            replaying one is a different act from asking an issuer about a key",
            }));
        } else if opts.online {
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

#[cfg(test)]
mod axis_tests {
    use super::*;
    use serde_json::json;

    fn field_of<'a>(plan: &'a EntryPlan, field: &str) -> Option<&'a Value> {
        plan.proposals
            .iter()
            .find(|p| p.field == field)
            .map(|p| &p.value)
    }

    #[test]
    fn a_classic_github_pat_is_a_user_token() {
        let entry = json!({ "provider": "X", "api_key": "ghp_abcdef" });
        let plan = plan_entry(&entry, false);
        assert_eq!(field_of(&plan, "acts_as"), Some(&json!("user")));
        assert_eq!(field_of(&plan, "issuer_kind"), Some(&json!("saas")));
    }

    #[test]
    fn a_github_app_installation_token_is_not_a_user_token() {
        let entry = json!({ "provider": "X", "api_key": "ghs_abcdef" });
        let plan = plan_entry(&entry, false);
        assert_eq!(field_of(&plan, "acts_as"), Some(&json!("installation")));
    }

    #[test]
    fn a_github_refresh_token_is_classified_as_oauth_client_not_api_key() {
        let entry = json!({ "provider": "X", "api_key": "ghr_abcdef" });
        let plan = plan_entry(&entry, false);
        assert_eq!(field_of(&plan, "secretType"), Some(&json!("oauth_client")));
    }

    #[test]
    fn an_openai_service_account_key_is_not_shadowed_by_the_bare_sk_dash_prefix() {
        // sk-svcacct- and sk-admin- both start with "sk-", which also matches
        // the generic OpenAI fallback earlier in SIGNATURES. Regression test
        // for exactly that shadowing bug.
        let entry = json!({ "provider": "X", "api_key": "sk-svcacct-abcdef" });
        let plan = plan_entry(&entry, false);
        assert_eq!(field_of(&plan, "acts_as"), Some(&json!("service")));

        let admin = json!({ "provider": "X", "api_key": "sk-admin-abcdef" });
        let plan = plan_entry(&admin, false);
        assert_eq!(field_of(&plan, "acts_as"), Some(&json!("admin")));
    }

    #[test]
    fn a_stripe_publishable_key_is_marked_publishable_not_server_only() {
        let entry = json!({ "provider": "X", "api_key": "pk_live_abcdef" });
        let plan = plan_entry(&entry, false);
        assert_eq!(field_of(&plan, "exposure"), Some(&json!("publishable")));
    }

    #[test]
    fn a_stripe_webhook_secret_is_verify_only() {
        let entry = json!({ "provider": "X", "api_key": "whsec_abcdef" });
        let plan = plan_entry(&entry, false);
        assert_eq!(field_of(&plan, "exposure"), Some(&json!("verify_only")));
    }

    #[test]
    fn a_slack_xoxc_value_is_recognised_as_a_web_session_not_an_api_key() {
        let entry = json!({ "provider": "X", "api_key": "xoxc-abcdef" });
        let plan = plan_entry(&entry, false);
        assert_eq!(field_of(&plan, "secretType"), Some(&json!("cookie")));
    }

    #[test]
    fn axes_are_suggestions_only_and_never_touch_the_public_flag() {
        let entry = json!({ "provider": "X", "api_key": "pk_live_abcdef" });
        let plan = plan_entry(&entry, false);
        assert!(
            plan.proposals.iter().all(|p| p.field != "primary_public"),
            "exposure must never propose setting primary_public itself"
        );
    }

    fn grafana_entry(url: &str) -> Value {
        json!({ "provider": "Grafana", "api_key": "glsa_exampleexampleexample", "api_url": url })
    }

    #[test]
    fn a_grafana_token_is_only_sent_to_a_host_it_is_safe_to_send_it_to() {
        // https anywhere; http only to names the public internet cannot reach.
        for ok in [
            "https://grafana.example.com",
            "https://grafana.example.com/grafana/",
            "http://grafana:3000",
            "http://127.0.0.1:3000",
            "http://192.168.1.5:3000",
            "http://grafana.lan",
            "http://[::1]:3000",
        ] {
            assert!(grafana_base(&grafana_entry(ok)).is_some(), "{ok}");
        }
        for bad in [
            "http://grafana.example.com",
            "http://8.8.8.8",
            "https://user:pw@grafana.example.com",
            "https://grafana.example.com/?next=1",
            "ftp://grafana",
            "not a url",
            "",
        ] {
            assert!(grafana_base(&grafana_entry(bad)).is_none(), "{bad}");
        }
        // Only a service-account token, never a cookie, never another prefix.
        let mut e = grafana_entry("https://g.example.com");
        e["api_key"] = json!("ghp_notgrafana");
        assert!(grafana_base(&e).is_none());
        let mut e = grafana_entry("https://g.example.com");
        e["secretType"] = json!("cookie");
        assert!(grafana_base(&e).is_none());
        // The consent screen names the host.
        assert_eq!(
            issuer_for(&grafana_entry("http://grafana:3000/")).as_deref(),
            Some("Grafana at grafana:3000")
        );
    }

    /// A Grafana that answers the two calls the probe makes and records the
    /// `Authorization` header it was sent.
    fn fake_grafana(user_status: u16) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut c, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let n = c.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let auth = req
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("authorization:"))
                    .unwrap_or("")
                    .to_string();
                let _ = tx.send(format!("{} | {auth}", req.lines().next().unwrap_or("")));
                let (status, body) = if req.contains("GET /api/org") {
                    (200, r#"{"id":1,"name":"Main Org."}"#)
                } else if user_status == 200 {
                    (
                        200,
                        r#"{"login":"sa-ci","name":"ci","isServiceAccount":true}"#,
                    )
                } else {
                    (user_status, r#"{"message":"Unauthorized"}"#)
                };
                let _ = write!(
                    c,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (format!("http://127.0.0.1:{port}"), rx)
    }

    #[test]
    fn the_grafana_probe_reads_identity_and_org_and_sends_the_token_as_a_bearer() {
        let (url, rx) = fake_grafana(200);
        let live = probe_entry(&grafana_entry(&url), 5, false).unwrap();
        assert_eq!(live.status, "ok");
        assert_eq!(live.detail, "sa-ci");
        let find = |f: &str| {
            live.proposals
                .iter()
                .find(|p| p.field == f)
                .map(|p| p.value.clone())
        };
        assert_eq!(find("account_name"), Some(json!("sa-ci")));
        assert!(find("api_description")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("for Main Org."));
        let first = rx.recv().unwrap();
        assert!(first.starts_with("GET /api/user "), "{first}");
        assert!(
            first
                .to_lowercase()
                .contains("bearer glsa_exampleexampleexample"),
            "{first}"
        );
    }

    #[test]
    fn a_grafana_that_refuses_the_token_is_reported_rejected() {
        let (url, _rx) = fake_grafana(401);
        let live = probe_entry(&grafana_entry(&url), 5, false).unwrap();
        assert_eq!(live.status, "rejected");
        assert!(live.proposals.is_empty());
    }
}
