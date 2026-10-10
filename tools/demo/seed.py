#!/usr/bin/env python3
"""Fill a throwaway unv-server with a demo vault: fake providers, every kind of
secret, three projects, users, classes and permission expressions.

Every value is generated here, at run time, from random bytes. Nothing in this
file is a credential, and nothing that looks like one is committed (issuer
prefixes are assembled from parts so a secret scanner has nothing to match).

    UNV_SERVER_URL=http://localhost:18743 UNV_PASSWORD=... tools/demo/seed.py [path/to/unv]
"""
import base64, os, secrets, string, subprocess, sys, datetime as dt

UNV = sys.argv[1] if len(sys.argv) > 1 else "unv"
ALNUM = string.ascii_letters + string.digits


def run(*args, stdin=None, check=True):
    r = subprocess.run([UNV, *args], input=stdin, capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f"unv {' '.join(args[:3])} failed: {r.stderr.strip() or r.stdout.strip()}")
    return r


def rnd(n, alphabet=ALNUM):
    return "".join(secrets.choice(alphabet) for _ in range(n))


def key(prefix, n):
    return prefix + rnd(n)


def days(n):
    return (dt.date.today() + dt.timedelta(days=n)).isoformat()


def b32():
    return base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")


def entry(provider, value, **kw):
    a = ["entry", "add", provider, "--key-stdin"]
    for flag, v in kw.items():
        flag = "--" + flag.replace("_", "-")
        if v is True:
            a.append(flag)
        elif isinstance(v, list):
            for item in v:
                a += [flag, item]
        elif v is not None:
            a += [flag, str(v)]
    run(*a, stdin=value)


# ----- projects first, so entries can join them ---------------------------
for name, ptype in [('Home VPN','wireguard'),('Media Stack','docker'),('Edge Proxy','nginx')]:
    run('project', 'add', name, '--type', ptype)

for cat in ['ai','cloud','cloud/aws','comms','dev','dev/source','dev/apis','homelab','observability','payments','personal','productivity']:
    run('category', 'add', cat)

# ----- API keys from the providers people actually use ----------------------
# Every card carries the metadata a real vault accumulates (description, account,
# environment, tags, categories, URL, version, scopes, limits, rotation), shaped
# after which fields a lived-in vault actually fills, so the screenshots show a
# board that looks used. All names, hosts and values are invented.
P = "ghp" + "_"          # assembled so no file in the repo matches a scanner
SK = "s" + "k-"
entry("GitHub", key(P, 36), account="ci-bot", env="production", tags="ci,deploy,automation",
      categories="dev/source", rotation_days=90, desc="Deploys and package publishing",
      details="Fine-grained token for the release workflow. Scoped to two repositories.",
      url="https://api.github.com", version="2022-11-28", scopes="repo,packages:write,workflow",
      rate_limit_count=5000, rate_limit_period="hour", totp=b32(), projects="media-stack")
entry("OpenAI", key(SK + "proj-", 48), account="platform", key_id="primary", env="production", price="paid",
      tags="llm,chat", categories="ai", rate_limit="500/min", desc="Production chat completions",
      details="Primary key for the chat service. Billing alerts are set at 80% of the monthly cap.",
      url="https://api.openai.com/v1", version="v1", env_prefixes="OPENAI")
entry("OpenAI", key(SK + "proj-", 48), account="platform", key_id="backup", env="production", price="paid",
      tags="llm,chat", categories="ai", rate_limit="500/min", desc="Failover key for the same project",
      url="https://api.openai.com/v1", version="v1", env_prefixes="OPENAI")
entry("Anthropic", key(SK + "ant-api03-", 52), account="research", env="production", price="paid",
      tags="llm,research", categories="ai", expires=days(21), desc="Evaluation runs and notebooks",
      url="https://api.anthropic.com", version="2023-06-01", rate_limit="50/min", env_prefixes="ANTHROPIC")
entry("Stripe", key("rk" + "_test_", 40), account="payments", env="staging", price="paid",
      tags="billing,pci", categories="payments", desc="Restricted key: charges and refunds only",
      rotation_days=60, url="https://api.stripe.com", version="2024-06-20",
      scopes="charges:write,refunds:write", callback_url="https://pay.example.com/webhooks/stripe")
entry("AWS", key("AK" + "IA", 16).upper(), account="deploy-prod", env="production",
      secret=rnd(40), tags="infra,critical", categories="cloud/aws", rotation_days=90, totp=b32(),
      desc="IAM user for the deploy pipeline", details="Can assume the deploy role in the production account only.",
      url="https://sts.eu-west-1.amazonaws.com", version="2011-06-15", env_prefixes="AWS")
entry("Cloudflare", rnd(40), account="dns-edit", env="production", tags="dns,edge,tls",
      categories="cloud", projects="edge-proxy", totp=b32(), desc="Zone-scoped token for DNS and certificates",
      url="https://api.cloudflare.com/client/v4", version="v4", scopes="zone:dns:edit,zone:read",
      rate_limit_count=240, rate_limit_period="minute")
entry("Vercel", rnd(24), account="web", env="production", tags="web,frontend", categories="cloud",
      desc="Deploys the marketing site", url="https://api.vercel.com", version="v13", rotation_days=120)
entry("Sentry", key("sn" + "tryu_", 64).lower(), account="errors", env="production",
      tags="observability,errors", categories="observability", desc="Error reporting for every service",
      url="https://sentry.io/api/0", version="0", scopes="project:read,event:write")
entry("Datadog", rnd(32).lower(), account="metrics", env="production", tags="observability,metrics",
      categories="observability", expires=days(9), desc="Agent key for the metrics pipeline",
      url="https://api.datadoghq.eu", version="v2", rate_limit="300/hour")
entry("SendGrid", key("S" + "G.", 22) + "." + rnd(43), account="mail", env="production", tags="email,transactional",
      categories="comms", desc="Transactional mail from the app", url="https://api.sendgrid.com/v3",
      version="v3", scopes="mail.send", rate_limit="600/min", callback_url="https://app.example.com/hooks/mail")
entry("Twilio", rnd(32).lower(), account="sms", env="production", price="paid", tags="sms,alerts",
      categories="comms", key_id="AC" + rnd(32).lower(), desc="Pager SMS for the on-call rota",
      url="https://api.twilio.com/2010-04-01", version="2010-04-01")
entry("Slack", key("xo" + "xb-", 40), account="alerts-bot", env="production", tags="chat,alerts",
      categories="comms", desc="Posts deploy and alert messages", url="https://slack.com/api",
      scopes="chat:write,channels:read", callback_url="https://app.example.com/slack/oauth")
entry("Discord", rnd(24) + "." + rnd(6) + "." + rnd(27), account="release-bot", env="production",
      tags="chat,bot", categories="comms", desc="Announces releases in the community server",
      url="https://discord.com/api/v10", version="v10", scopes="bot,applications.commands")
entry("Spotify", rnd(32).lower(), account="playlist-sync", secret=rnd(32).lower(), env="development",
      tags="music,oauth", categories="personal", desc="Playlist sync script",
      url="https://api.spotify.com/v1", version="v1", scopes="playlist-modify-private",
      callback_url="http://127.0.0.1:8888/callback")
entry("Notion", key("nt" + "n_", 44), account="wiki", env="production", tags="docs,wiki",
      categories="productivity", desc="Syncs the runbook database", url="https://api.notion.com/v1",
      version="2022-06-28")
entry("Linear", key("lin" + "_api_", 40), account="eng", env="production", tags="tracker,engineering",
      categories="productivity", desc="Creates issues from alerts", url="https://api.linear.app/graphql")
entry("Supabase", rnd(40), account="app-db", env="production", tags="db,backend", categories="cloud",
      desc="Service role key for the app database", url="https://abcd1234.supabase.co", version="v1",
      rotation_days=90)
entry("Mapbox", key("p" + "k.", 60), account="maps", env="production", price="free", tags="maps,geo",
      categories="dev/apis", desc="Public token for the store locator", url="https://api.mapbox.com",
      version="v5", rate_limit="600/min")
entry("Grafana", key("gl" + "sa_", 32), account="dashboards", env="production", tags="observability,dashboards",
      categories="observability", url="https://grafana.example.com", desc="Service account for provisioning",
      version="10.4", scopes="dashboards:write,datasources:read")
entry("TMDB v3", rnd(32).lower(), account="media", env="production", tags="media,metadata", categories="dev/apis",
      desc="Poster and metadata lookups", url="https://api.themoviedb.org/3", version="3", rate_limit="40/sec")
entry("TMDB v4", key("ey" + "J", 120), account="media", env="production", tags="media,metadata",
      categories="dev/apis", desc="Read access token for the newer API", url="https://api.themoviedb.org/4",
      version="4")

# ----- other kinds of secret ------------------------------------------------
entry("Proxmox", rnd(24, ALNUM + "!#%&*"), type="password", account="root", env="production",
      tags="homelab,hypervisor", categories="homelab", projects="home-vpn", desc="Root login for the hypervisor",
      url="https://pve.lan:8006", rotation_days=180)
entry("Fastmail", rnd(20, ALNUM + "!#%&*"), type="password", account="me@example.com", tags="email,personal",
      categories="personal", totp=b32(), desc="Main mailbox", url="https://app.fastmail.com")
entry("Postgres", f"postgres://app:{rnd(20)}@db.internal:5432/app", type="connection_string",
      account="app", env="production", tags="db,primary", categories="cloud", projects="media-stack",
      desc="Application database", details="Primary instance. Read replicas use a separate role.",
      version="16", rotation_days=90)
entry("Backup Passphrase", "", type="env_var", env="production", tags="backup,restic", categories="homelab",
      desc="Restic repository for nightly backups",
      var=[f"!RESTIC_PASSWORD={rnd(32)}", "RESTIC_REPOSITORY=s3:s3.example.com/backups"])
entry("Deploy Key", "", type="ssh_key", account="ci@example.com", tags="ci,git", categories="dev/source",
      desc="Read-only key for pulling private repositories")
entry("Calendar Feed", "", type="composite", composite_kind="link",
      template="https://calendar.example.com/ical/{account}/{token}/basic.ics",
      var=["account=team@example.com", f"!token={rnd(40)}"], tags="calendar,feed", categories="productivity",
      desc="Team calendar, subscribed in the phone")
entry("Dashboard Session", "", type="cookie", url="https://dashboard.example.com", tags="session,web",
      categories="dev/apis", user_agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0",
      var=[f"!session={rnd(48)}", f"!csrf={rnd(32)}"], expires=days(2), desc="Browser session for the admin dashboard")
run("gen", "cert", "example.com", "--days", "90", "--save-as", "Wildcard TLS Cert", check=False)
run("gen", "ssh", "--comment", "homelab", "--save-as", "Homelab SSH Key", check=False)
for name, d, t, c in [("Wildcard TLS Cert", "Certificate for *.example.com, renewed every 90 days", "tls,edge", "cloud"),
                      ("Homelab SSH Key", "Login key for the lab machines", "ssh,homelab", "homelab")]:
    run("entry", "set", name, "--desc", d, "--tags", t, "--categories", c, "--env", "production", check=False)

entry("Wireguard", base64.b64encode(secrets.token_bytes(32)).decode(), account="home-vpn", env="production",
      tags="vpn,homelab", categories="homelab", projects="home-vpn", desc="Interface key for the home VPN",
      rotation_days=365)

# ----- bundles: entries that belong on one card ------------------------------
run("bundle", "new", "TMDB", "--member", "v3=TMDB v3", "--member", "v4=TMDB v4", check=False)

# ----- projects -------------------------------------------------------------
def chunk(p, name, *pairs):
    run("project", "chunk", "set", p, name, *pairs)

chunk("home-vpn", "Interface", "Address=10.10.0.1/24", "ListenPort=51820", "DNS=10.10.0.1",
      "PrivateKey=${Wireguard}")
chunk("home-vpn", "Peer", "PublicKey=" + base64.b64encode(secrets.token_bytes(32)).decode(), "AllowedIPs=10.10.0.2/32")
run("project", "chunk", "rename", "home-vpn", "Peer", "Laptop")
run("project", "chunk", "add", "home-vpn", "Phone", "--type", "wg_peer")
chunk("home-vpn", "Phone", "PublicKey=" + base64.b64encode(secrets.token_bytes(32)).decode(), "AllowedIPs=10.10.0.3/32")
chunk("media-stack", "service-1", "image=ghcr.io/example/app:2.4", "container_name=app", "restart=unless-stopped",
      "ports=8080:8080", "DATABASE_URL=${Postgres}")
run("project", "chunk", "rename", "media-stack", "service-1", "app")
chunk("edge-proxy", "HTTPS :443 main", "server_name=app.example.com", "listen=443 ssl http2")

# ----- config history: two snapshots with a rotated secret between them ------
# The Home VPN interface reads ${Wireguard}; rotating that entry changes the
# rendered WireGuard file, which is what the Config history screenshot diffs.
# (A Compose chunk keeps ${VAR} for Compose to expand, so it would show nothing.)
run("history", "snapshot")
run("entry", "set", "Wireguard", "--key-stdin", stdin=base64.b64encode(secrets.token_bytes(32)).decode())
run("history", "snapshot")

# ----- users, classes, permissions (RBAC) ------------------------------------
run("class", "add", "Developers", "--desc", "Read AI and source keys; write nothing")
run("class", "add", "Operators", "--desc", "Own infrastructure projects", "--manage-users")
run("perm", "set", "class", "Developers", "--read", "category:ai OR category:dev*")
run("perm", "set", "class", "Operators", "--read", "category:cloud* OR category:homelab OR project:*",
    "--write", "project:media-stack OR project:edge-proxy")
for user, cls, read, write in [
    ("alice", "Developers", "tag:llm OR tag:ci", ""),
    ("bob", "Operators", "category:cloud* OR project:*", "project:media-stack"),
    ("ci-bot", None, "project:media-stack", ""),
]:
    run("user", "add", user, "--user-password", "demo-" + user + "-pw-123")
    if cls:
        run("user", "class", user, cls)
    run("perm", "set", "user", user, "--read", read, *(["--write", write] if write else []))
print("demo vault seeded")
