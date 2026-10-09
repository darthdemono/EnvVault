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
P = "ghp" + "_"          # assembled so no file in the repo matches a scanner
SK = "s" + "k-"
entry("GitHub", key(P, 36), account="ci-bot", env="production", tags="ci,deploy",
      categories="dev/source", rotation_days=90, desc="Deploys and package publishing",
      totp=b32(), projects="media-stack")
entry("OpenAI", key(SK + "proj-", 48), account="platform", key_id="primary", env="production", price="paid",
      tags="llm", categories="ai", rate_limit="500/min", desc="Production chat completions")
entry("OpenAI", key(SK + "proj-", 48), account="platform", key_id="backup", env="production", price="paid",
      tags="llm", categories="ai", rate_limit="500/min")
entry("Anthropic", key(SK + "ant-api03-", 52), account="research", env="production", price="paid",
      tags="llm", categories="ai", expires=days(21))
entry("Stripe", key("rk" + "_test_", 40), account="payments", env="staging", price="paid",
      tags="billing,pci", categories="payments", desc="Restricted key: charges and refunds only", rotation_days=60)
entry("AWS", key("AK" + "IA", 16).upper(), account="deploy-prod", env="production",
      secret=rnd(40), tags="infra,critical", categories="cloud/aws", rotation_days=90, totp=b32(),
      desc="IAM user for the deploy pipeline")
entry("Cloudflare", rnd(40), account="dns-edit", env="production", tags="dns,edge",
      categories="cloud", projects="edge-proxy", totp=b32())
entry("Vercel", rnd(24), account="web", env="production", tags="web", categories="cloud")
entry("Sentry", key("sn" + "tryu_", 64).lower(), account="errors", env="production", tags="observability",
      categories="observability")
entry("Datadog", rnd(32).lower(), account="metrics", env="production", tags="observability",
      categories="observability", expires=days(9))
entry("SendGrid", key("S" + "G.", 22) + "." + rnd(43), account="mail", env="production", tags="email",
      categories="comms")
entry("Twilio", rnd(32).lower(), account="sms", env="production", price="paid", tags="sms",
      categories="comms", key_id="AC" + rnd(32).lower())
entry("Slack", key("xo" + "xb-", 40), account="alerts-bot", env="production", tags="chat,alerts",
      categories="comms")
entry("Discord", rnd(24) + "." + rnd(6) + "." + rnd(27), account="release-bot", env="production",
      tags="chat", categories="comms")
entry("Spotify", rnd(32).lower(), account="playlist-sync", secret=rnd(32).lower(), env="development",
      tags="music", categories="personal")
entry("Notion", key("nt" + "n_", 44), account="wiki", env="production", tags="docs", categories="productivity")
entry("Linear", key("lin" + "_api_", 40), account="eng", env="production", tags="tracker", categories="productivity")
entry("Supabase", rnd(40), account="app-db", env="production", tags="db", categories="cloud")
entry("Mapbox", key("p" + "k.", 60), account="maps", env="production", price="free", tags="maps",
      categories="dev/apis")
entry("Grafana", key("gl" + "sa_", 32), account="dashboards", env="production", tags="observability",
      categories="observability", url="https://grafana.example.com")

# ----- other kinds of secret ------------------------------------------------
entry("Proxmox", rnd(24, ALNUM + "!#%&*"), type="password", account="root", env="production",
      tags="homelab", categories="homelab", projects="home-vpn")
entry("Fastmail", rnd(20, ALNUM + "!#%&*"), type="password", account="me@example.com", tags="email",
      categories="personal", totp=b32())
entry("Postgres", f"postgres://app:{rnd(20)}@db.internal:5432/app", type="connection_string",
      account="app", env="production", tags="db", categories="cloud", projects="media-stack")
entry("Backup Passphrase", "", type="env_var", env="production", tags="backup", categories="homelab",
      var=[f"!RESTIC_PASSWORD={rnd(32)}", "RESTIC_REPOSITORY=s3:s3.example.com/backups"])
entry("Deploy Key", "", type="ssh_key", account="ci@example.com", tags="ci", categories="dev/source")
entry("Calendar Feed", "", type="composite", composite_kind="link",
      template="https://calendar.example.com/ical/{account}/{token}/basic.ics",
      var=["account=team@example.com", f"!token={rnd(40)}"], tags="calendar", categories="productivity")
entry("Dashboard Session", "", type="cookie", url="https://dashboard.example.com", tags="session",
      categories="dev/apis", user_agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0",
      var=[f"!session={rnd(48)}", f"!csrf={rnd(32)}"], expires=days(2))
run("gen", "cert", "example.com", "--days", "90", "--save-as", "Wildcard TLS Cert", check=False)
run("gen", "ssh", "--comment", "homelab", "--save-as", "Homelab SSH Key", check=False)

# ----- projects -------------------------------------------------------------
def chunk(p, name, *pairs):
    run("project", "chunk", "set", p, name, *pairs)

chunk("home-vpn", "Interface", "Address=10.10.0.1/24", "ListenPort=51820", "DNS=10.10.0.1",
      "PrivateKey=" + base64.b64encode(secrets.token_bytes(32)).decode())
chunk("home-vpn", "Peer", "PublicKey=" + base64.b64encode(secrets.token_bytes(32)).decode(), "AllowedIPs=10.10.0.2/32")
run("project", "chunk", "rename", "home-vpn", "Peer", "Laptop")
run("project", "chunk", "add", "home-vpn", "Phone", "--type", "wg_peer")
chunk("home-vpn", "Phone", "PublicKey=" + base64.b64encode(secrets.token_bytes(32)).decode(), "AllowedIPs=10.10.0.3/32")
chunk("media-stack", "service-1", "image=ghcr.io/example/app:2.4", "container_name=app", "restart=unless-stopped",
      "ports=8080:8080", "DATABASE_URL=${Postgres}")
run("project", "chunk", "rename", "media-stack", "service-1", "app")
chunk("edge-proxy", "HTTPS :443 main", "server_name=app.example.com", "listen=443 ssl http2")

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
