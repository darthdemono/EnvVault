#!/usr/bin/env python3
"""Screenshot the real app against the demo server (tools/demo/run.sh drives this).

Walks the login, the main grid, each kind of secret, the projects, the tools and
the multi-user screens, and writes numbered PNGs. Runs inside the viewer image.
"""
import os, signal, subprocess, sys, time

os.environ.setdefault("SHOT_CROP", "1920x1200")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "viewer"))
import shots  # noqa: E402
from shots import WD, wait_for  # noqa: E402

OUT = sys.argv[2] if len(sys.argv) > 2 else "/out"
SERVER = os.environ.get("DEMO_SERVER", "http://localhost:18743")
PASSWORD = os.environ.get("DEMO_PASSWORD", "demo-passphrase-123")


def click_text(wd, selector, text, exact=False):
    """Click the first element matching `selector` whose text contains `text`."""
    ok = wd.js(
        "const t = arguments[1].toLowerCase();"
        "const norm = e => e.textContent.replace(/\\s+/g, ' ').trim().toLowerCase();"
        "const has = arguments[2] ? (e => norm(e) === t) : (e => norm(e).includes(t));"
        "const el = [...document.querySelectorAll(arguments[0])].filter(has).find(e => ![...e.children].some(has));"
        "if (el) { el.click(); return true } return false",
        [selector, text.lower(), exact],
    )
    if not ok:
        found = wd.js(
            "const t = arguments[0].toLowerCase();"
            "return [...document.querySelectorAll('body *')].filter(e => e.textContent.toLowerCase().includes(t)"
            " && ![...e.children].some(c => c.textContent.toLowerCase().includes(t)))"
            ".slice(0, 4).map(e => e.tagName + '#' + e.id + '.' + e.className + ' < ' + (e.parentElement||{}).id)",
            [text])
        raise RuntimeError(f"nothing matches {selector} / {text}; elsewhere: {found}")


def main():
    os.makedirs(OUT, exist_ok=True)
    home = "/tmp/demo-home"
    subprocess.run(["rm", "-rf", home])
    for d in ("data", "config", "state", "cache"):
        os.makedirs(f"{home}/{d}")
    env = dict(os.environ, HOME=home, XDG_DATA_HOME=f"{home}/data", XDG_CONFIG_HOME=f"{home}/config",
               XDG_STATE_HOME=f"{home}/state", XDG_CACHE_HOME=f"{home}/cache", DISPLAY=":99")
    xvfb = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1920x1200x24", "-nolisten", "tcp"], env=env)
    time.sleep(1.5)
    driver = subprocess.Popen(["tauri-driver", "--port", "4444", "--native-driver", "/usr/bin/WebKitWebDriver"], env=env)
    time.sleep(1.5)
    wd = WD()
    shots.OUT = OUT
    try:
        wd.start()
        wd.size(1920, 1200)
        wait_for(lambda: wd.exists("#unlock-overlay"), 30, "the unlock screen")
        time.sleep(1.0)

        def snap(name):
            # Park the pointer in a corner so no native tooltip is on screen.
            wd.call("POST", wd.s("/actions"), {"actions": [{"type": "pointer", "id": "mouse",
                    "actions": [{"type": "pointerMove", "duration": 0, "origin": "viewport", "x": 1915, "y": 1195}]}]})
            time.sleep(0.7)
            wd.shot(f"{OUT}/{name}.png")
            print("  ", name, flush=True)

        # 1. Login: point the app at a server and sign in as its owner.
        wd.js("localStorage.setItem('unenverse-settings', JSON.stringify({onboardingCompleted: true,"
              " theme: 'dark', cardSize: 'compact', panelOrder: ['secrets','tools','remote','users','auth']}))")
        wd.js("location.reload()")
        wait_for(lambda: wd.exists("#unlock-overlay.open"), 30, "the unlock screen again")
        time.sleep(0.8)
        snap("login")
        wd.type("#unlock-server", SERVER)
        wd.type("#unlock-password", PASSWORD)
        snap("login-filled")
        wd.click("#unlock-submit-btn")
        wait_for(lambda: wd.js("return document.querySelectorAll('.card').length > 5"), 60, "the demo vault")
        time.sleep(1.5)
        try:  # the "bundle these?" suggestion is not part of the pitch
            click_text(wd, "button", "Not now")
        except RuntimeError:
            pass
        time.sleep(0.8)

        # 2. The hero shot: the whole window, a full grid.
        snap("unenverse")

        def go(name, fn, pause=0.6):
            try:
                wd.js("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape', bubbles: true}))")
                time.sleep(0.3)
                fn()
                time.sleep(pause)
            except RuntimeError as e:
                print("  FAILED", name, e, flush=True)
                return
            snap(name)

        def panel(p):
            wd.click(f'#activity-bar [data-panel="{p}"]')

        def tool(t):
            panel("tools")
            wd.click(f'[data-tool="{t}"]')

        go("card-expanded", lambda: wd.click(".card"))
        go("add-secret", lambda: (panel("secrets"), wd.click("#add-btn")))
        go("authenticator", lambda: panel("auth"), 1.5)
        for slug, label in (("project-wireguard", "Home VPN"), ("project-compose", "Media Stack"),
                            ("project-nginx", "Edge Proxy")):
            go(slug, lambda l=label: (panel("secrets"), click_text(wd, ".sidebar-label", l)), 1.0)
        go("health-scan", lambda: (tool("health"), wd.click("#health-scan-btn")), 1.2)
        go("generator", lambda: tool("secret-gen"))
        go("audit-log", lambda: tool("audit"))
        go("users-list", lambda: panel("users"), 1.5)
        go("user-permissions", lambda: (panel("users"), click_text(wd, "#users-panel *", "alice")), 1.5)
        go("classes", lambda: (panel("users"), click_text(wd, "#users-panel button", "Classes"),
                                  time.sleep(1.0), click_text(wd, "#users-panel *", "Operators")), 1.5)
        go("tools-nodes", lambda: tool("nodes"))
        go("config-history", lambda: tool("history"))
        go("settings", lambda: wd.click("#settings-btn"))

    finally:
        wd.stop()
        for p in (driver, xvfb):
            p.send_signal(signal.SIGTERM)


if __name__ == "__main__":
    main()
