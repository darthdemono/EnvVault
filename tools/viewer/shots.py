#!/usr/bin/env python3
"""Drive the real desktop app on a virtual display and screenshot it (Phase 40).

Runs inside the `unv-viewer` image (see ./Dockerfile). Starts Xvfb, then
`tauri-driver`, which fronts WebKitWebDriver, and talks W3C WebDriver to the
actual Tauri window: the real WebKitGTK engine, the real IPC bridge, a real
SQLCipher vault in a throwaway home directory. Nothing is mocked and nothing
touches the host.

    python3 shots.py APP_BINARY OUT_DIR [scenario ...]

With no scenario names every scenario runs. Besides the PNGs it writes
`report.json`: per scenario, any JavaScript error the page logged, so a run is a
check as well as a picture.
"""

import base64
import http.client
import json
import os
import shutil
import signal
import subprocess
import sys
import time

APP, OUT = sys.argv[1], sys.argv[2]
WANT = set(sys.argv[3:])
PASSWORD = "correct-horse-battery-staple"
HOME = "/tmp/unv-home"


class WD:
    """Just enough of the W3C WebDriver protocol, over http.client."""

    def __init__(self, port=4444):
        self.port = port
        self.sid = None

    def call(self, method, path, body=None, timeout=60):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        payload = json.dumps(body if body is not None else {}) if method == "POST" else None
        c.request(method, path, payload, {"Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read()
        try:
            v = json.loads(data)
        except ValueError:
            raise RuntimeError(f"{method} {path}: {r.status} {data[:200]!r}")
        if r.status >= 400 or (isinstance(v.get("value"), dict) and "error" in v["value"]):
            raise RuntimeError(f"{method} {path}: {json.dumps(v)[:300]}")
        return v.get("value")

    def start(self):
        v = self.call(
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {
                        "browserName": "wry",
                        "tauri:options": {"application": APP},
                    }
                }
            },
            timeout=120,
        )
        self.sid = v["sessionId"]

    def s(self, path):
        return f"/session/{self.sid}{path}"

    def size(self, w, h):
        self.call("POST", self.s("/window/rect"), {"x": 0, "y": 0, "width": w, "height": h})

    def find(self, css, timeout=10):
        end = time.time() + timeout
        last = None
        while time.time() < end:
            try:
                el = self.call("POST", self.s("/element"), {"using": "css selector", "value": css})
                return list(el.values())[0]
            except RuntimeError as e:
                last = e
                time.sleep(0.2)
        raise RuntimeError(f"no element {css!r}: {last}")

    def exists(self, css):
        els = self.call("POST", self.s("/elements"), {"using": "css selector", "value": css})
        return bool(els)

    def click(self, css):
        self.call("POST", self.s(f"/element/{self.find(css)}/click"))

    def type(self, css, text):
        el = self.find(css)
        self.call("POST", self.s(f"/element/{el}/clear"))
        self.call("POST", self.s(f"/element/{el}/value"), {"text": text})

    def js(self, script, args=None):
        return self.call("POST", self.s("/execute/sync"), {"script": script, "args": args or []})

    def js_async(self, script, args=None):
        return self.call("POST", self.s("/execute/async"), {"script": script, "args": args or []}, timeout=120)

    def shot(self, path):
        # WebDriver's own screenshot hangs under software compositing, so grab
        # the virtual display itself: the window fills it.
        subprocess.run(["import", "-window", "root", "-crop", os.environ.get("SHOT_CROP", "1440x900") + "+0+0", "+repage", path], check=True, env=dict(os.environ, DISPLAY=":99"))

    def stop(self):
        if self.sid:
            try:
                self.call("DELETE", f"/session/{self.sid}")
            except Exception:
                pass


def wait_for(cond, secs=20, what="condition"):  # noqa
    end = time.time() + secs
    while time.time() < end:
        try:
            if cond():
                return
        except RuntimeError:
            pass
        time.sleep(0.3)
    subprocess.run(["import", "-window", "root", f"{OUT}/_timeout.png"], env=dict(os.environ, DISPLAY=":99"))
    raise RuntimeError(f"timed out waiting for {what}")


def main():
    os.makedirs(OUT, exist_ok=True)
    shutil.rmtree(HOME, ignore_errors=True)
    for d in ("data", "config", "state", "cache"):
        os.makedirs(f"{HOME}/{d}")
    env = dict(
        os.environ,
        HOME=HOME,
        XDG_DATA_HOME=f"{HOME}/data",
        XDG_CONFIG_HOME=f"{HOME}/config",
        XDG_STATE_HOME=f"{HOME}/state",
        XDG_CACHE_HOME=f"{HOME}/cache",
        DISPLAY=":99",
    )
    xvfb = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1600x1000x24", "-nolisten", "tcp"], env=env)
    time.sleep(1.5)
    driver = subprocess.Popen(["tauri-driver", "--port", "4444", "--native-driver", "/usr/bin/WebKitWebDriver"], env=env)
    time.sleep(1.5)
    wd = WD()
    report = {}
    try:
        wd.start()
        wd.size(1440, 900)
        wait_for(lambda: wd.exists("#unlock-overlay"), 30, "the unlock screen")
        time.sleep(1.0)

        # A page error is a failed screenshot: collect them from here on.
        def collect():
          wd.js(
            "window.__shotErrors = [];"
            "window.addEventListener('error', e => window.__shotErrors.push(String(e.message)));"
            "window.addEventListener('unhandledrejection', e => window.__shotErrors.push('rejection: ' + String(e.reason)));"
          )

        collect()

        def snap(name):
            wd.shot(f"{OUT}/{name}.png")
            errs = wd.js("return window.__shotErrors.splice(0)")
            report[name] = {"errors": errs}
            print(f"  {name}{'  ERRORS: ' + '; '.join(errs) if errs else ''}", flush=True)

        # First run: the create-vault screen.
        if not WANT or "unlock-first-run" in WANT:
            snap("unlock-first-run")

        wd.type("#unlock-password", PASSWORD)
        try:  # only the first run asks twice
            if wd.js("return getComputedStyle(document.getElementById('unlock-confirm-group')).display !== 'none'"):
                wd.type("#unlock-confirm", PASSWORD)
        except RuntimeError:
            pass
        if not WANT or "unlock-filled" in WANT:
            snap("unlock-filled")
        wd.click("#unlock-submit-btn")
        wait_for(lambda: wd.js("return !!document.querySelector('#card-grid')") and not wd.js(
            "return document.getElementById('unlock-overlay').classList.contains('open')"), 40, "the vault to open")
        time.sleep(1.0)
        if not WANT or "onboarding" in WANT:
            snap("onboarding")

        # Skip the wizard and seed the vault the way the UI lab does.
        wd.js("localStorage.setItem('unenverse-settings', JSON.stringify({onboardingCompleted: true, panelOrder: ['secrets','tools','remote','users','auth']}))")
        seed = json.load(open("/out/seed.json"))
        res = wd.js_async(
            "const done = arguments[arguments.length - 1];"
            "window.__TAURI__.core.invoke('save_vault', {data: arguments[0], expectVersion: null})"
            ".then(() => done('ok'), e => done('err: ' + e));",
            [seed],
        )
        print(f"  seed: {res}", flush=True)
        wd.js("location.reload()")
        wait_for(lambda: wd.js("return !!document.querySelector('.card')") or wd.exists("#unlock-overlay.open"), 40, "the seeded grid")
        if wd.exists("#unlock-overlay.open"):
            time.sleep(1.0)
            wd.js(
                "const f = document.getElementById('unlock-password'); f.value = arguments[0];"
                "f.dispatchEvent(new Event('input', {bubbles: true}));"
                "document.getElementById('unlock-submit-btn').click();",
                [PASSWORD],
            )
            wait_for(lambda: wd.js("return !!document.querySelector('.card')"), 40, "the grid after unlock")
        time.sleep(1.0)
        collect()  # the reload above dropped the listeners

        def scenario(name, fn):
            if WANT and name not in WANT:
                return
            try:
                # Whatever the previous scenario left open.
                wd.js("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape', bubbles: true}))")
                time.sleep(0.2)
                fn()
            except RuntimeError as e:
                report[name] = {"errors": [f"scenario failed: {e}"]}
                print(f"  {name}  FAILED: {e}", flush=True)
                return
            time.sleep(0.4)
            snap(name)

        def panel(p):
            wd.click(f'#activity-bar [data-panel="{p}"]')

        def tool(t):
            panel("tools")
            wd.click(f'[data-tool="{t}"]')

        scenario("secrets-grid", lambda: None)
        scenario("secrets-expanded", lambda: wd.click(".card"))
        scenario("tools-secret-gen", lambda: tool("secret-gen"))
        scenario("tools-health", lambda: (tool("health"), wd.click("#health-scan-btn")))
        scenario("tools-nodes", lambda: tool("nodes"))
        scenario("tools-history", lambda: tool("history"))
        scenario("tools-import-export", lambda: tool("import-export"))
        scenario("panel-auth", lambda: panel("auth"))
        scenario("panel-remote", lambda: panel("remote"))
        scenario("modal-add-entry", lambda: (panel("secrets"), wd.click("#add-btn")))

        def settings(tab):
            def go():
                wd.click("#settings-btn")
                time.sleep(0.4)
                wd.click(f'.settings-tab[data-stab="{tab}"]')
            return go

        for tab in ("appearance", "layout", "security", "data", "advanced"):
            scenario(f"settings-{tab}", settings(tab))
    finally:
        wd.stop()
        for p in (driver, xvfb):
            p.send_signal(signal.SIGTERM)
        with open(f"{OUT}/report.json", "w") as f:
            json.dump(report, f, indent=2)
    bad = {k: v for k, v in report.items() if v["errors"]}
    print(f"{len(report)} screens, {len(bad)} with page errors")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
