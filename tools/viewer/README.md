# Viewer

Screenshots of the real desktop app: its actual WebKitGTK window, driven by WebDriver on a virtual display inside Docker. See ADR-0150.

    tools/viewer/run.sh                     # all scenarios, PNGs in shots/native
    tools/viewer/run.sh panel-auth          # only some, by name
    OUT=/some/dir tools/viewer/run.sh

The first run builds the image (a few minutes) and compiles the app in a named volume (about six minutes); later runs reuse both. `shots/` is gitignored. `report.json` lists any JavaScript error the page logged per screen, and the script exits 1 if there is one.

Scenarios live in `shots.py`. The vault is created through the real lock screen and then seeded with the same vault the UI lab uses, so the grid is not empty. Add a scenario with `scenario("name", lambda: ...)`.
