"""Demo screenshots (synthetic data only). Runs in the demo app's network namespace, so it can reach nothing else:

  PW=$(docker exec m0nitor-demo-app-1 cat /run/demo/admin_password)
  docker run --rm --network container:m0nitor-demo-app-1 -e PW="$PW" -e FANOUT_ID=3 -v "$PWD":/w -w /w \\
    mcr.microsoft.com/playwright/python:v1.49.1-noble sh -c "pip install -q playwright==1.49.1 && python demo/screenshots.py"

Every image is a real page of the demo at 1440x900 (mobile: 390x844 @2x), written to docs/screenshots/.
"""
import os

from playwright.sync_api import sync_playwright

B, OUT = "http://localhost:8000", "docs/screenshots"
SHOTS = []


def login(ctx):
    pg = ctx.new_page()
    pg.goto(B + "/login")
    pg.fill("input[name=username]", "admin")
    pg.fill("input[name=password]", os.environ["PW"])
    pg.click("button.primary")
    pg.wait_for_load_state("networkidle")
    return pg


def save(pg, name):
    pg.screenshot(path=f"{OUT}/{name}.png")
    SHOTS.append(name)
    print("saved", name)


def shot(pg, url, name, wait=2500, sel=None):
    pg.goto(B + url)
    pg.wait_for_load_state("networkidle")
    if sel:
        pg.wait_for_selector(sel, timeout=60000)
    pg.wait_for_timeout(wait)
    save(pg, name)


def hover_arc(pg, sel="#map path.arc.in"):
    """Show the tooltip of the longest arc of one direction (source -> destination pairs)."""
    pg.evaluate("""sel => { const ps = [...document.querySelectorAll(sel)].sort((a, b) => b.getTotalLength() - a.getTotalLength());
        const p = ps[0], q = p.getPointAtLength(p.getTotalLength() * 0.6), m = p.getScreenCTM();
        p.dispatchEvent(new PointerEvent('pointermove', {clientX: q.x * m.a + m.e, clientY: q.y * m.d + m.f, bubbles: true})); }""", sel)
    pg.wait_for_timeout(500)


with sync_playwright() as p:
    b = p.chromium.launch()
    fan = os.environ.get("FANOUT_ID", "")
    for scheme in ("light", "dark"):
        pg = login(b.new_context(viewport={"width": 1440, "height": 900}, color_scheme=scheme))
        shot(pg, "/", f"overview-{scheme}", 4000, sel="#map path.arc")
        if scheme == "light":
            shot(pg, "/netmon/countries?range=1h", "countries-light", 3000, sel="#blkmap path.country")
            pg.goto(B + "/")
            pg.wait_for_selector("#map path.arc.in", timeout=60000)
            pg.wait_for_timeout(3000)
            pg.locator(".map-card").scroll_into_view_if_needed()
            hover_arc(pg)
            pg.locator(".map-card").screenshot(path=f"{OUT}/map-tooltip.png")
            SHOTS.append("map-tooltip")
            print("saved map-tooltip")
            shot(pg, "/netmon/security", "security-findings", 2000)
            if fan:
                shot(pg, f"/netmon/alert/{fan}", "finding-detail", 3500, sel="#ft-remotes tbody tr")
            shot(pg, "/netmon/connections?range=1h", "connections", 3000, sel="#conv table")
            shot(pg, "/netmon/servers?range=6h", "servers", 3000, sel="table tbody tr")
            shot(pg, "/netmon/servers/10.40.0.250?range=6h", "server-detail", 3500, sel=".srvaddrs")
            shot(pg, "/netmon/coverage", "coverage", 2000)
            shot(pg, "/netmon/settings", "settings", 2000)
    m = login(b.new_context(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True, device_scale_factor=2))
    shot(m, "/", "mobile-overview", 4000)
    print("mobile scrollWidth", m.evaluate("document.documentElement.scrollWidth"))
    print("done:", ", ".join(SHOTS))
