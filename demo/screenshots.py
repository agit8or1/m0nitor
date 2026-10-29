"""Demo screenshots (synthetic data only). Runs in the demo app's network namespace, so it can reach nothing else:
  docker run --rm --network container:m0nitor-demo-app-1 -e PW=... -v $PWD:/w -w /w <playwright image> python demo/screenshots.py
"""
import os
import sqlite3

from playwright.sync_api import sync_playwright

B, OUT = "http://localhost:8000", "docs/screenshots"


def login(ctx):
    pg = ctx.new_page()
    pg.goto(B + "/login")
    pg.fill("input[name=username]", "admin")
    pg.fill("input[name=password]", os.environ["PW"])
    pg.click("button.primary")
    pg.wait_for_load_state("networkidle")
    return pg


def shot(pg, url, name, wait=2500, full=False, sel=None):
    pg.goto(B + url)
    pg.wait_for_load_state("networkidle")
    if sel:
        pg.wait_for_selector(sel, timeout=30000)
    pg.wait_for_timeout(wait)
    pg.screenshot(path=f"{OUT}/{name}.png", full_page=full)
    print("saved", name)


with sync_playwright() as p:
    b = p.chromium.launch()
    fan = os.environ.get("FANOUT_ID", "")
    for scheme in ("light", "dark"):
        pg = login(b.new_context(viewport={"width": 1440, "height": 900}, color_scheme=scheme))
        shot(pg, "/", f"overview-{scheme}", 4000)
        if scheme == "light":
            shot(pg, "/netmon/servers?range=6h", "servers", 3000)
            shot(pg, "/netmon/servers/10.40.0.250?range=6h", "server-page", 3500)
            shot(pg, "/netmon/connections?range=1h&dir=out", "connections", 3000, sel="#conv table")
            shot(pg, "/netmon/security", "security", 1500, full=True)
            if fan:
                shot(pg, f"/netmon/alert/{fan}", "finding-nat-fanout", 3500, full=True)
            shot(pg, "/netmon/coverage", "coverage", 1500, full=True)
        pg.goto(B + "/netmon/countries?range=1h")
        pg.wait_for_selector("#blkmap path.country", timeout=30000)
        pg.wait_for_timeout(3000)
        pos = pg.evaluate("""cc => { const p=[...document.querySelectorAll('#blkmap path.country')].find(x=>x.__data__&&x.__data__.properties.cc===cc);
            const r=p.getBoundingClientRect(); return [r.x+r.width/2, r.y+r.height/2]; }""", "CN")
        pg.mouse.move(*pos)
        pg.wait_for_timeout(600)
        pg.screenshot(path=f"{OUT}/countries-tooltip-{scheme}.png")
        print("saved countries", scheme)
    m = login(b.new_context(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True, device_scale_factor=2))
    shot(m, "/", "mobile-overview", 4000)
    print("mobile scrollWidth", m.evaluate("document.documentElement.scrollWidth"))
