"""Threat intelligence from the ExploitHound Threat Radar (public CVE intelligence: CISA KEV, FIRST EPSS, CVE Program).

Enrichment only, never a detection source: the radar lists vulnerabilities, not addresses, so it cannot mark
traffic malicious. It is used to (1) mark IDS findings whose signature metadata cites a CVE that is confirmed
exploited (CISA KEV) or predicted (high EPSS), and (2) list radar CVEs that name software you run on a server
(Inventory "Software"). Optional: raise IDS findings for a confirmed-exploited CVE one severity level (off by default).

The radar page is HTML; each CVE is a <tr class="radar-row"> with data-* attributes, inside one of three panels:
confirmed (most recent CISA KEV additions), predicted (highest EPSS not yet in KEV), disclosed (published in the last
7 days). The page shows a window of each list, not the whole KEV catalog. Fetched over HTTPS on an interval; the last
good copy is kept when a fetch fails.
"""
import html
import re
import time

import httpx

from .core import get_setting, get_state, put_setting, set_state

SETTING = "threatintel"
STATE = "threatintel:data"
DEFAULTS = {"enabled": True, "url": "https://exploithound.com/threat-radar/", "interval_hours": 6, "raise_known_exploited": False}
SECTIONS = {"confirmed": "Confirmed exploited (CISA KEV)", "predicted": "Predicted (high EPSS)", "disclosed": "Newly disclosed (7 days)"}
RANK = {"confirmed": 0, "predicted": 1, "disclosed": 2}
MAX_BYTES = 20 * 2 ** 20
CVE_RE = re.compile(r"(?i)\bcve[-_](\d{4})[-_](\d{4,7})\b")

_PANEL = re.compile(r'id="(confirmed|predicted|disclosed|scoring)"')
_ROW = re.compile(r'<tr class="radar-row" id="(?:new-)?cve-(\d{4}-\d{4,7})"([^>]*)>(.*?)</tr>', re.S)
_ATTR = re.compile(r'data-([a-z]+)="([^"]*)"')
_TD = re.compile(r'<td data-label="([^"]+)">(.*?)</td>', re.S)
_TAG = re.compile(r"<[^>]+>")
_cache = {"ts": None, "data": None}


def settings(conn):
    return {**DEFAULTS, **(get_setting(conn, SETTING, {}) or {})}


def save_settings(conn, values, user):
    s = settings(conn)
    s.update({k: v for k, v in values.items() if k in DEFAULTS})
    if not str(s["url"]).startswith("https://"):
        raise ValueError("the feed URL must use https://")
    s["interval_hours"] = max(1, min(int(s["interval_hours"]), 168))
    put_setting(conn, SETTING, s, user)
    return s


def norm(cve):
    m = CVE_RE.search(cve or "")
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else ""


def text(fragment):
    return " ".join(html.unescape(_TAG.sub(" ", fragment)).split())


def parse(page):
    """{CVE-id: {section, cvss, epss, band, products, desc, date}}; a CVE in several panels keeps the strongest one."""
    panels = [(m.start(), m.group(1)) for m in _PANEL.finditer(page)]
    out = {}
    for m in _ROW.finditer(page):
        before = [name for pos, name in panels if pos < m.start()]
        section = before[-1] if before else ""
        if section not in RANK:
            continue
        a = {k: html.unescape(v) for k, v in _ATTR.findall(m.group(2))}
        tds = {k: text(v) for k, v in _TD.findall(m.group(3))}
        try:
            epss = float(a.get("epss", "-1"))
            cvss = float(a["cvss"]) if a.get("cvss") not in (None, "", "-1") else None
        except ValueError:
            epss, cvss = -1.0, None
        cve = f"CVE-{m.group(1)}"
        row = {"section": section, "cvss": cvss, "epss": epss if epss >= 0 else None, "band": a.get("band", ""),
               "products": [p for p in a.get("product", "").split("|") if p][:8], "desc": tds.get("What it is", "")[:240],
               "date": tds.get("Added to KEV") or tds.get("Published") or ""}
        if cve not in out or RANK[section] < RANK[out[cve]["section"]]:
            out[cve] = row
    return out


def fetch(url):
    with httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "netmon threat-intel (enrichment)"}) as c:
        with c.stream("GET", url) as r:
            r.raise_for_status()
            buf = bytearray()
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > MAX_BYTES:
                    raise ValueError("feed larger than 20 MiB")
    return buf.decode("utf-8", "replace")


def refresh(conn, force=False):
    """Fetch when due. Keeps the last good data on failure; returns the stored state."""
    s = settings(conn)
    st, _ = get_state(conn, STATE, None)
    st = st or {}
    if not s["enabled"] or (not force and st.get("attempt") and time.time() - st["attempt"] < s["interval_hours"] * 3600
                            and not (st.get("error") and time.time() - st["attempt"] > 1800)):
        return st
    st["attempt"] = time.time()
    try:
        rows = parse(fetch(s["url"]))
        if not rows:
            raise ValueError("no CVE rows found (page layout changed?)")
        st.update({"fetched": time.time(), "url": s["url"], "rows": rows, "error": "",
                   "counts": {k: sum(1 for r in rows.values() if r["section"] == k) for k in RANK}})
    except Exception as ex:
        st["error"] = str(ex)[:300]
    set_state(conn, STATE, st)
    _cache["ts"] = None
    return st


def data(conn):
    """Stored feed (cached per process until the next refresh)."""
    _, ts = get_state(conn, STATE, None)
    if _cache["ts"] != ts:
        _cache["data"], _cache["ts"] = get_state(conn, STATE, None)[0] or {}, ts
    return _cache["data"] or {}   # never fetched yet (fresh or offline install): no radar data, not an error


def lookup(conn, cves):
    """Radar entries for CVE ids (any spelling: CVE_2021_44228, cve-2021-44228), strongest first."""
    rows = data(conn).get("rows", {})
    hits = []
    for c in sorted({norm(x) for x in cves if norm(x)}):
        if c in rows:
            hits.append({"cve": c, **rows[c]})
    return sorted(hits, key=lambda h: (RANK[h["section"]], -(h["epss"] or 0)))


def software_matches(conn, software):
    """Radar CVEs whose product names contain every word of one of `software` (e.g. "nextcloud", "proxmox ve")."""
    rows = data(conn).get("rows", {})
    out = []
    for term in software:
        words = [w for w in re.split(r"\W+", term.lower()) if w]
        if not words or len("".join(words)) < 3:
            continue
        for cve, r in rows.items():
            if any(all(re.search(rf"\b{re.escape(w)}\b", p) for w in words) for p in r["products"]):
                out.append({"cve": cve, "term": term, **r})
    return sorted(out, key=lambda h: (RANK[h["section"]], -(h["epss"] or 0), -(h["cvss"] or 0)))
