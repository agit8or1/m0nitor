"""Per-user firewall (site) restrictions.

A viewer or analyst can be limited to some firewalls (users.sites: JSON list of site ids; NULL = all). Admins always
see every firewall: they manage firewalls, users and global settings, so restricting them would be misleading.

How it is enforced, so that every page and API gets it without each one remembering to:
- the request's allowed set lives in a context variable, set when the session is resolved (web.current);
- Config.sites / cfg["sites"] / cfg.site(id) return only allowed firewalls while it is set, so every site picker,
  scope, per-firewall loop and flow query (ExporterName IN the scope's exporters) is limited by construction;
- records that carry a site (findings, incidents, identities, applications, probes, segments, exceptions, blocks,
  hunt matches ...) are filtered with site_sql()/can_site(), and opening one directly is a 404 (not 403, so the
  existence of another firewall's records is not revealed);
- work a request hands to a thread or pool runs in a copy of the request's context (spawn/submit), and shared caches
  include allowed_key() in their key.
Background workers (detector, probes, health) run outside any request and see everything.
"""
import contextvars
import json
import re
import threading

_ALLOWED = contextvars.ContextVar("netmon_allowed_sites", default=None)   # None = unrestricted


class NoSites(Exception):
    """A restricted user whose firewalls no longer exist: nothing to show."""


def set_allowed(sites):
    """sites: None (all) or an iterable of site ids. Returns the token for reset()."""
    return _ALLOWED.set(None if sites is None else frozenset(sites))


def reset(token):
    _ALLOWED.reset(token)


def allowed():
    """frozenset of allowed site ids, or None when unrestricted."""
    return _ALLOWED.get()


def restricted() -> bool:
    return _ALLOWED.get() is not None


def allowed_key():
    """Cache-key component: () when unrestricted, else the sorted allowed ids."""
    a = _ALLOWED.get()
    return () if a is None else tuple(sorted(a))


def can_site(sid) -> bool:
    a = _ALLOWED.get()
    return a is None or sid in a


def filter_sites(sites: list) -> list:
    a = _ALLOWED.get()
    return sites if a is None else [s for s in sites if s.get("id") in a]


def site_sql(col="site"):
    """(SQL condition, params) limiting a column of site ids to the allowed set. Rows with no site (NULL) are only
    visible to unrestricted users."""
    a = _ALLOWED.get()
    if a is None:
        return "1=1", ()
    if not a:
        return "0=1", ()
    ids = sorted(a)
    return f"{col} IN ({','.join('?' * len(ids))})", tuple(ids)


def and_site(col="site"):
    """' AND <cond>' plus params, for appending to an existing WHERE."""
    c, p = site_sql(col)
    return ("" if c == "1=1" else f" AND {c}"), p


def ch_sites():
    """For ClickHouse event tables (fw_events, ids_events, ...): (condition, params) on their `site` column."""
    a = _ALLOWED.get()
    if a is None:
        return "1", {}
    return "site IN {_allowed_sites:Array(String)}", {"_allowed_sites": sorted(a)}


def require(sid):
    """404 unless the record's site is allowed (used when a record is opened by id)."""
    if not can_site(sid):
        from fastapi import HTTPException
        raise HTTPException(404, "not found")


def spawn(target, *args, **kw):
    """threading.Thread that keeps the request's restriction (threads do not inherit context variables)."""
    ctx = contextvars.copy_context()
    t = threading.Thread(target=ctx.run, args=(target, *args), kwargs=kw, daemon=True)
    t.start()
    return t


def submit(pool, fn, *args, **kw):
    """pool.submit that keeps the request's restriction."""
    ctx = contextvars.copy_context()
    return pool.submit(ctx.run, fn, *args, **kw)


# ---- per-user setting ------------------------------------------------------------------------------------------
def user_sites(conn, username, role, all_ids):
    """The allowed set for a session: None for admins and unrestricted users, else the stored ids that still exist."""
    if role == "admin":
        return None
    r = conn.execute("SELECT sites FROM users WHERE username=?", (username,)).fetchone()
    raw = r["sites"] if r else None
    if not raw:
        return None
    try:
        want = set(json.loads(raw))
    except (ValueError, TypeError):
        return frozenset()          # unreadable restriction: fail closed
    return frozenset(want & set(all_ids))


def stored_sites(conn, username):
    """The stored restriction as a list, or None for 'all firewalls'."""
    r = conn.execute("SELECT sites FROM users WHERE username=?", (username,)).fetchone()
    if not r or not r["sites"]:
        return None
    try:
        return list(json.loads(r["sites"]))
    except (ValueError, TypeError):
        return []


def store_sites(conn, username, sites):
    """sites: None = all firewalls, else a non-empty list of ids."""
    conn.execute("UPDATE users SET sites=? WHERE username=?", (None if sites is None else json.dumps(sorted(set(sites))), username))
    conn.commit()


def ch_restrict(sql, params, sites):
    """Add the request's firewall restriction to simple aggregate ClickHouse queries (coverage, source counts):
    'FROM flows WHERE' gets the allowed firewalls' exporters, 'FROM netmon.<table> WHERE' their site ids. Queries
    without a WHERE after the table get one. Unrestricted: unchanged. sites = the (already filtered) cfg.sites."""
    if not restricted():
        return sql, params
    if re.search(r"\bOR\b", sql, re.I):
        # 'WHERE <site> AND a OR b' would escape the filter: refuse rather than guess the precedence
        raise ValueError("query not restrictable per firewall")
    p = dict(params or {})
    p["_ax"] = sorted({s.get("exporter", "") for s in sites if s.get("exporter")}) or ["\x00none"]
    p["_as"] = sorted(s["id"] for s in sites) or ["\x00none"]

    def fix(m):
        table = m.group(1)
        cond = "ExporterName IN {_ax:Array(String)}" if table.startswith("flows") else "site IN {_as:Array(String)}"
        return f"FROM {table} WHERE {cond} AND " if m.group(2).strip() else f"FROM {table} WHERE {cond}"
    pat = r"FROM\s+((?:netmon\.)?[A-Za-z_0-9]+)(\s+WHERE\s+|(?=[\s)]|$))"
    out = re.sub(pat, lambda m: fix(m) if m.group(1).startswith(("flows", "netmon.")) else m.group(0), sql)
    return out, p
