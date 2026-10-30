"""Notification channels: email (SMTP), SMS (Twilio or email-to-SMS gateway), generic webhook (HMAC),
Slack, Microsoft Teams (Workflows), Discord, ntfy and Pushover.

Channels live in the database (Settings → Notifications). Nothing is sent until a channel is
configured and enabled; every channel has a clearly marked test message. Deliveries run on a
background worker with retry/backoff, per-channel rate limits, quiet hours and maintenance windows,
and every attempt is recorded.
"""
import hashlib
import hmac
import json
import queue
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage

import httpx

from .core import audit, get_setting

SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CATEGORY = {"new_dest_country": "info", "new_dest_asn": "info", "fw_blocked_scan": "info", "exporter_silence": "health", "disk_usage": "health",
            "detector_error": "health", "syslog_silence": "health", "source_health": "health", "dns_bypass": "info", "dns_anomaly": "security", "test": "test"}

# type -> (label, fields[(key, label, kind)], secret keys)
TYPES = {
    "email": ("Email (SMTP)", [("host", "SMTP host", "text"), ("port", "Port", "number"),
                              ("security", "Security (starttls | ssl | none)", "text"), ("username", "Username", "text"),
                              ("password", "Password", "secret"), ("from", "From address", "text"),
                              ("to", "To (comma-separated)", "text")], {"password"}),
    "sms_twilio": ("SMS (Twilio)", [("account_sid", "Account SID", "text"), ("auth_token", "Auth token", "secret"),
                                    ("from", "From number (E.164) or Messaging Service SID", "text"),
                                    ("to", "To numbers (E.164, comma-separated)", "text")], {"auth_token"}),
    "sms_email": ("SMS via carrier email gateway", [("host", "SMTP host", "text"), ("port", "Port", "number"),
                                                  ("security", "Security (starttls | ssl | none)", "text"), ("username", "Username", "text"),
                                                  ("password", "Password", "secret"), ("from", "From address", "text"),
                                                  ("to", "Gateway addresses, e.g. 5551234567@vtext.com", "text")], {"password"}),
    "webhook": ("Generic webhook (JSON, HMAC-signed)", [("url", "URL (https)", "text"), ("secret", "HMAC secret (optional)", "secret"),
                                                       ("auth_header", "Authorization header (optional)", "secret")], {"secret", "auth_header"}),
    "slack": ("Slack (incoming webhook)", [("url", "Webhook URL", "secret")], {"url"}),
    "teams": ("Microsoft Teams (Workflows webhook)", [("url", "Workflow webhook URL", "secret")], {"url"}),
    "discord": ("Discord (webhook)", [("url", "Webhook URL", "secret")], {"url"}),
    "ntfy": ("ntfy push", [("server", "Server (https://ntfy.sh or self-hosted)", "text"), ("topic", "Topic", "text"),
                          ("token", "Access token (optional)", "secret")], {"token"}),
    "pushover": ("Pushover", [("app_token", "Application token", "secret"), ("user_key", "User/group key", "secret")],
                 {"app_token", "user_key"}),
}


def category(rule):
    return CATEGORY.get(rule, "security")


class Notifier:
    @property
    def base(self):
        """https://<this monitor's FQDN> when set (Settings → Firewalls & sites → This monitor), else the configured URL."""
        m = get_setting(self.conn, "monitor:db", {}) or {}
        return f"https://{m['fqdn']}" if m.get("fqdn") else self._base

    def __init__(self, cfg, conn, base_url):
        from .core import ThreadLocalDB
        self.cfg, self._base = cfg, base_url.rstrip("/")
        self.conn = ThreadLocalDB()  # safe from detector, web and worker threads alike
        self.q = queue.Queue(maxsize=1000)
        self._started = False

    # ---- public ---------------------------------------------------------------------
    @property
    def enabled(self):
        return bool(self.conn.execute("SELECT count(*) FROM channels WHERE enabled=1").fetchone()[0])

    def start(self):
        if not self._started:
            self._started = True
            threading.Thread(target=self._worker, daemon=True).start()
            threading.Thread(target=self._summary_loop, daemon=True).start()

    def alert(self, alert_id, test=False):
        """Queue an alert for routing to matching channels (non-blocking)."""
        try:
            self.q.put_nowait(("alert", alert_id, None))
        except queue.Full:
            audit(self.conn, "notifier", "queue_full", {"alert": alert_id})

    def recovery(self, alert_id):
        """Queue a recovery notice for a closed health alert (same channels and filters as the alert)."""
        try:
            self.q.put_nowait(("recovery", alert_id, None))
        except queue.Full:
            audit(self.conn, "notifier", "queue_full", {"recovery": alert_id})

    def test(self, channel_id, user):
        self.q.put(("test", channel_id, user))

    # ---- routing ----------------------------------------------------------------------
    def in_maintenance(self, a, now):
        for m in self.conn.execute("SELECT * FROM maintenance WHERE enabled=1 AND start_ts<=? AND end_ts>=?", (now, now)):
            if m["asset"] in ("*", a["asset"]) and m["rule"] in ("*", a["rule"]):
                return m["reason"]
        return None

    def matches(self, ch, a, now):
        if SEV.get(a["severity"], 0) < SEV.get(ch["min_severity"], 2):
            return "below minimum severity"
        if category(a["rule"]) not in json.loads(ch["categories"] or "[]"):
            return "category not routed"
        if ch["quiet_start"] is not None and ch["quiet_end"] is not None:
            h = time.localtime(now).tm_hour
            qs, qe = ch["quiet_start"], ch["quiet_end"]
            quiet = (qs <= h < qe) if qs < qe else (h >= qs or h < qe)
            if quiet and not (ch["quiet_allow_high"] and SEV.get(a["severity"], 0) >= 3):
                return "quiet hours"
        sent = self.conn.execute("SELECT count(*) FROM deliveries WHERE channel_id=? AND status='delivered' AND ts>?",
                                 (ch["id"], now - 3600)).fetchone()[0]
        if sent >= ch["max_per_hour"]:
            return "rate limited"
        return None

    def _log(self, ch, alert_id, kind, status, attempts=0, detail=""):
        self.conn.execute("INSERT INTO deliveries(ts,channel_id,channel,alert_id,kind,status,attempts,detail) VALUES (?,?,?,?,?,?,?,?)",
                          (time.time(), ch["id"] if ch else None, ch["name"] if ch else "", alert_id, kind, status, attempts, detail[:500]))
        self.conn.commit()

    def _worker(self):
        while True:
            kind, ref, user = self.q.get()
            try:
                if kind == "alert":
                    self._route_alert(ref)
                elif kind == "recovery":
                    a = self.conn.execute("SELECT * FROM alerts WHERE id=?", (ref,)).fetchone()
                    for ch in self.conn.execute("SELECT * FROM channels WHERE enabled=1").fetchall() if a else []:
                        if "health" in json.loads(ch["categories"] or "[]"):
                            self._deliver(ch, ref, "recovery", {"title": f"[RECOVERED] {a['title']}", "severity": "info",
                                                                "text": f"{a['title']}\nThe check is healthy again.",
                                                                "link": f"{self.base}/netmon/alert/{ref}", "id": ref, "test": False})
                elif kind == "test":
                    ch = self.conn.execute("SELECT * FROM channels WHERE id=?", (ref,)).fetchone()
                    if ch:
                        msg = {"title": "[TEST] netmon test notification", "severity": "info",
                               "text": f"This is a TEST message requested by {user}. No security event occurred.",
                               "link": f"{self.base}/netmon/settings/notifications", "test": True}
                        self._deliver(ch, None, "test", msg)
            except Exception as ex:  # never let the worker die
                self._log(None, ref if kind == "alert" else None, kind, "error", 0, str(ex))

    def _route_alert(self, alert_id):
        a = self.conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not a:
            return
        now = time.time()
        if a["test"]:
            return
        mw = self.in_maintenance(a, now)
        if mw:
            self.conn.execute("UPDATE alerts SET maintenance=1, notify_status=? WHERE id=?", (f"suppressed: maintenance ({mw})", alert_id))
            self.conn.commit()
            return
        results = []
        for ch in self.conn.execute("SELECT * FROM channels WHERE enabled=1").fetchall():
            why = self.matches(ch, a, now)
            if why:
                results.append(f"{ch['name']}: skipped ({why})")
                continue
            msg = self.format_alert(a)
            results.append(f"{ch['name']}: {self._deliver(ch, alert_id, 'alert', msg)}")
        self.conn.execute("UPDATE alerts SET notify_status=? WHERE id=?",
                          ("; ".join(results)[:500] if results else "no channels configured", alert_id))
        self.conn.commit()

    def format_alert(self, a):
        nxt = (json.loads(a["next_steps"] or "[]") or [""])[0]
        return {"title": f"[{a['severity'].upper()}] {a['title']}", "severity": a["severity"],
                "text": f"{a['title']}\nConfidence: {a['confidence']} · rule {a['rule']}\nWhy: {a['baseline']}\nNext: {nxt}",
                "link": f"{self.base}/netmon/alert/{a['id']}", "id": a["id"], "rule": a["rule"], "asset": a["asset"],
                "confidence": a["confidence"], "test": False}

    def _deliver(self, ch, alert_id, kind, msg):
        err = ""
        for attempt in range(1, 5):
            try:
                send(ch["type"], json.loads(ch["config"]), msg)
                self._log(ch, alert_id, kind, "delivered", attempt)
                return "delivered"
            except Exception as ex:
                err = redact(str(ex))
                time.sleep(min(60, 2 ** attempt))
        self._log(ch, alert_id, kind, "failed", 4, err)
        return f"failed ({err[:80]})"

    # ---- daily summary ------------------------------------------------------------------
    def _summary_loop(self):
        from .core import db_connect, get_setting, set_state
        conn = db_connect()
        while True:
            time.sleep(60)
            hour = get_setting(conn, "summary_hour", 8)
            lt = time.localtime()
            day = time.strftime("%Y-%m-%d", lt)
            last = conn.execute("SELECT v FROM state WHERE k='summary_sent'").fetchone()
            if lt.tm_hour != hour or (last and json.loads(last["v"]) == day):
                continue
            set_state(conn, "summary_sent", day)
            since = time.time() - 86400
            rows = conn.execute("SELECT severity, rule, title FROM alerts WHERE first_seen>? AND test=0 ORDER BY "
                                "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END LIMIT 10", (since,)).fetchall()
            n = conn.execute("SELECT count(*) FROM alerts WHERE first_seen>? AND test=0", (since,)).fetchone()[0]
            text = f"{n} new finding(s) in the last 24 h." + "".join(f"\n- [{r['severity']}] {r['title']}" for r in rows)
            msg = {"title": "netmon daily summary", "severity": "info", "text": text, "link": f"{self.base}/netmon/security", "test": False}
            for ch in conn.execute("SELECT * FROM channels WHERE enabled=1 AND summary_daily=1").fetchall():
                try:
                    send(ch["type"], json.loads(ch["config"]), msg)
                    conn.execute("INSERT INTO deliveries(ts,channel_id,channel,kind,status,attempts) VALUES (?,?,?,?,?,1)",
                                 (time.time(), ch["id"], ch["name"], "summary", "delivered"))
                except Exception as ex:
                    conn.execute("INSERT INTO deliveries(ts,channel_id,channel,kind,status,attempts,detail) VALUES (?,?,?,?,?,1,?)",
                                 (time.time(), ch["id"], ch["name"], "summary", "failed", redact(str(ex))[:300]))
                conn.commit()


def redact(s: str) -> str:
    """Strip anything that looks like a URL path/token from error text before logging."""
    import re
    return re.sub(r"(https?://[^/\s]+)/\S*", r"\1/…", s)


def _smtp(c, subject, body):
    msg = EmailMessage()
    msg["Subject"], msg["From"] = subject, c["from"]
    msg["To"] = ", ".join(x.strip() for x in c["to"].split(",") if x.strip())
    msg.set_content(body)
    port, sec = int(c.get("port") or 587), (c.get("security") or "starttls").lower()
    ctx = ssl.create_default_context()
    if sec == "ssl":
        s = smtplib.SMTP_SSL(c["host"], port, timeout=20, context=ctx)
    else:
        s = smtplib.SMTP(c["host"], port, timeout=20)
        if sec == "starttls":
            s.starttls(context=ctx)
    with s:
        if c.get("username"):
            s.login(c["username"], c.get("password", ""))
        s.send_message(msg)


def send(kind, c, m):
    """Deliver message m ({title, text, link, severity, test}) via one channel type. Raises on failure."""
    title, text, link = m["title"], m["text"], m.get("link", "")
    short = f"{title} {link}"[:300]
    if kind == "email":
        _smtp(c, title, f"{text}\n\n{link}\n\n— netmon{' (TEST)' if m.get('test') else ''}")
    elif kind == "sms_email":
        _smtp(c, "netmon", short[:150])
    elif kind == "sms_twilio":
        for to in [x.strip() for x in c["to"].split(",") if x.strip()]:
            frm = c["from"].strip()
            data = {"To": to, "Body": short[:320], **({"MessagingServiceSid": frm} if frm.startswith("MG") else {"From": frm})}
            r = httpx.post(f"https://api.twilio.com/2010-04-01/Accounts/{c['account_sid']}/Messages.json", data=data,
                           auth=(c["account_sid"], c["auth_token"]), timeout=20)
            if r.status_code >= 300:
                raise RuntimeError(f"Twilio HTTP {r.status_code}")
    elif kind == "webhook":
        if not c["url"].startswith("https://"):
            raise RuntimeError("webhook URL must use https")
        body = json.dumps(m).encode()
        h = {"Content-Type": "application/json"}
        if c.get("secret"):
            h["X-Netmon-Signature"] = "sha256=" + hmac.new(c["secret"].encode(), body, hashlib.sha256).hexdigest()
        if c.get("auth_header"):
            h["Authorization"] = c["auth_header"]
        _post(c["url"], content=body, headers=h)
    elif kind == "slack":
        _post(c["url"], json={"text": f"*{title}*\n{text}\n<{link}|Open in netmon>"})
    elif kind == "discord":
        _post(c["url"], json={"content": f"**{title}**\n{text}\n{link}"[:1990]})
    elif kind == "teams":
        card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4",
                "body": [{"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True},
                         {"type": "TextBlock", "text": text, "wrap": True}],
                "actions": [{"type": "Action.OpenUrl", "title": "Open in netmon", "url": link}] if link else []}
        _post(c["url"], json={"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]})
    elif kind == "ntfy":
        prio = {"critical": "5", "high": "4", "medium": "3"}.get(m.get("severity"), "2")
        h = {"Title": title.encode("ascii", "replace").decode(), "Priority": prio, "Tags": "shield"}
        if link:
            h["Click"] = link
        if c.get("token"):
            h["Authorization"] = f"Bearer {c['token']}"
        _post(f"{c['server'].rstrip('/')}/{c['topic']}", content=text.encode(), headers=h)
    elif kind == "pushover":
        r = httpx.post("https://api.pushover.net/1/messages.json", timeout=20,
                       data={"token": c["app_token"], "user": c["user_key"], "title": title[:250], "message": text[:1000],
                             "url": link, "priority": "1" if m.get("severity") in ("high", "critical") else "0"})
        if r.status_code >= 300:
            raise RuntimeError(f"Pushover HTTP {r.status_code}")
    else:
        raise RuntimeError(f"unknown channel type {kind}")


def _post(url, **kw):
    r = httpx.post(url, timeout=20, **kw)
    if r.status_code >= 300:
        raise RuntimeError(f"HTTP {r.status_code}")
