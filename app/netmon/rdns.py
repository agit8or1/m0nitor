"""Reverse DNS (PTR) names for map tooltips, cached in memory.

Never blocks a request: an address with no cached answer is queued and resolved by one background thread
through the site's own resolver (the firewall), so its name shows on the next refresh."""
import ipaddress
import queue
import threading
import time

from .dnsresolve import query

POS_MIN, POS_MAX, NEG_TTL, MAX_CACHE = 3600, 86400, 6 * 3600, 50000


class RDNS:
    def __init__(self, cfg):
        self.cfg, self.cache, self.q, self.pending = cfg, {}, queue.Queue(maxsize=5000), set()
        self.lock, self.thread = threading.Lock(), None

    def server(self):
        for s in self.cfg.sites:
            if s.get("syslog_source") or s.get("exporter_ip"):
                return s.get("syslog_source") or s.get("exporter_ip")
        return ""

    def get(self, ip):
        """Cached PTR name, '' when there is none (or not resolved yet: then it is queued)."""
        if not ip:
            return ""
        now = time.time()
        with self.lock:
            hit = self.cache.get(ip)
            if hit and hit[1] > now:
                return hit[0]
            if ip in self.pending:
                return hit[0] if hit else ""
            self.pending.add(ip)
        try:
            self.q.put_nowait(ip)
        except queue.Full:
            with self.lock:
                self.pending.discard(ip)
        self._start()
        return hit[0] if hit else ""

    def _start(self):
        if self.thread is None:
            with self.lock:
                if self.thread is None:
                    self.thread = [threading.Thread(target=self._run, daemon=True, name=f"rdns-{i}") for i in range(4)]
                    for t in self.thread:
                        t.start()

    def _run(self):
        while True:
            ip = self.q.get()
            name, ttl = "", NEG_TTL
            try:
                srv = self.server()
                if srv:
                    ans = query(ipaddress.ip_address(ip).reverse_pointer, "PTR", srv, timeout=4.0)
                    if ans:
                        name, ttl = ans[0][0].rstrip("."), min(POS_MAX, max(POS_MIN, ans[0][1]))
            except Exception:
                ttl = 600   # timeout / bad answer: try again later
            with self.lock:
                if len(self.cache) > MAX_CACHE:
                    self.cache.clear()
                self.cache[ip] = (name, time.time() + ttl)
                self.pending.discard(ip)
