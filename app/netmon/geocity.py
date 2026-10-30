"""City-level GeoIP for map placement only: where to draw an endpoint, never what country it is in.

Source: DB-IP "IP to City Lite" (CC BY 4.0, https://db-ip.com), a monthly mmdb fetched without an account into the
data volume. Countries everywhere else still come from the IPinfo database Akvorado enriches flows with, so a city
lookup never changes which country traffic is counted under; a location whose country disagrees with the flow's
country is not used. City-level GeoIP is approximate (often the ISP's registered city), so it is shown as a region.

Refresh: when the file is missing or older than REFRESH_DAYS, the current month's file (then the previous month's)
is downloaded, checked by opening it and looking up a known address, and swapped in atomically. A failed download
keeps the old file and is retried after RETRY_SECONDS.
"""
import gzip
import os
import shutil
import threading
import time

from .core import get_state, set_state

DB_PATH = os.environ.get("NETMON_GEOCITY_DB", "/data/geo/dbip-city-lite.mmdb")
URL = "https://download.db-ip.com/free/dbip-city-lite-{ym}.mmdb.gz"
REFRESH_DAYS = 32
RETRY_SECONDS = 6 * 3600
ATTRIBUTION = "IP geolocation by DB-IP (db-ip.com), CC BY 4.0"
STATE = "geocity"


class CityGeo:
    def __init__(self, path=DB_PATH):
        self.path, self._r, self._mtime, self._cache, self._lock = path, None, 0, {}, threading.Lock()

    def _reader(self):
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            return None
        if self._r is None or m != self._mtime:   # reopen after a monthly refresh swapped the file
            import maxminddb
            with self._lock:
                self._r, self._mtime = maxminddb.open_database(self.path), m
                self._cache.clear()
        return self._r

    def loc(self, ip):
        """{"lat", "lon", "city", "region", "cc"} or None (no database, no record, or no coordinates)."""
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
        out = None
        try:
            r = self._reader()
            rec = (r.get(ip) if r else None) or {}
            ll = rec.get("location") or {}
            if ll.get("latitude") is not None and ll.get("longitude") is not None:
                c = rec.get("country") or {}
                out = {"lat": round(float(ll["latitude"]), 3), "lon": round(float(ll["longitude"]), 3),
                       "city": ((rec.get("city") or {}).get("names") or {}).get("en", ""),
                       "region": (((rec.get("subdivisions") or [{}])[0]).get("names") or {}).get("en", ""),
                       "cc": (c.get("iso_code", "") if isinstance(c, dict) else str(c)).upper()}
        except Exception:
            out = None
        with self._lock:
            if len(self._cache) > 200_000:
                self._cache.clear()
            self._cache[ip] = out
        return out

    def provenance(self):
        try:
            r = self._reader()
        except Exception as ex:
            return {"database": None, "error": str(ex)[:160], "attribution": ATTRIBUTION}
        if not r:
            return {"database": None, "attribution": ATTRIBUTION}
        m = r.metadata()
        return {"database": m.database_type, "built": time.strftime("%Y-%m-%d", time.gmtime(m.build_epoch)), "attribution": ATTRIBUTION}


GEO = CityGeo()


def _months(now):
    t = time.gmtime(now)
    prev = (t.tm_year, t.tm_mon - 1) if t.tm_mon > 1 else (t.tm_year - 1, 12)
    return [f"{t.tm_year:04d}-{t.tm_mon:02d}", f"{prev[0]:04d}-{prev[1]:02d}"]


def refresh(conn, now=None, fetch=None, path=None):
    """Download when due (self-limiting; safe to call every minute). Returns the stored state."""
    now, path = now or time.time(), path or DB_PATH
    st = get_state(conn, STATE, None)[0] or {}
    try:
        if now - os.path.getmtime(path) < REFRESH_DAYS * 86400:
            return st
    except OSError:
        pass
    if now - st.get("tried", 0) < RETRY_SECONDS:
        return st
    st["tried"] = now
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp, errors = path + ".part", []
    for ym in _months(now):
        try:
            (fetch or _fetch)(URL.format(ym=ym), tmp)
            import maxminddb
            r = maxminddb.open_database(tmp)
            ok = bool((r.get("8.8.8.8") or {}).get("location"))
            r.close()
            if not ok:
                raise ValueError("test lookup has no location")
            os.replace(tmp, path)
            st.update(ok=True, month=ym, updated=now, error=None)
            break
        except Exception as ex:
            errors.append(f"{ym}: {str(ex)[:160]}")
            if os.path.exists(tmp):
                os.remove(tmp)
    else:
        st.update(ok=os.path.exists(path), error="; ".join(errors))
    set_state(conn, STATE, st)
    return st


def _fetch(url, dest):
    import httpx
    gz = dest + ".gz"
    try:
        with httpx.Client(timeout=120, follow_redirects=True, headers={"User-Agent": "netmon map geolocation"}) as c:
            with c.stream("GET", url) as r:
                r.raise_for_status()
                with open(gz, "wb") as fh:
                    for chunk in r.iter_bytes(1 << 20):
                        fh.write(chunk)
        with gzip.open(gz, "rb") as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
    finally:
        if os.path.exists(gz):
            os.remove(gz)


def locate(rows, geo=None):
    """Adds `loc` to remote-endpoint rows (ip, cc) when the city database places them in the flow's own country."""
    geo = geo or GEO
    for r in rows:
        g = geo.loc(r["ip"])
        r["loc"] = g if g and g["cc"] == r["cc"] else None
    return rows


def regions(rows, geo=None):
    """Remote-endpoint rows (ip, cc, in_b, out_b, flows) -> per (country, region) byte-weighted map locations."""
    agg = {}
    for r in locate(rows, geo):
        g = r.pop("loc")
        if not g:
            continue
        name = g["region"] or g["city"] or "?"
        a = agg.setdefault((r["cc"], name), {"key": f"{r['cc']}:{name}", "cc": r["cc"], "region": name, "in_b": 0, "out_b": 0,
                                              "flows": 0, "peers": 0, "_w": 0, "_lat": 0.0, "_lon": 0.0, "_city": {}})
        b = r["in_b"] + r["out_b"]
        w = max(b, 1)
        a["in_b"] += r["in_b"]
        a["out_b"] += r["out_b"]
        a["flows"] += r["flows"]
        a["peers"] += 1
        a["_w"] += w
        a["_lat"] += g["lat"] * w
        a["_lon"] += g["lon"] * w
        if g["city"]:
            a["_city"][g["city"]] = a["_city"].get(g["city"], 0) + b
    out = []
    for a in agg.values():
        cities, w = sorted(a.pop("_city").items(), key=lambda x: -x[1]), a.pop("_w")
        a["ll"] = [round(a.pop("_lat") / w, 3), round(a.pop("_lon") / w, 3)]
        a["cities"] = [c for c, _ in cities[:3]]
        out.append(a)
    return sorted(out, key=lambda a: -(a["in_b"] + a["out_b"]))
