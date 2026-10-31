"""Local users + server-side sessions (scrypt hashes, hashed session tokens)."""
import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from urllib.parse import quote

from . import secretbox

SESSION_COOKIE = "netmon_session"
SESSION_TTL = 12 * 3600
IDLE_TTL = 2 * 3600
ROLES = {"viewer": 0, "analyst": 1, "admin": 2}

AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY, pw_hash TEXT NOT NULL, role TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, last_login REAL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, created_at REAL NOT NULL,
  last_seen REAL NOT NULL, expires_at REAL NOT NULL, ip TEXT, user_agent TEXT);
CREATE TABLE IF NOT EXISTS login_failures (ip TEXT NOT NULL, username TEXT, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS mfa_pending (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at REAL NOT NULL,
  ip TEXT, next TEXT);
"""
USER_COLS = {"totp_secret": "TEXT", "totp_enabled": "INTEGER NOT NULL DEFAULT 0", "totp_last": "INTEGER NOT NULL DEFAULT 0",
             "recovery": "TEXT", "email": "TEXT"}


def init(conn):
    conn.executescript(AUTH_SCHEMA)
    have = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
    for col, typ in USER_COLS.items():
        if col not in have:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
    conn.commit()


# ---- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ------------------------------------------
def totp_new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def totp_check(secret: str, code: str, last_counter: int = 0, now=None, window=1):
    """Return the matched counter (to block replay) or None."""
    code = "".join(c for c in code if c.isdigit())
    if len(code) != 6 or not secret:
        return None
    c0 = int((now or time.time()) // 30)
    for c in range(c0 - window, c0 + window + 1):
        if c > last_counter and hmac.compare_digest(_hotp(secret, c), code):
            return c
    return None


def totp_seal(secret: str, username: str) -> str:
    return secretbox.seal(secret, "totp:" + username)


def totp_secret_of(stored, username: str):
    """The TOTP seed from the users table (sealed, or legacy plaintext until the startup migration seals it)."""
    return secretbox.reveal(stored, "totp:" + username) if stored else None


def totp_uri(secret: str, username: str, issuer="netmon") -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def new_recovery_codes(n=10):
    codes = ["-".join(secrets.token_hex(3) for _ in range(2)) for _ in range(n)]
    return codes, json.dumps([hashlib.sha256(c.encode()).hexdigest() for c in codes])


def use_recovery(conn, username: str, code: str) -> bool:
    row = conn.execute("SELECT recovery FROM users WHERE username=?", (username,)).fetchone()
    hashes = json.loads(row["recovery"] or "[]") if row else []
    h = hashlib.sha256(code.strip().lower().encode()).hexdigest()
    if h not in hashes:
        return False
    hashes.remove(h)
    conn.execute("UPDATE users SET recovery=? WHERE username=?", (json.dumps(hashes), username))
    conn.commit()
    return True


def verify_second_factor(conn, username: str, code: str) -> str | None:
    """Return 'totp' or 'recovery' on success."""
    u = conn.execute("SELECT totp_secret, totp_last FROM users WHERE username=? AND totp_enabled=1", (username,)).fetchone()
    if not u:
        return None
    c = totp_check(totp_secret_of(u["totp_secret"], username), code, u["totp_last"] or 0)
    if c is not None:
        conn.execute("UPDATE users SET totp_last=? WHERE username=?", (c, username))
        conn.commit()
        return "totp"
    return "recovery" if use_recovery(conn, username, code) else None


def start_mfa(conn, username: str, ip: str, nxt: str) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute("DELETE FROM mfa_pending WHERE expires_at < ?", (time.time(),))
    conn.execute("INSERT INTO mfa_pending VALUES (?,?,?,?,?)", (_th(token), username, time.time() + 300, ip, nxt))
    conn.commit()
    return token


def pending_mfa(conn, token: str | None):
    if not token:
        return None
    r = conn.execute("SELECT * FROM mfa_pending WHERE token_hash=? AND expires_at > ?", (_th(token), time.time())).fetchone()
    return dict(r) if r else None


def finish_mfa(conn, token: str):
    conn.execute("DELETE FROM mfa_pending WHERE token_hash=?", (_th(token),))
    conn.commit()


def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024)
    return f"scrypt$32768$8$1${salt.hex()}${h.hex()}"


def check_pw(pw: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(got.hex(), h)
    except (ValueError, TypeError):
        return False


_DUMMY = hash_pw(secrets.token_hex(8))  # equalize timing for unknown users


def password_problem(pw: str) -> str | None:
    if len(pw) < 12:
        return "password must be at least 12 characters"
    return None


def bootstrap_admin(conn, password_file: str):
    """Create the first admin from a secret file if no users exist."""
    if conn.execute("SELECT count(*) FROM users").fetchone()[0]:
        return False
    pw = secretbox.read_file(password_file)
    if not pw:
        return False
    if password_problem(pw):
        return False
    conn.execute("INSERT INTO users(username,pw_hash,role,created_at) VALUES (?,?,?,?)",
                 ("admin", hash_pw(pw), "admin", time.time()))
    conn.commit()
    return True


def throttled(conn, ip: str, username: str) -> bool:
    """≥5 failures from this IP, or ≥10 for this username, in 15 minutes."""
    since = time.time() - 900
    conn.execute("DELETE FROM login_failures WHERE ts < ?", (since - 86400,))
    by_ip = conn.execute("SELECT count(*) FROM login_failures WHERE ip=? AND ts>?", (ip, since)).fetchone()[0]
    by_user = conn.execute("SELECT count(*) FROM login_failures WHERE username=? AND ts>?",
                           (username, since)).fetchone()[0]
    return by_ip >= 5 or by_user >= 10


def record_failure(conn, ip: str, username: str):
    conn.execute("INSERT INTO login_failures(ip,username,ts) VALUES (?,?,?)", (ip, username[:64], time.time()))
    conn.commit()


def check_password(conn, username: str, password: str, ip: str):
    """Return the user row if the password is right and the account active, else None (failure recorded)."""
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    ok = check_pw(password, row["pw_hash"] if row else _DUMMY) and row is not None and not row["disabled"]
    if not ok:
        record_failure(conn, ip, username)
        return None
    return row


def login(conn, username: str, password: str, ip: str, ua: str):
    """Password-only login (used when the account has no second factor). Returns a session token or None."""
    if not check_password(conn, username, password, ip):
        return None
    return create_session(conn, username, ip, ua)


def create_session(conn, username: str, ip: str, ua: str) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?)",
                 (_th(token), username, now, now, now + SESSION_TTL, ip, ua[:200]))
    conn.execute("UPDATE users SET last_login=? WHERE username=?", (now, username))
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    conn.commit()
    return token


def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def session_user(conn, token: str | None):
    """Return (username, role, token_hash) for a valid session, refreshing idle time."""
    if not token:
        return None
    now = time.time()
    s = conn.execute("SELECT s.*, u.role, u.disabled FROM sessions s JOIN users u USING(username) "
                     "WHERE token_hash=?", (_th(token),)).fetchone()
    if not s or s["disabled"] or s["expires_at"] < now or now - s["last_seen"] > IDLE_TTL:
        return None
    if now - s["last_seen"] > 60:
        conn.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, s["token_hash"]))
        conn.commit()
    return s["username"], s["role"], s["token_hash"]


def logout(conn, token: str | None):
    if token:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (_th(token),))
        conn.commit()


def revoke_user_sessions(conn, username: str):
    conn.execute("DELETE FROM sessions WHERE username=?", (username,))
    conn.commit()
