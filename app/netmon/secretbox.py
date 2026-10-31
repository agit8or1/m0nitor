"""Secrets at rest: AES-256-GCM with a master key kept outside the data directory.

Sealed values look like ``nmsec1.<key id>.<base64url(nonce || ciphertext+tag)>``. The purpose (``file:<name>``,
``channel``, ``totp:<user>``) is bound as associated data, so a sealed value cannot be moved to another place and
still decrypt.

Master key (32 random bytes, base64 or hex in the file):
- ``$NETMON_MASTER_KEY_FILE`` (default ``/run/keys/master.key``, mounted read-only from ``/opt/netmon/keys``);
- otherwise ``<data dir>/master.key``, created on first start so upgrades keep working. That fallback sits next to
  the data it protects, so Settings → Health warns until the key is moved out of the data directory.
- ``<key file>.old`` and a leftover ``<data dir>/master.key`` are accepted for decryption only: anything sealed with
  them is re-sealed with the current key at startup (key rotation).

What it protects: a copy of ``netmon.db`` or of ``data/`` (a backup, a disk image, a support bundle) without the key
does not reveal credentials. It does not protect against someone who can read the key, e.g. root on the host or code
running inside the app container.
"""
import base64
import binascii
import hashlib
import json
import logging
import os
import sys
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .core import DATA_DIR

log = logging.getLogger("netmon.secretbox")
PREFIX = "nmsec1."
SECRETS_DIR = os.path.join(DATA_DIR, "secrets")


class SecretError(Exception):
    pass


def key_file():
    return os.environ.get("NETMON_MASTER_KEY_FILE", "/run/keys/master.key")


def fallback_file():
    return os.path.join(DATA_DIR, "master.key")


def _parse_key(text: str) -> bytes:
    t = text.strip()
    for dec in (lambda s: bytes.fromhex(s), lambda s: base64.b64decode(s, validate=True),
                lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))):
        try:
            k = dec(t)
        except (ValueError, binascii.Error):
            continue
        if len(k) == 32:
            return k
    raise SecretError("master key must be 32 bytes, base64 or hex encoded")


def _kid(key: bytes) -> str:
    return hashlib.sha256(b"netmon-master-key:" + key).hexdigest()[:8]


def new_key_text() -> str:
    return base64.b64encode(os.urandom(32)).decode()


class Box:
    def __init__(self):
        self.keys = {}          # kid -> AESGCM
        self.files = {}         # kid -> path
        self.current = None
        self.source = None      # "mounted" | "data-dir"
        self.error = None
        main, fb = key_file(), fallback_file()
        if os.path.exists(main):
            self.source = "mounted"
            self._add(main, current=True)
        else:
            if not os.path.exists(fb):
                try:
                    fd = os.open(fb, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w") as f:
                        f.write(new_key_text() + "\n")
                    log.warning("no master key at %s: generated %s (move it out of the data directory)", main, fb)
                except FileExistsError:
                    pass
            self.source = "data-dir"
            self._add(fb, current=True)
        for old in (main + ".old", fb):
            if old not in self.files.values() and os.path.exists(old):
                self._add(old, current=False)

    def _add(self, path, current):
        try:
            key = _parse_key(open(path).read())
        except (OSError, SecretError) as ex:
            if current:
                self.error = f"{path}: {ex}"
            log.error("master key %s unusable: %s", path, ex)
            return
        kid = _kid(key)
        self.keys.setdefault(kid, AESGCM(key))
        self.files.setdefault(kid, path)
        if current:
            self.current = kid

    def seal(self, text: str, purpose: str) -> str:
        if not self.current:
            raise SecretError(self.error or "no master key")
        nonce = os.urandom(12)
        ct = self.keys[self.current].encrypt(nonce, text.encode(), b"netmon:" + purpose.encode())
        return f"{PREFIX}{self.current}." + base64.urlsafe_b64encode(nonce + ct).decode().rstrip("=")

    def unseal(self, token: str, purpose: str) -> str:
        try:
            kid, data = token[len(PREFIX):].split(".", 1)
            raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
        except (ValueError, binascii.Error):
            raise SecretError("malformed sealed value") from None
        if kid not in self.keys:
            raise SecretError(f"sealed with an unknown master key ({kid})")
        try:
            return self.keys[kid].decrypt(raw[:12], raw[12:], b"netmon:" + purpose.encode()).decode()
        except InvalidTag:
            raise SecretError("integrity check failed (wrong key, tampered value or moved value)") from None

    def stale(self, token: str) -> bool:
        """Sealed with a key that is not the current one."""
        return not token.startswith(f"{PREFIX}{self.current}.")


_box = None
_lock = threading.Lock()


def box() -> Box:
    global _box
    with _lock:
        if _box is None:
            _box = Box()
        return _box


def reset():
    """Forget the loaded keys (tests, key rotation)."""
    global _box
    with _lock:
        _box = None


def is_sealed(v) -> bool:
    return isinstance(v, str) and v.startswith(PREFIX)


def seal(text: str, purpose: str) -> str:
    return box().seal(text, purpose)


def reveal(v, purpose: str):
    """Plaintext of a stored value: sealed values are decrypted, legacy plaintext passes through.
    None if it cannot be decrypted (logged, never raised into a request)."""
    if not is_sealed(v):
        return v
    try:
        return box().unseal(v, purpose)
    except SecretError as ex:
        log.error("cannot decrypt %s: %s", purpose, ex)
        return None


def file_purpose(path) -> str:
    return "file:" + os.path.basename(path)


def read_file(path):
    """Contents of a secret file (sealed or legacy plaintext), stripped; None if missing or undecryptable."""
    if not path:
        return None
    try:
        text = open(path).read().strip()
    except OSError:
        return None
    return reveal(text, file_purpose(path))


def write_file(path, value: str) -> str:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(seal(value.strip(), file_purpose(path)) + "\n")
    os.replace(path + ".tmp", path)
    return path


def _file_state(path):
    try:
        text = open(path).read().strip()
    except OSError:
        return "missing"
    if not is_sealed(text):
        return "plaintext"
    try:
        box().unseal(text, file_purpose(path))
    except SecretError:
        return "unreadable"
    return "stale" if box().stale(text) else "sealed"


def seal_file(path) -> str:
    """Seal a plaintext file in place, or re-seal one made with an old key. Returns the state it was in."""
    st = _file_state(path)
    if st in ("plaintext", "stale"):
        write_file(path, read_file(path) or "")
    return st


def _rows(conn):
    for r in conn.execute("SELECT id, config FROM channels").fetchall():
        yield "channel", r["config"], "channel", ("UPDATE channels SET config=? WHERE id=?", r["id"])
    for r in conn.execute("SELECT username, totp_secret FROM users WHERE totp_secret IS NOT NULL AND totp_secret != ''").fetchall():
        yield "totp", r["totp_secret"], "totp:" + r["username"], ("UPDATE users SET totp_secret=? WHERE username=?", r["username"])


def _value_state(v, purpose):
    if not is_sealed(v):
        return "plaintext"
    try:
        box().unseal(v, purpose)
    except SecretError:
        return "unreadable"
    return "stale" if box().stale(v) else "sealed"


def _data_files():
    try:
        names = sorted(os.listdir(SECRETS_DIR))
    except OSError:
        return []
    return [os.path.join(SECRETS_DIR, n) for n in names if not n.endswith(".tmp") and os.path.isfile(os.path.join(SECRETS_DIR, n))]


def migrate(conn) -> dict:
    """Seal every plaintext secret the app owns (database values, data/secrets files) and re-seal values made with an
    old key. Undecryptable values are left untouched. Idempotent; runs at startup."""
    done = {"sealed": 0, "resealed": 0, "unreadable": 0}
    b = box()
    if not b.current:
        log.error("secrets not sealed: %s", b.error)
        return done
    for _kind, v, purpose, (sql, ref) in list(_rows(conn)):
        st = _value_state(v, purpose)
        if st in ("plaintext", "stale"):
            conn.execute(sql, (seal(reveal(v, purpose), purpose), ref))
            done["sealed" if st == "plaintext" else "resealed"] += 1
        elif st == "unreadable":
            done["unreadable"] += 1
    conn.commit()
    for p in _data_files():
        st = seal_file(p)
        if st in ("plaintext", "stale"):
            done["sealed" if st == "plaintext" else "resealed"] += 1
        elif st == "unreadable":
            done["unreadable"] += 1
    if done["sealed"] or done["resealed"] or done["unreadable"]:
        log.warning("secrets at rest: %s", done)
    return done


def config_files(cfg):
    """Secret files referenced by the configuration that live outside data/secrets (operator-managed, e.g. the
    read-only /run/secrets mount)."""
    paths = []
    devices = (cfg.raw.get("devices") or []) if hasattr(cfg, "raw") else []
    for s in [*(cfg.get("sites") or []), *devices]:
        paths += [(s.get("block") or {}).get("key_file"), (s.get("snmp") or {}).get("community_file"), (s.get("snmp") or {}).get("v3_file")]
    paths.append((cfg.get("ai") or {}).get("key_file"))
    out = []
    for p in paths:
        if p and os.path.dirname(os.path.abspath(p)) != os.path.abspath(SECRETS_DIR) and p not in out and os.path.exists(p):
            out.append(p)
    return out


def status(conn, cfg=None, extra_files=()) -> dict:
    """Counts per state, without revealing anything."""
    b = box()
    counts = {}
    for kind, v, purpose, _ in _rows(conn):
        st = _value_state(v, purpose)
        counts.setdefault(kind, {}).setdefault(st, 0)
        counts[kind][st] += 1
    for p in _data_files():
        counts.setdefault("file", {}).setdefault(_file_state(p), 0)
        counts["file"][_file_state(p)] += 1
    operator = {}
    for p in [*(config_files(cfg) if cfg is not None else []), *extra_files]:
        if p and os.path.exists(p) and p not in operator:
            operator[p] = _file_state(p)
    return {"source": b.source, "key_id": b.current, "key_file": b.files.get(b.current), "error": b.error,
            "old_keys": sorted(f for k, f in b.files.items() if k != b.current), "counts": counts, "operator_files": operator}


def main(argv):
    """python -m netmon.secretbox (status | genkey | seal FILE...)"""
    if not argv or argv[0] not in ("status", "genkey", "seal"):
        print(main.__doc__)
        return 2
    if argv[0] == "genkey":
        print(new_key_text())
        return 0
    if argv[0] == "seal":
        rc = 0
        for p in argv[1:]:
            st = seal_file(p)
            print(f"{p}: {'sealed' if st == 'plaintext' else 're-sealed' if st == 'stale' else st}")
            rc |= st in ("missing", "unreadable")
        return rc
    from .core import db_connect, load_config
    print(json.dumps(status(db_connect(), load_config()), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
