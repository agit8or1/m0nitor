"""Secrets at rest: sealing, purpose binding, migration of legacy plaintext, key rotation, no leaks in status."""
import base64
import json
import os

import pytest

from netmon import secretbox
from netmon.auth import init as auth_init


@pytest.fixture
def box(tmp_path, monkeypatch):
    key = tmp_path / "keys" / "master.key"
    key.parent.mkdir()
    key.write_text(base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setenv("NETMON_MASTER_KEY_FILE", str(key))
    monkeypatch.setattr(secretbox, "SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setattr(secretbox, "DATA_DIR", str(tmp_path))
    secretbox.reset()
    yield key
    secretbox.reset()


def test_roundtrip_and_purpose_binding(box):
    t = secretbox.seal("hunter2-very-secret", "channel")
    assert secretbox.is_sealed(t) and "hunter2" not in t
    assert secretbox.reveal(t, "channel") == "hunter2-very-secret"
    assert secretbox.reveal(t, "totp:alice") is None            # moved to another place: refused
    assert secretbox.reveal("legacy-plain", "channel") == "legacy-plain"
    assert secretbox.seal("x", "channel") != secretbox.seal("x", "channel")   # fresh nonce every time


def test_tampered_value_rejected(box):
    t = secretbox.seal("abc", "channel")
    raw = bytearray(base64.urlsafe_b64decode(t.split(".")[2] + "=="))
    raw[-1] ^= 1
    bad = ".".join(t.split(".")[:2]) + "." + base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
    assert secretbox.reveal(bad, "channel") is None


def test_files_sealed_and_readable(box, tmp_path):
    p = secretbox.write_file(str(tmp_path / "secrets" / "s1-snmp"), "  community-xyz \n")
    assert "community-xyz" not in open(p).read()
    assert oct(os.stat(p).st_mode & 0o777) == "0o600"
    assert secretbox.read_file(p) == "community-xyz"
    os.rename(p, str(tmp_path / "secrets" / "s2-snmp"))             # file swapped under another name: refused
    assert secretbox.read_file(str(tmp_path / "secrets" / "s2-snmp")) is None
    assert secretbox.read_file(str(tmp_path / "nope")) is None


def test_migrate_seals_legacy_plaintext(box, tmp_path, conn):
    auth_init(conn)
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "openai_api_key").write_text("sk-legacy-plaintext-key\n")
    conn.execute("INSERT INTO users(username,pw_hash,role,created_at,totp_secret) VALUES ('alice','x','admin',0,'JBSWY3DPEHPK3PXP')")
    conn.execute("INSERT INTO channels(name,type,config,min_severity,categories,created_by,created_at) VALUES "
                 "('c','slack',?,'medium','[]','alice',0)", (json.dumps({"url": "https://hooks.example/abc"}),))
    conn.commit()
    done = secretbox.migrate(conn)
    assert done["sealed"] == 3 and done["unreadable"] == 0
    assert secretbox.migrate(conn)["sealed"] == 0                  # idempotent
    raw = conn.execute("SELECT config FROM channels").fetchone()[0]
    assert secretbox.is_sealed(raw) and "hooks.example" not in raw
    from netmon.notify import channel_config
    assert channel_config({"config": raw}) == {"url": "https://hooks.example/abc"}
    from netmon import auth
    stored = conn.execute("SELECT totp_secret FROM users").fetchone()[0]
    assert secretbox.is_sealed(stored) and auth.totp_secret_of(stored, "alice") == "JBSWY3DPEHPK3PXP"
    assert "sk-legacy" not in open(tmp_path / "secrets" / "openai_api_key").read()
    assert secretbox.read_file(str(tmp_path / "secrets" / "openai_api_key")) == "sk-legacy-plaintext-key"
    st = secretbox.status(conn)
    assert st["source"] == "mounted" and st["counts"]["channel"] == {"sealed": 1}
    assert "hooks.example" not in json.dumps(st) and "JBSWY3" not in json.dumps(st) and "sk-legacy" not in json.dumps(st)


def test_key_rotation_reseals_with_new_key(box, tmp_path, conn):
    auth_init(conn)
    conn.execute("INSERT INTO users(username,pw_hash,role,created_at,totp_secret) VALUES ('bob','x','admin',0,?)",
                 (secretbox.seal("SEED", "totp:bob"),))
    conn.commit()
    old_kid = secretbox.box().current
    os.rename(box, str(box) + ".old")
    box.write_text(secretbox.new_key_text())
    secretbox.reset()
    assert secretbox.box().current != old_kid
    assert secretbox.migrate(conn)["resealed"] == 1
    os.remove(str(box) + ".old")
    secretbox.reset()
    from netmon import auth
    assert auth.totp_secret_of(conn.execute("SELECT totp_secret FROM users").fetchone()[0], "bob") == "SEED"


def test_lost_key_reports_unreadable_without_crashing(box, tmp_path, conn):
    auth_init(conn)
    conn.execute("INSERT INTO channels(name,type,config,min_severity,categories,created_by,created_at) VALUES "
                 "('c','slack',?,'medium','[]','x',0)", (secretbox.seal('{"url": "https://h.example/x"}', "channel"),))
    conn.commit()
    box.write_text(secretbox.new_key_text())                       # key replaced, old one gone
    secretbox.reset()
    assert secretbox.migrate(conn)["unreadable"] == 1
    from netmon.notify import channel_config
    with pytest.raises(RuntimeError, match="cannot be decrypted"):
        channel_config(conn.execute("SELECT config FROM channels").fetchone())


def test_fallback_key_in_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("NETMON_MASTER_KEY_FILE", str(tmp_path / "absent" / "master.key"))
    monkeypatch.setattr(secretbox, "DATA_DIR", str(tmp_path))
    secretbox.reset()
    try:
        b = secretbox.box()
        assert b.source == "data-dir" and b.current
        assert oct(os.stat(tmp_path / "master.key").st_mode & 0o777) == "0o600"
        assert secretbox.reveal(secretbox.seal("v", "p"), "p") == "v"
    finally:
        secretbox.reset()


def test_block_and_snmp_readers_accept_sealed_files(box, tmp_path):
    from netmon.block import read_key
    from netmon.counters import auth_args
    k = secretbox.write_file(str(tmp_path / "secrets" / "s1-block.key"), "key=AAA\nsecret=BBB")
    assert read_key(k) == ("AAA", "BBB")
    c = secretbox.write_file(str(tmp_path / "secrets" / "s1-snmp"), "public-ro")
    assert auth_args({"community_file": c}) == ["-v2c", "-c", "public-ro"]
    v3 = secretbox.write_file(str(tmp_path / "secrets" / "d1-snmpv3.json"), json.dumps({"auth": "a" * 8, "priv": "p" * 8}))
    args = auth_args({"version": "v3", "user": "u", "v3_file": v3})
    assert "a" * 8 in args and "p" * 8 in args
    plain = tmp_path / "op.key"
    plain.write_text("legacy:plain\n")                              # operator file not sealed yet: still works
    assert read_key(str(plain)) == ("legacy", "plain")


def test_cli_seal_in_place(box, tmp_path, capsys):
    f = tmp_path / "opnsense_block.key"
    f.write_text("k:s\n")
    assert secretbox.main(["seal", str(f)]) == 0
    assert "sealed" in capsys.readouterr().out
    assert "k:s" not in f.read_text() and secretbox.read_file(str(f)) == "k:s"
    assert secretbox.main(["seal", str(f)]) == 0                    # second run: already sealed, unchanged
