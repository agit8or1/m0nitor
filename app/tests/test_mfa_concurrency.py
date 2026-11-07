"""Second-factor single use under real database concurrency.

Every worker thread opens its own SQLite connection to the same WAL database file (as the app's request threads do via
ThreadLocalDB) and all of them are released together by a barrier, so validations of one factor or one challenge really
overlap. Several rounds per test make an interleaving that a read-then-update implementation loses very likely; the old
code (separate read and unconditional update) produced several successes per round here.
"""
import hashlib
import json
import threading
import time

import pytest

from netmon import auth
from netmon.core import db_connect

THREADS = 8
ROUNDS = 15


@pytest.fixture
def dbpath(tmp_path):
    p = str(tmp_path / "mfa.db")
    c = db_connect(p)
    auth.init(c)
    c.close()
    return p


def add_user(path, name, codes=(), secret=None):
    c = db_connect(path)
    secret = secret or auth.totp_new_secret()
    c.execute("INSERT OR REPLACE INTO users(username,pw_hash,role,created_at,totp_secret,totp_enabled,totp_last,recovery) "
              "VALUES (?,?,?,?,?,1,0,?)", (name, "x", "viewer", time.time(), auth.totp_seal(secret, name),
                                           json.dumps([hashlib.sha256(x.encode()).hexdigest() for x in codes])))
    c.commit()
    c.close()
    return secret


def race(path, fn, args_list):
    """Run fn(conn, *args) in parallel threads, one connection each, all released at once. Returns results in order."""
    barrier = threading.Barrier(len(args_list))
    out, errs = [None] * len(args_list), []

    def work(i, args):
        conn = db_connect(path)
        try:
            barrier.wait(timeout=10)
            out[i] = fn(conn, *args)
        except Exception as ex:   # surfaced below: no worker may crash
            errs.append(ex)
        finally:
            conn.close()
    ts = [threading.Thread(target=work, args=(i, a)) for i, a in enumerate(args_list)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    assert not errs, errs
    return out


def current_code(secret):
    return auth._hotp(secret, int(time.time() // 30))


def sessions(path, user):
    c = db_connect(path)
    n = c.execute("SELECT count(*) FROM sessions WHERE username=?", (user,)).fetchone()[0]
    c.close()
    return n


def test_same_recovery_code_concurrently_exactly_one_succeeds(dbpath):
    for rnd in range(ROUNDS):
        codes = [f"{rnd:03x}abc-{i:06x}" for i in range(4)]
        add_user(dbpath, "rc", codes)
        res = race(dbpath, auth.use_recovery, [("rc", codes[0])] * THREADS)
        assert res.count(True) == 1, (rnd, res)
        c = db_connect(dbpath)
        left = json.loads(c.execute("SELECT recovery FROM users WHERE username='rc'").fetchone()[0])
        c.close()
        assert len(left) == 3 and hashlib.sha256(codes[0].encode()).hexdigest() not in left


def test_different_recovery_codes_concurrently_all_succeed(dbpath):
    """The compare-and-swap retries when another code was consumed at the same moment: nothing is lost or refused."""
    codes = [f"aaa{i:03x}-bbbbbb" for i in range(THREADS + 2)]
    add_user(dbpath, "rc2", codes)
    res = race(dbpath, auth.use_recovery, [("rc2", x) for x in codes[:THREADS]])
    assert res == [True] * THREADS
    c = db_connect(dbpath)
    left = json.loads(c.execute("SELECT recovery FROM users WHERE username='rc2'").fetchone()[0])
    c.close()
    assert sorted(left) == sorted(hashlib.sha256(x.encode()).hexdigest() for x in codes[THREADS:])


def test_same_totp_timestep_concurrently_exactly_one_succeeds(dbpath):
    secret = add_user(dbpath, "tp")
    for rnd in range(ROUNDS):
        c = db_connect(dbpath)
        c.execute("UPDATE users SET totp_last=0 WHERE username='tp'")   # fresh round: the timestep is unused again
        c.commit()
        c.close()
        code = current_code(secret)
        res = race(dbpath, auth.use_totp, [("tp", code)] * THREADS)
        assert res.count(True) == 1, (rnd, res)


def test_sequential_replay_fails(dbpath):
    secret = add_user(dbpath, "seq", ["111111-222222"])
    c = db_connect(dbpath)
    code = current_code(secret)
    assert auth.verify_second_factor(c, "seq", code) == "totp"
    assert auth.verify_second_factor(c, "seq", code) is None          # same timestep again
    assert auth.verify_second_factor(c, "seq", "111111-222222") == "recovery"
    assert auth.verify_second_factor(c, "seq", "111111-222222") is None
    assert auth.verify_second_factor(c, "seq", "000000") is None


def _complete(conn, token, code):
    return auth.complete_mfa(conn, token, code, "198.51.100.7", "test")[0]


def test_same_challenge_concurrently_issues_exactly_one_session(dbpath):
    """Each thread brings a *different* valid recovery code, so only the challenge itself can stop duplicate sessions."""
    for rnd in range(ROUNDS):
        user = f"pc{rnd}"
        codes = [f"{rnd:03x}{i:03x}-cccccc" for i in range(THREADS)]
        add_user(dbpath, user, codes)
        c = db_connect(dbpath)
        tok = auth.start_mfa(c, user, "198.51.100.7", "/")
        c.close()
        res = race(dbpath, _complete, [(tok, x) for x in codes])
        assert res.count("ok") == 1, (rnd, res)
        assert set(res) <= {"ok", "busy", "invalid"}, res
        assert sessions(dbpath, user) == 1
        c = db_connect(dbpath)
        assert auth.pending_mfa(c, tok) is None                          # the challenge is gone
        c.close()


def test_same_challenge_same_totp_concurrently_one_session(dbpath):
    for rnd in range(ROUNDS):
        user = f"pt{rnd}"
        secret = add_user(dbpath, user)
        c = db_connect(dbpath)
        tok = auth.start_mfa(c, user, "198.51.100.7", "/")
        c.close()
        res = race(dbpath, _complete, [(tok, current_code(secret))] * THREADS)
        assert res.count("ok") == 1, (rnd, res)
        assert sessions(dbpath, user) == 1


def test_completed_challenge_cannot_be_reused(dbpath):
    secret = add_user(dbpath, "reuse", ["dddddd-eeeeee"])
    c = db_connect(dbpath)
    tok = auth.start_mfa(c, "reuse", "198.51.100.7", "/x")
    st, info = auth.complete_mfa(c, tok, current_code(secret), "198.51.100.7", "t")
    assert st == "ok" and info["next"] == "/x" and info["method"] == "totp" and auth.session_user(c, info["token"])[0] == "reuse"
    assert auth.complete_mfa(c, tok, "dddddd-eeeeee", "198.51.100.7", "t")[0] == "invalid"
    assert sessions(dbpath, "reuse") == 1
    # the recovery code was not touched by the refused attempt
    assert auth.use_recovery(c, "reuse", "dddddd-eeeeee") is True


def test_invalid_and_expired_challenges_fail(dbpath):
    secret = add_user(dbpath, "exp")
    c = db_connect(dbpath)
    assert auth.complete_mfa(c, None, "123456", "ip", "ua")[0] == "invalid"
    assert auth.complete_mfa(c, "no-such-token", current_code(secret), "ip", "ua")[0] == "invalid"
    tok = auth.start_mfa(c, "exp", "ip", "/")
    c.execute("UPDATE mfa_pending SET expires_at=? WHERE token_hash=?", (time.time() - 1, auth._th(tok)))
    c.commit()
    assert auth.complete_mfa(c, tok, current_code(secret), "ip", "ua")[0] == "invalid"
    assert sessions(dbpath, "exp") == 0
    # an expired challenge does not burn the factor: the same code still works with a fresh challenge
    tok2 = auth.start_mfa(c, "exp", "ip", "/")
    assert auth.complete_mfa(c, tok2, current_code(secret), "ip", "ua")[0] == "ok"


def test_wrong_code_releases_the_challenge_for_a_retry(dbpath):
    secret = add_user(dbpath, "retry")
    c = db_connect(dbpath)
    tok = auth.start_mfa(c, "retry", "ip", "/")
    assert auth.complete_mfa(c, tok, "000000", "ip", "ua")[0] == "bad"
    assert auth.complete_mfa(c, tok, current_code(secret), "ip", "ua")[0] == "ok"


def test_claimed_challenge_is_busy_and_stale_claim_can_be_taken_over(dbpath):
    secret = add_user(dbpath, "busy")
    c = db_connect(dbpath)
    tok = auth.start_mfa(c, "busy", "ip", "/")
    row, claim = auth.claim_mfa(c, tok)            # another request is mid-validation
    assert row and claim
    assert auth.complete_mfa(c, tok, current_code(secret), "ip", "ua")[0] == "busy"
    assert sessions(dbpath, "busy") == 0
    # the holder crashed: after CLAIM_TTL another request may take over; the old holder can then no longer consume it
    c.execute("UPDATE mfa_pending SET claimed_at=? WHERE token_hash=?", (time.time() - auth.CLAIM_TTL - 1, auth._th(tok)))
    c.commit()
    assert auth.complete_mfa(c, tok, current_code(secret), "ip", "ua")[0] == "ok"
    assert auth.consume_mfa(c, tok, claim) is False
    assert sessions(dbpath, "busy") == 1


def test_different_users_authenticate_concurrently(dbpath):
    """Per-user rows, no global lock: simultaneous logins of different users all succeed, one session each."""
    users = [f"u{i}" for i in range(THREADS)]
    secrets_ = {u: add_user(dbpath, u) for u in users}
    c = db_connect(dbpath)
    toks = {u: auth.start_mfa(c, u, "ip", "/") for u in users}
    c.close()
    res = race(dbpath, _complete, [(toks[u], current_code(secrets_[u])) for u in users])
    assert res == ["ok"] * THREADS
    assert all(sessions(dbpath, u) == 1 for u in users)
