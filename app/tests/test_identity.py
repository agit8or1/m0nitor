"""Persistent device identity: attribution over time, site isolation, randomized MACs, no automatic merging."""

import pytest

from netmon import identity as idn


@pytest.fixture
def c(conn):
    return conn


T0 = 1_790_000_000


def test_history_survives_ip_change_and_old_events_keep_their_owner(c):
    a = idn.observe(c, "site-a", T0, ip="10.40.0.8", mac="e4:43:4b:00:00:08", hostname="backup-1", source="arp")
    idn.observe(c, "site-a", T0 + 900, ip="10.40.0.8", mac="e4:43:4b:00:00:08", source="arp")
    # the backup server moves to .9; a camera takes .8
    assert idn.observe(c, "site-a", T0 + 86400, ip="10.40.0.9", mac="e4:43:4b:00:00:08", source="arp") == a
    b = idn.observe(c, "site-a", T0 + 90000, ip="10.40.0.8", mac="00:12:34:56:78:9a", hostname="cam-04", source="arp")
    assert b != a
    then = idn.owner_at(c, "site-a", "10.40.0.8", T0 + 600)
    assert then["identity"] == a and then["confidence"] == "high"
    now = idn.owner_at(c, "site-a", "10.40.0.8", T0 + 90000 + 60)
    assert now["identity"] == b
    assert idn.owner_at(c, "site-a", "10.40.0.9", T0 + 86400 + 10)["identity"] == a
    kinds = {(r["kind"], r["value"]) for r in idn.evidence(c, a)}
    assert ("ip", "10.40.0.8") in kinds and ("ip", "10.40.0.9") in kinds
    sugg = c.execute("SELECT kind FROM identity_suggestions").fetchall()
    assert [s["kind"] for s in sugg] == ["moved"]          # a person decides whether the name follows


def test_overlapping_private_addresses_at_two_sites_stay_apart(c):
    a = idn.observe(c, "site-a", T0, ip="10.0.0.5", mac="00:11:22:33:44:55")
    b = idn.observe(c, "site-b", T0, ip="10.0.0.5", mac="66:77:88:99:00:11")
    assert a != b
    assert idn.owner_at(c, "site-a", "10.0.0.5", T0)["identity"] == a
    assert idn.owner_at(c, "site-b", "10.0.0.5", T0)["identity"] == b
    with pytest.raises(ValueError):
        idn.merge(c, a, b, "admin")


def test_same_mac_at_another_site_is_a_suggestion_not_a_merge(c):
    a = idn.observe(c, "site-a", T0, ip="10.0.0.5", mac="00:11:22:33:44:55")
    b = idn.observe(c, "site-b", T0 + 10, ip="10.50.0.5", mac="00:11:22:33:44:55")
    assert a != b
    s = c.execute("SELECT * FROM identity_suggestions").fetchone()
    assert s["kind"] == "same_mac_other_site"


def test_hostname_alone_never_merges(c):
    a = idn.observe(c, "site-a", T0, ip="10.40.0.20", mac="00:aa:00:00:00:01", hostname="nas")
    b = idn.observe(c, "site-a", T0, ip="10.40.0.21", mac="00:aa:00:00:00:02", hostname="nas")
    assert a != b
    assert c.execute("SELECT kind FROM identity_suggestions").fetchone()["kind"] == "same_hostname"
    # factory-default names do not even make a suggestion
    idn.observe(c, "site-a", T0, ip="10.40.0.30", mac="00:aa:00:00:00:03", hostname="ubuntu")
    idn.observe(c, "site-a", T0, ip="10.40.0.31", mac="00:aa:00:00:00:04", hostname="ubuntu")
    assert c.execute("SELECT count(*) FROM identity_suggestions").fetchone()[0] == 1


def test_reused_ip_without_mac_is_probable_not_certain(c):
    a = idn.observe(c, "site-a", T0, ip="10.40.0.40", mac="00:bb:00:00:00:01")
    # three days later only traffic: attached to the previous owner, but inferred
    idn.observe(c, "site-a", T0 + 3 * 86400, ip="10.40.0.40", source="traffic")
    o = idn.owner_at(c, "site-a", "10.40.0.40", T0 + 3 * 86400)
    assert o["identity"] == a and o["confidence"] == "low" and "probable" in o["explain"]
    # a later MAC confirmation upgrades it
    idn.observe(c, "site-a", T0 + 3 * 86400 + 60, ip="10.40.0.40", mac="00:bb:00:00:00:01")
    assert idn.owner_at(c, "site-a", "10.40.0.40", T0 + 3 * 86400 + 60)["confidence"] == "high"


def test_ip_only_identity_learns_its_mac(c):
    a = idn.observe(c, "site-a", T0, ip="10.40.0.50", source="traffic")
    assert idn.owner_at(c, "site-a", "10.40.0.50", T0)["confidence"] == "low"
    assert idn.observe(c, "site-a", T0 + 300, ip="10.40.0.50", mac="00:cc:00:00:00:01") == a
    assert c.execute("SELECT basis FROM identities WHERE id=?", (a,)).fetchone()["basis"] == "mac"


def test_randomized_mac_is_medium_confidence(c):
    assert idn.randomized("da:a1:19:00:00:01") and not idn.randomized("00:11:22:33:44:55")
    a = idn.observe(c, "site-a", T0, ip="10.40.0.60", mac="da:a1:19:00:00:01")
    assert idn.owner_at(c, "site-a", "10.40.0.60", T0)["confidence"] == "medium"
    assert c.execute("SELECT basis FROM identities WHERE id=?", (a,)).fetchone()["basis"] == "random-mac"


def test_two_devices_on_one_address_at_once_is_ambiguous(c):
    idn.observe(c, "site-a", T0, ip="10.40.0.70", mac="00:dd:00:00:00:01")
    idn.observe(c, "site-a", T0 + 60, ip="10.40.0.70", mac="00:dd:00:00:00:02")
    o = idn.owner_at(c, "site-a", "10.40.0.70", T0 + 30)
    assert o["identity"] is None and len(o["ambiguous"]) == 2


def test_unknown_after_long_gap(c):
    idn.observe(c, "site-a", T0, ip="10.40.0.80", mac="00:ee:00:00:00:01")
    assert idn.owner_at(c, "site-a", "10.40.0.80", T0 + 10 * 86400)["confidence"] == "unknown"
    assert idn.owner_at(c, "site-a", "10.40.0.80", T0 - 10 * 86400)["identity"] is None


def test_ipv6_and_mapped_addresses(c):
    a = idn.observe(c, "site-a", T0, ip="2001:db8::10", mac="00:ff:00:00:00:01", source="ndp")
    assert idn.owner_at(c, "site-a", "2001:DB8:0::10", T0)["identity"] == a
    b = idn.observe(c, "site-a", T0, ip="::ffff:10.40.0.90", mac="00:ff:00:00:00:02")
    assert idn.owner_at(c, "site-a", "10.40.0.90", T0)["identity"] == b


def test_merge_separate_and_undo_are_audited(c):
    a = idn.observe(c, "site-a", T0, ip="10.40.0.160", mac="00:14:5e:00:00:01", hostname="ibm-x")
    b = idn.observe(c, "site-a", T0, ip="10.40.0.163", mac="00:14:5e:00:00:02")
    idn.merge(c, a, b, "admin", "one machine, two NICs")
    assert idn.resolve(c, b) == a
    assert idn.owner_at(c, "site-a", "10.40.0.163", T0)["identity"] == a
    # new sightings of the merged MAC land on the kept device
    assert idn.observe(c, "site-a", T0 + 600, ip="10.40.0.163", mac="00:14:5e:00:00:02") == a
    idn.unmerge(c, b, "admin")
    assert idn.resolve(c, b) == b and idn.owner_at(c, "site-a", "10.40.0.163", T0)["identity"] == b
    rows = [r["id"] for r in idn.evidence(c, a) if r["value"] == "ibm-x"]
    new = idn.separate(c, a, rows, "admin", "hostname belongs elsewhere")
    assert [r["value"] for r in idn.evidence(c, new)] == ["ibm-x"]
    acts = [r["action"] for r in c.execute("SELECT action FROM audit ORDER BY id")]
    assert acts == ["identity_merged", "identity_unmerged", "identity_separated"]
    with pytest.raises(ValueError):
        idn.separate(c, new, [r["id"] for r in idn.evidence(c, new)], "admin")   # not all of them


def test_ingest_discovery_traffic_does_not_override_mac_and_counts(c):
    n = idn.ingest_discovery(c, {"site-a": {"10.40.0.8": T0, "10.40.0.99": T0}},
                             {"10.40.0.8": {"mac": "e4:43:4b:00:00:08", "hostname": "", "site": "site-a"}},
                             {"2001:db8::8": {"mac": "e4:43:4b:00:00:08", "hostname": "", "site": "site-a"}},
                             [{"ip": "10.40.0.8", "mac": "e4:43:4b:00:00:08", "hostname": "backup-1", "site": "site-a",
                               "starts": T0 - 100, "ends": T0 + 7100, "type": "dynamic"}], ts=T0)
    assert n == {"arp": 1, "ndp": 1, "dhcp": 1, "traffic": 1}
    a = idn.owner_at(c, "site-a", "10.40.0.8", T0)["identity"]
    assert idn.owner_at(c, "site-a", "2001:db8::8", T0)["identity"] == a      # IPv4 and IPv6 on one device
    assert {r["kind"] for r in idn.evidence(c, a)} == {"ip", "mac", "hostname", "dhcp"}
    assert idn.owner_at(c, "site-a", "10.40.0.99", T0)["confidence"] == "low"


def test_label_names_first_and_uses_site(cfg, c):
    a = idn.observe(c, "site-a", T0, ip="10.40.0.8", mac="e4:43:4b:00:00:08")
    lab = idn.label(c, cfg, "10.40.0.8", ts=T0)
    assert lab["identity"] == a and lab["name"] == "backup-1" and lab["site"] == "site-a"
    idn.rename(c, a, "Backup Server", "admin")
    assert idn.label(c, cfg, "10.40.0.8", ts=T0)["name"] == "Backup Server"


def test_lease_time_parsing():
    from netmon.discovery import _lease_time
    assert _lease_time(1794005992) == 1794005992.0
    assert _lease_time("2026/11/06 10:00:00 UTC") == 1793959200.0
    assert _lease_time("junk") is None and _lease_time("") is None


def test_two_addresses_at_once_is_not_a_move(c):
    a = idn.observe(c, "site-a", T0, ip="10.40.0.251", mac="bc:24:11:28:a0:71")
    assert idn.observe(c, "site-a", T0, ip="10.40.0.82", mac="bc:24:11:28:a0:71") == a
    assert c.execute("SELECT count(*) FROM identity_suggestions").fetchone()[0] == 0
    assert idn.owner_at(c, "site-a", "10.40.0.251", T0)["identity"] == idn.owner_at(c, "site-a", "10.40.0.82", T0)["identity"] == a
    assert [r["action"] for r in c.execute("SELECT action FROM identity_events WHERE identity_id=? ORDER BY id", (a,))] == ["created", "address_added"]
