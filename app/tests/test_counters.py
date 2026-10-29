from netmon.counters import rates


def test_rates_gaps_on_reset_and_missing_samples():
    s = [(0, 0, 0), (10, 1250, 2500), (20, 2500, 5000), (30, 100, 100), (40, 1350, 1350), (100, 9000, 9000), (110, 10250, 10250)]
    r = rates(s, 10)
    assert r[0][1] == 1000 and r[0][2] == 2000          # 1250 B / 10 s = 1000 bit/s
    assert r[2][1] is None                               # counter went backwards -> gap
    assert r[3][1] == 1000
    assert r[4][1] is None                               # 60 s gap > 3x interval -> gap, not averaged
    assert r[5][1] == 1000
