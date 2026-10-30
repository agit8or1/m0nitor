"""ClickHouse tables owned by netmon (database `netmon`). Idempotent: run at startup and by `install`.

Akvorado owns `default.flows*`; everything here is netmon's own log/event storage. Retention is per table
(TTL); DNS retention is configurable (Settings -> DNS) because query names are sensitive.
"""

TABLES = {
    "fw_events": """CREATE TABLE IF NOT EXISTS netmon.fw_events (`ts` DateTime64(3, 'UTC'), `received` DateTime('UTC'),
        `site` LowCardinality(String), `rulenr` UInt32, `rid` String, `iface` LowCardinality(String), `reason` LowCardinality(String),
        `action` LowCardinality(String), `dir` LowCardinality(String), `ipver` UInt8, `proto` LowCardinality(String), `src` IPv6, `dst` IPv6,
        `sport` UInt16, `dport` UInt16, `length` UInt32, `tcpflags` LowCardinality(String))
        ENGINE = MergeTree PARTITION BY toDate(ts) ORDER BY (site, action, ts) TTL toDateTime(ts) + toIntervalDay(14)
        SETTINGS ttl_only_drop_parts = 1""",
    "ids_events": """CREATE TABLE IF NOT EXISTS netmon.ids_events (`ts` DateTime64(3, 'UTC'), `received` DateTime('UTC'),
        `site` LowCardinality(String), `sensor` LowCardinality(String), `sig_id` UInt32, `gid` UInt32, `rev` UInt32, `signature` String,
        `category` LowCardinality(String), `severity` UInt8, `action` LowCardinality(String), `proto` LowCardinality(String), `src` IPv6,
        `dst` IPv6, `sport` UInt16, `dport` UInt16, `iface` LowCardinality(String), `event_type` LowCardinality(String), `flow_id` UInt64,
        `raw` String CODEC(ZSTD(3)))
        ENGINE = MergeTree PARTITION BY toYYYYMM(ts) ORDER BY (site, ts) TTL toDateTime(ts) + toIntervalDay(90)""",
    "sys_events": """CREATE TABLE IF NOT EXISTS netmon.sys_events (`ts` DateTime64(3, 'UTC'), `received` DateTime('UTC'),
        `site` LowCardinality(String), `app` LowCardinality(String), `severity` UInt8, `kind` LowCardinality(String),
        `message` String CODEC(ZSTD(3)))
        ENGINE = MergeTree PARTITION BY toYYYYMM(ts) ORDER BY (site, app, ts) TTL toDateTime(ts) + toIntervalDay(30)""",
    "fw_hourly": """CREATE TABLE IF NOT EXISTS netmon.fw_hourly (`hour` DateTime('UTC'), `site` LowCardinality(String),
        `action` LowCardinality(String), `dir` LowCardinality(String), `iface` LowCardinality(String), `proto` LowCardinality(String),
        `dport` UInt16, `events` UInt64, `bytes` UInt64)
        ENGINE = SummingMergeTree PARTITION BY toYYYYMM(hour) ORDER BY (site, action, dir, iface, proto, dport, hour)
        TTL hour + toIntervalDay(365)""",
    "fw_hourly_mv": """CREATE MATERIALIZED VIEW IF NOT EXISTS netmon.fw_hourly_mv TO netmon.fw_hourly AS
        SELECT toStartOfHour(ts) AS hour, site, action, dir, iface, proto, dport, count() AS events, sum(length) AS bytes
        FROM netmon.fw_events GROUP BY hour, site, action, dir, iface, proto, dport""",
    # DNS: resolver query logs (Unbound log-replies: no answers) or Zeek dns.log (answers + TTLs)
    "dns_events": """CREATE TABLE IF NOT EXISTS netmon.dns_events (`ts` DateTime64(3, 'UTC'), `received` DateTime('UTC'),
        `site` LowCardinality(String), `sensor` LowCardinality(String), `source` LowCardinality(String), `client` IPv6,
        `query` String, `qtype` LowCardinality(String), `rcode` LowCardinality(String), `answers` Array(String), `ttls` Array(UInt32),
        `resolver` IPv6, `uid` String)
        ENGINE = MergeTree PARTITION BY toDate(ts) ORDER BY (site, client, ts) TTL toDateTime(ts) + toIntervalDay({dns_days})
        SETTINGS ttl_only_drop_parts = 1""",
    # answers netmon got for names in the resolver query log (dnsresolve.py): remote address -> FQDN
    "dns_resolved": """CREATE TABLE IF NOT EXISTS netmon.dns_resolved (`ts` DateTime64(3, 'UTC'), `site` LowCardinality(String),
        `query` String, `qtype` LowCardinality(String), `addr` IPv6, `ttl` UInt32, `clients` Array(IPv6), `resolver` String)
        ENGINE = MergeTree PARTITION BY toDate(ts) ORDER BY (site, addr, ts) TTL toDateTime(ts) + toIntervalDay({dns_days})
        SETTINGS ttl_only_drop_parts = 1""",
    # Zeek (optional internal sensor): conn, tls, http, notice, capture health
    "zeek_conn": """CREATE TABLE IF NOT EXISTS netmon.zeek_conn (`ts` DateTime64(3, 'UTC'), `received` DateTime('UTC'),
        `site` LowCardinality(String), `sensor` LowCardinality(String), `uid` String, `proto` LowCardinality(String),
        `service` LowCardinality(String), `orig_h` IPv6, `orig_p` UInt16, `resp_h` IPv6, `resp_p` UInt16, `duration` Float32,
        `orig_bytes` UInt64, `resp_bytes` UInt64, `conn_state` LowCardinality(String), `local_orig` UInt8, `local_resp` UInt8,
        `missed_bytes` UInt64, `history` String)
        ENGINE = MergeTree PARTITION BY toDate(ts) ORDER BY (site, sensor, ts) TTL toDateTime(ts) + toIntervalDay(14)
        SETTINGS ttl_only_drop_parts = 1""",
    "zeek_tls": """CREATE TABLE IF NOT EXISTS netmon.zeek_tls (`ts` DateTime64(3, 'UTC'), `received` DateTime('UTC'),
        `site` LowCardinality(String), `sensor` LowCardinality(String), `uid` String, `orig_h` IPv6, `resp_h` IPv6, `resp_p` UInt16,
        `version` LowCardinality(String), `server_name` String, `established` UInt8, `validation_status` String)
        ENGINE = MergeTree PARTITION BY toDate(ts) ORDER BY (site, ts) TTL toDateTime(ts) + toIntervalDay(14)""",
    "zeek_http": """CREATE TABLE IF NOT EXISTS netmon.zeek_http (`ts` DateTime64(3, 'UTC'), `received` DateTime('UTC'),
        `site` LowCardinality(String), `sensor` LowCardinality(String), `uid` String, `orig_h` IPv6, `resp_h` IPv6, `resp_p` UInt16,
        `method` LowCardinality(String), `host` String, `uri` String, `status_code` UInt16, `user_agent` String)
        ENGINE = MergeTree PARTITION BY toDate(ts) ORDER BY (site, ts) TTL toDateTime(ts) + toIntervalDay(14)""",
    "zeek_notice": """CREATE TABLE IF NOT EXISTS netmon.zeek_notice (`ts` DateTime64(3, 'UTC'), `received` DateTime('UTC'),
        `site` LowCardinality(String), `sensor` LowCardinality(String), `note` LowCardinality(String), `msg` String, `src` IPv6,
        `dst` IPv6, `p` UInt16)
        ENGINE = MergeTree PARTITION BY toYYYYMM(ts) ORDER BY (site, ts) TTL toDateTime(ts) + toIntervalDay(90)""",
    "zeek_stats": """CREATE TABLE IF NOT EXISTS netmon.zeek_stats (`ts` DateTime64(3, 'UTC'), `received` DateTime('UTC'),
        `site` LowCardinality(String), `sensor` LowCardinality(String), `kind` LowCardinality(String), `percent_lost` Float32,
        `gaps` UInt64, `acks` UInt64, `pkts_proc` UInt64, `pkts_dropped` UInt64)
        ENGINE = MergeTree PARTITION BY toYYYYMM(ts) ORDER BY (site, sensor, ts) TTL toDateTime(ts) + toIntervalDay(30)""",
    # server/application security logs forwarded by syslog (sshd, sudo, su, ...): actual events, never inferred from flows
    "auth_events": """CREATE TABLE IF NOT EXISTS netmon.auth_events (`ts` DateTime64(3, 'UTC'), `received` DateTime('UTC'),
        `site` LowCardinality(String), `host` LowCardinality(String), `sender` IPv6, `app` LowCardinality(String),
        `event` LowCardinality(String), `user` String, `src` IPv6, `method` LowCardinality(String), `message` String CODEC(ZSTD(3)))
        ENGINE = MergeTree PARTITION BY toYYYYMM(ts) ORDER BY (site, host, ts) TTL toDateTime(ts) + toIntervalDay(90)""",
}


def ensure(ch, dns_days=7):
    """Create the database and any missing table; returns the names created or verified."""
    ch.query("CREATE DATABASE IF NOT EXISTS netmon", {})
    done = []
    for name, sql in TABLES.items():
        ch.query(sql.replace("{dns_days}", str(int(dns_days))), {})
        done.append(name)
    return done


def set_dns_retention(ch, days):
    ch.query(f"ALTER TABLE netmon.dns_events MODIFY TTL toDateTime(ts) + toIntervalDay({int(days)})", {})
    ch.query(f"ALTER TABLE netmon.dns_resolved MODIFY TTL toDateTime(ts) + toIntervalDay({int(days)})", {})


def statements(dns_days=7):
    return ["CREATE DATABASE IF NOT EXISTS netmon"] + [s.replace("{dns_days}", str(int(dns_days))) for s in TABLES.values()]


if __name__ == "__main__":   # python -m netmon.schema | clickhouse-client --multiquery  (run as a ClickHouse admin)
    import sys
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    print(";\n".join(" ".join(x.split()) for x in statements(days)) + ";")
