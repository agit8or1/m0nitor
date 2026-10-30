# netmon Zeek sensor policy: JSON logs, hourly rotation (run.sh deletes rotated files after a day; netmon has
# already ingested them into ClickHouse by then). No TLS interception: ssl.log carries SNI/version only.
@load policy/tuning/json-logs
redef Log::default_rotation_interval = 1 hr;
