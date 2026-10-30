#!/bin/bash
# Zeek on a capture-only interface (no IP address) fed by a mirror: see docs/zeek-sensor.md for the three feed options.
set -eu
: "${ZEEK_IFACE:?set NETMON_ZEEK_IFACE to the capture-only interface}"
SENSOR="${ZEEK_SENSOR:-mirror}"
case "$SENSOR" in *[!A-Za-z0-9_-]*) echo "ZEEK_SENSOR may use letters, digits, - and _ only" >&2; exit 1;; esac
mkdir -p "/logs/$SENSOR" && cd "/logs/$SENSOR"
( while sleep 900; do find "/logs/$SENSOR" -maxdepth 1 -name '*.*-*-*-*-*-*.log' -mmin +1440 -delete; done ) &
exec zeek -C -i "$ZEEK_IFACE" local /etc/netmon/netmon.zeek
