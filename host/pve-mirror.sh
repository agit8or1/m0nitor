#!/bin/sh
# Mirror the traffic of one Linux bridge on a Proxmox VE host into a VM NIC: the netmon Zeek sensor's capture-only
# interface (docs/zeek-sensor.md, option A). Runs ON THE PROXMOX HOST as root, from pve-mirror.timer; idempotent.
#
#   pve-mirror.sh <bridge> <tap>            e.g. pve-mirror.sh vmbr0 tap105i1   (tap<vmid>i<n> of the sensor NIC)
#   pve-mirror.sh --remove <bridge> <tap>   remove every mirror this script added
#
# Every frame entering the bridge enters through exactly one port, so mirroring each port's ingress (plus the bridge
# device's own egress, for traffic the host itself sends) copies each frame once. The sensor NIC must sit on a
# separate, port-less bridge (e.g. vmbr9), never on <bridge> itself. Filters use preference 49 and are tagged by it.
set -eu
PREF=49
if [ "${1:-}" = "--remove" ]; then
  BR=$2
  for p in /sys/class/net/"$BR"/brif/* "/sys/class/net/$BR"; do
    dev=$(basename "$p")
    tc filter del dev "$dev" ingress pref $PREF 2>/dev/null || true
    tc filter del dev "$dev" egress pref $PREF 2>/dev/null || true
  done
  rm -f "/run/pve-mirror.$BR"
  exit 0
fi
BR=$1 TAP=$2
[ -d "/sys/class/net/$BR/brif" ] || { echo "no bridge $BR" >&2; exit 1; }
[ ! -e "/sys/class/net/$BR/brif/$TAP" ] || { echo "$TAP is a port of $BR: put the sensor NIC on a separate bridge" >&2; exit 1; }
[ -e "/sys/class/net/$TAP" ] || exit 0          # sensor VM not running: nothing to do
IDX=$(cat "/sys/class/net/$TAP/ifindex")
# the sensor VM restarted (new tap ifindex): drop the stale mirrors first
if [ "$(cat "/run/pve-mirror.$BR" 2>/dev/null || true)" != "$TAP:$IDX" ]; then
  "$0" --remove "$BR"
  echo "$TAP:$IDX" > "/run/pve-mirror.$BR"
fi
add() {   # add <dev> <ingress|egress>
  tc qdisc show dev "$1" | grep -q clsact || tc qdisc add dev "$1" clsact
  tc filter show dev "$1" "$2" | grep -q "pref $PREF " ||
    tc filter add dev "$1" "$2" pref $PREF matchall action mirred egress mirror dev "$TAP"
}
for p in /sys/class/net/"$BR"/brif/*; do add "$(basename "$p")" ingress; done
add "$BR" egress
