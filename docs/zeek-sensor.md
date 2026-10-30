# Zeek sensor (optional)

Flow records only cover traffic that crosses the firewall. A Zeek sensor on the monitor host adds what a traffic
**copy** shows it: LAN-to-LAN connections, DNS answers with TTLs, TLS SNI and version (never decrypted content), and
cleartext HTTP request lines. Nothing is captured until you pick a feed below and start the sensor. The Coverage page
shows "awaiting traffic feed" until records arrive and reports Zeek's own capture loss once they do.

The sensor needs a **capture-only interface** on the monitor host: a second NIC with no IP address that receives
the mirrored frames. Pick one feed:

| Option | Sees | Changes needed outside m0nitor |
|---|---|---|
| A. Proxmox bridge mirror | everything on one Proxmox bridge, including VM-to-VM traffic on that host | a port-less bridge + one script and timer on the Proxmox host |
| B. Switch SPAN port | the switch ports you mirror (traffic between physical hosts) | SPAN session on the switch, a cable to a Proxmox NIC, a bridge for it |
| C. Firewall bridge span | frames crossing the firewall's LAN bridge members | OPNsense bridge "span port", a cable to a Proxmox NIC, a bridge for it |

A and B/C can be combined (one sensor per feed, distinguished by `NETMON_ZEEK_SENSOR`). None of them is applied
automatically; m0nitor deploys nothing to other hosts.

## Option A: Proxmox bridge mirror

On the **Proxmox host** (replace `vmbr0` with the bridge your servers use and `105` with the monitor VM's id):

1. Add a port-less bridge for the sensor in `/etc/network/interfaces`, then `ifreload -a`:

       auto vmbr9
       iface vmbr9 inet manual
           bridge-ports none
           bridge-stp off
           bridge-fd 0

2. Give the monitor VM a second NIC on it: `qm set 105 -net1 virtio,bridge=vmbr9,firewall=0`. Its tap device is
   `tap105i1`.
3. Install the mirror: copy `host/pve-mirror.sh` to `/usr/local/sbin/`, and `host/pve-mirror.service` and
   `host/pve-mirror.timer` to `/etc/systemd/system/`. Edit the bridge and tap in the service, then
   `systemctl daemon-reload && systemctl enable --now pve-mirror.timer`.
   The script mirrors each bridge port's ingress (plus the host's own egress) into the tap. It is idempotent, follows
   new VMs and sensor restarts, and refuses a sensor tap that is a member of the mirrored bridge.
   To undo: `systemctl disable --now pve-mirror.timer && pve-mirror.sh --remove vmbr0`.

Mirroring costs some CPU on the Proxmox host in proportion to bridge traffic.

## Option B: switch SPAN port

1. On the switch, mirror the ports (or VLAN) you want to watch to a free port. Cable it to a spare NIC on the Proxmox host.
2. On the Proxmox host, bridge that NIC alone with MAC learning off, so every frame reaches the sensor:

       auto vmbr9
       iface vmbr9 inet manual
           bridge-ports enp5s0
           bridge-stp off
           bridge-fd 0
           bridge-ageing 0

3. `qm set 105 -net1 virtio,bridge=vmbr9,firewall=0`.

A SPAN port drops frames when the mirrored ports together exceed its speed.

## Option C: OPNsense bridge span port

1. In OPNsense: **Interfaces → Other Types → Bridge**, edit the LAN bridge, show advanced options and set
   **Span port** to a free physical interface. That interface must not be a bridge member and has no IP address.
   This changes the production bridge configuration, so schedule it.
2. Cable that port to a spare NIC on the Proxmox host. Then do steps 2 and 3 of option B.

The span port receives every frame that crosses the bridge between its members. Traffic between VMs on the same
Proxmox host never reaches the firewall, so this feed cannot see it; use option A for that.

## On the monitor host (all options)

1. Bring the capture interface up without an address, e.g. `/etc/netplan/60-zeek.yaml` (then `netplan apply`):

       network:
         version: 2
         ethernets:
           ens19: {dhcp4: false, dhcp6: false, accept-ra: false, link-local: [], optional: true}

2. In `app/.env`: `NETMON_ZEEK_IFACE=ens19` (optional: `NETMON_ZEEK_SENSOR=pve1`).
3. Start the sensor: `cd app && docker compose --profile zeek up -d`. It runs `zeek/zeek` 9.0.0 (pinned by digest),
   read-only, with only the packet-capture capabilities. It writes JSON logs to the `zeek-logs` volume, which the app
   mounts read-only and ingests into ClickHouse (14-day retention). Rotated files are deleted after a day.
4. Check the Coverage page: "Zeek sensor (internal traffic)" turns healthy once connection records arrive.

To stop it: `docker compose --profile zeek stop zeek`.
