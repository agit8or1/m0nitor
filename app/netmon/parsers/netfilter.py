"""Linux netfilter kernel log lines (iptables LOG / nftables log): Linux, VyOS, EdgeOS, UniFi, OpenWrt, DD-WRT.

  [WAN_IN-default-D]IN=eth0 OUT=eth1 MAC=.. SRC=198.51.100.7 DST=10.0.0.5 LEN=60 ... PROTO=TCP SPT=51515 DPT=22 ...
The kernel line has no action field. The action comes only from the operator's / vendor's log prefix:
  UniFi / EdgeOS / VyOS rule prefixes ending in -A (accept), -D (drop), -R (reject)
  words in the prefix: DROP, DENY, REJECT, BLOCK / ACCEPT, ALLOW, PASS (fw4: 'drop wan in: ', 'reject wan out: ')
Without one the action is 'unknown' and the line never counts as a firewall block.
"""
import re

from . import action_of, direction, event, ip, num

RE_NF = re.compile(r"(?<![A-Za-z0-9_])IN=(\S*) OUT=(\S*) .*?SRC=(\S+) DST=(\S+) .*?PROTO=(\S+)(.*)$")
RE_PFX_SUFFIX = re.compile(r"-([ADR])\]?\s*$")
RE_PFX_WORD = re.compile(r"\b(drop|deny|reject|block|accept|allow|pass)\b", re.I)
RE_UPTIME = re.compile(r"^\[\s*\d+\.\d+\]\s*")


def prefix_action(prefix):
    m = RE_PFX_SUFFIX.search(prefix)
    if m:
        return {"A": "allow", "D": "block", "R": "block"}[m.group(1)]
    m = RE_PFX_WORD.search(prefix)
    return action_of(m.group(1)) if m else "unknown"


def parse(raw, app, msg, dev):
    m = RE_NF.search(msg)
    if not m:
        return None
    iface_in, iface_out, src, dst, prot, rest = m.groups()
    pre = RE_UPTIME.sub("", msg[:m.start()].strip())
    f = dict(x.split("=", 1) for x in rest.split() if "=" in x)
    act = prefix_action(pre)
    sp, dp = num(f.get("SPT")), num(f.get("DPT"))
    return [event("traffic", action=act, src=ip(src), dst=ip(dst), sport=sp, dport=dp, proto=prot.lower(),
                  iface_in=iface_in, iface_out=iface_out, rule=pre.strip("[]: ")[:200],
                  dir=direction(dev, iface_in, iface_out), bytes=num(f.get("LEN")), packets=1, subtype="netfilter")]
