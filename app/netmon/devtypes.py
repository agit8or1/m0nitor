"""Device types (what an internal address is), their categories, and MAC vendor lookup.

Vendor lookup uses the IEEE registry CSVs (MA-L 24-bit, MA-M 28-bit, MA-S 36-bit prefixes) from the ieee-data package,
mounted read-only at OUI_DIR. Without them, the vendor the firewall reports is used."""
import csv
import os
import re
import threading

DEVICE_TYPES = ("physical server", "virtual machine", "container", "hypervisor host", "workstation / laptop", "mobile device",
                "printer", "IoT / camera", "VoIP phone", "network device (switch / AP)", "firewall / router", "storage / NAS", "other")

CATEGORIES = (   # (category, types) in display order; an address without a type is "Unclassified"
    ("Servers", ("physical server", "hypervisor host", "storage / NAS")),
    ("Virtual", ("virtual machine", "container")),
    ("Network", ("firewall / router", "network device (switch / AP)")),
    ("Endpoints", ("workstation / laptop", "mobile device", "VoIP phone")),
    ("IoT & peripherals", ("printer", "IoT / camera")),
    ("Other", ("other",)),
)
UNCLASSIFIED = "Unclassified"
CATEGORY_NAMES = tuple(c for c, _ in CATEGORIES) + (UNCLASSIFIED,)
_CAT = {t: c for c, ts in CATEGORIES for t in ts}


def category_of(kind):
    return _CAT.get(kind or "", UNCLASSIFIED)


# virtual NIC prefixes -> platform: a MAC from one of these is a guest (VM or container) of that platform
VIRT_OUIS = {
    "bc:24:11": "Proxmox VE", "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware", "00:1c:14": "VMware",
    "00:15:5d": "Hyper-V", "00:16:3e": "Xen", "52:54:00": "QEMU/KVM", "08:00:27": "VirtualBox", "00:1c:42": "Parallels",
    "00:21:f6": "Oracle VM", "02:42:ac": "Docker",
}
# vendors that make (practically) one kind of networked device; matched on the IEEE organization name. Deliberately
# short: Dell, HP, Cisco, Ubiquiti, TP-Link, Apple, Intel... make several kinds and set no type.
VENDOR_TYPES = (
    (r"hikvision|dahua|axis communications|reolink|amcrest|hanwha vision|uniview|vivotek|mobotix", "IoT / camera"),
    (r"brother industries|lexmark|kyocera|ricoh|xerox|konica minolta|zebra technologies|sharp corporation", "printer"),
    (r"yealink|polycom|grandstream|snom|mitel|avaya", "VoIP phone"),
    (r"synology|qnap", "storage / NAS"),
    (r"juniper|aruba|ruckus|routerboard|mikrotik|arista|extreme networks", "network device (switch / AP)"),
    (r"fortinet|palo alto networks|netgate|sophos|watchguard|sonicwall", "firewall / router"),
)

OUI_DIR = os.environ.get("NETMON_OUI_DIR", "/usr/share/ieee-data")
_db, _lock = None, threading.Lock()


def _load():
    global _db
    with _lock:
        if _db is not None:
            return _db
        db = {}
        for f, n in (("oui.csv", 6), ("mam.csv", 7), ("oui36.csv", 9), ("iab.csv", 9)):
            try:
                with open(os.path.join(OUI_DIR, f), newline="", encoding="utf-8", errors="replace") as fh:
                    for row in csv.DictReader(fh):
                        a, org = (row.get("Assignment") or "").strip().lower(), (row.get("Organization Name") or "").strip()
                        if len(a) == n and org:
                            db.setdefault(n, {})[a] = org
            except OSError:
                continue
        _db = db
        return db


def available():
    return bool(_load())


def mac_hex(mac):
    return re.sub(r"[^0-9a-f]", "", str(mac or "").lower())


def locally_administered(mac):
    h = mac_hex(mac)
    return len(h) == 12 and bool(int(h[1], 16) & 2)


def vendor_of(mac):
    """IEEE organization for a MAC (longest registered prefix wins), 'randomized (private) MAC', or ''."""
    h = mac_hex(mac)
    if len(h) != 12:
        return ""
    if mac[:8].lower() in VIRT_OUIS:
        return VIRT_OUIS[mac[:8].lower()] + " (virtual NIC)"
    if locally_administered(mac):
        return "randomized (private) MAC"
    db = _load()
    for n in (9, 7, 6):
        org = db.get(n, {}).get(h[:n])
        if org and org.lower() != "private":
            return org
    return ""


def type_from_mac(mac, vendor=""):
    """(type, reason) when the MAC proves the device type, else (None, None)."""
    plat = VIRT_OUIS.get(str(mac or "")[:8].lower())
    if plat:
        return "virtual machine", f"MAC prefix ({plat})"
    v = (vendor or vendor_of(mac) or "").lower()
    for rx, t in VENDOR_TYPES:
        if re.search(rx, v):
            return t, f"MAC vendor ({vendor or vendor_of(mac)})"
    return None, None
