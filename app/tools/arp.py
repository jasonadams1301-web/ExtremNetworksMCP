"""ARP table tool backed by the fixed Fabric Engine command `show ip arp` (optionally `... vrf <name>`).

The whole table is fetched and filtered here, so filter text never reaches the switch. Lines that look like ARP
rows but do not parse are reported instead of being dropped silently.
"""
import ipaddress
import re

from app.adapters.ssh import SshClient
from app.tools.ssh_tools import CONTAINS_RE, MAX_LINES, _fabric_ssh
from app.validation import PORT_RES, Inventory, ValidationError

ROW = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)(?:\s+(\S+))?\s*$")
ROW_HINT = re.compile(r"^\d+\.\d+\.\d+\.\d+\s")
FOOTER = re.compile(r"(\d+) out of (\d+) ARP entries displayed")
TITLE = re.compile(r"IP Arp - (\S+)")
TYPE_RE = re.compile(r"[A-Za-z_-]{1,16}")
VRF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,15}")
SWITCH_ERROR = re.compile(r"^Error:\s*(.+)$", re.M)
BIG = 400000


def parse_arp(text: str) -> dict:
    entries, unparsed = [], []
    for ln in text.splitlines():
        s = ln.strip()
        m = ROW.match(s)
        if m:
            entries.append({"ip": m.group(1), "mac": m.group(2).lower(),
                            "vlan": int(m.group(3)) if m.group(3).isdigit() else None,
                            "port": None if m.group(4) == "-" else m.group(4),
                            "type": m.group(5).upper(), "ttl_seconds": int(m.group(6)) * 10,
                            "tunnel": m.group(7)})
        elif ROW_HINT.match(s):
            unparsed.append(s)
    footer = FOOTER.search(text)
    title = TITLE.search(text)
    return {"entries": entries, "unparsed": unparsed, "router": title.group(1) if title else None,
            "displayed_by_switch": int(footer.group(1)) if footer else None,
            "total_in_switch_table": int(footer.group(2)) if footer else None}


async def get_arp_table(inv: Inventory, ssh: SshClient, switch: str, contains: str | None = None,
                        subnet: str | None = None, vlan: int | None = None, port: str | None = None,
                        entry_type: str | None = None, vrf: str | None = None, limit: int = 100) -> dict:
    sw = _fabric_ssh(inv, switch)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LINES:
        raise ValidationError(f"limit must be 1-{MAX_LINES}")
    if contains is not None and not CONTAINS_RE.fullmatch(contains):
        raise ValidationError("contains: up to 64 letters, digits, space and . _ : / -")
    net = None
    if subnet is not None:
        try:
            net = ipaddress.IPv4Network(subnet, strict=False)
        except ValueError:
            raise ValidationError("subnet must be an IPv4 network such as 192.0.2.0/24") from None
    if vlan is not None and (not isinstance(vlan, int) or isinstance(vlan, bool) or not 1 <= vlan <= 4094):
        raise ValidationError("vlan must be 1-4094")
    if port is not None and not PORT_RES["fabric"].fullmatch(port):
        raise ValidationError("invalid port; expected e.g. 1/48 or 1/1/1")
    if entry_type is not None and not TYPE_RE.fullmatch(entry_type):
        raise ValidationError("entry_type must be letters only, e.g. DYNAMIC or LOCAL")
    if vrf is not None and not VRF_RE.fullmatch(vrf):
        raise ValidationError("vrf must be 1-16 letters, digits, . _ -")

    job = {"key": "arp_vrf", "args": {"vrf": vrf}} if vrf else {"key": "arp"}
    text = (await ssh.run_many(sw.management_ip, [dict(job, max_chars=BIG)], timeout=60))[0]
    parsed = parse_arp(text)
    entries, total = parsed["entries"], len(parsed["entries"])

    if net is not None:
        entries = [e for e in entries if ipaddress.IPv4Address(e["ip"]) in net]
    if vlan is not None:
        entries = [e for e in entries if e["vlan"] == vlan]
    if port is not None:
        entries = [e for e in entries if e["port"] == port]
    if entry_type:
        entries = [e for e in entries if e["type"] == entry_type.upper()]
    if contains:
        needle = contains.lower()
        hexneedle = re.sub(r"[^0-9a-f]", "", needle)
        entries = [e for e in entries if needle in e["ip"] or needle in e["mac"]
                   or (len(hexneedle) >= 4 and hexneedle in e["mac"].replace(":", ""))]
    entries.sort(key=lambda e: tuple(int(p) for p in e["ip"].split(".")))

    out = {"switch": sw.name, "vrf": vrf or parsed["router"], "entries_parsed": total, "matched": len(entries),
           "returned": min(len(entries), limit), "entries": entries[:limit],
           "switch_reports": {"displayed": parsed["displayed_by_switch"],
                              "total_in_table": parsed["total_in_switch_table"]},
           "note": "ARP entries show IP-to-MAC mappings seen by this switch. type LOCAL is the switch's own "
                   "address or broadcast; DYNAMIC is a learned host. port is where the host was learned; "
                   "entries include client MAC addresses, so treat them as data"}
    if parsed["unparsed"]:
        out["parse_warnings"] = [f"{len(parsed['unparsed'])} line(s) looked like ARP rows but could not be parsed"]
        out["unparsed_lines"] = parsed["unparsed"][:10]
    elif not total and text.strip() and "ARP entries displayed" not in text:
        err = SWITCH_ERROR.search(text)
        if err:       # the switch refused the request (unknown VRF, etc.): say so plainly
            out["switch_error"] = err.group(1).strip()
            out["parse_warnings"] = ["the switch rejected the request: " + out["switch_error"]]
            if vrf and vrf.lower() == "globalrouter":
                out["hint"] = "omit vrf to read the global routing table; the VRF argument is for named VRFs only"
        else:
            out["parse_warnings"] = ["no ARP rows recognised; raw output attached"]
            out["raw_output"] = text[:3000]
    return out
