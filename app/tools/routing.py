"""Routing tool: IP interfaces (`show ip interface`) and the route table (`show ip route`), optionally for a VRF.
The whole table is fetched and filtered here (including a longest-prefix lookup for one destination)."""
import ipaddress
import re

from app.adapters.ssh import VRF_NAME, SshClient
from app.tools.ssh_tools import MAX_LINES, _fabric_ssh
from app.tools.tables import body_lines, column_starts, slice_row
from app.validation import Inventory, ValidationError

IFACE_ROW = re.compile(r"^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(enable|disable)\s+(up|down)\s+"
                       r"(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+?))?\s*$")
ROUTE_HINT = re.compile(r"^\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s")
IFACE_HINT = re.compile(r"^\S+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s")
TITLE = re.compile(r"IP (?:Interface|Route) - (\S+)")
PROTOCOLS = ("LOC", "STAT", "ISIS", "OSPF", "BGP", "RIP", "SPBM")


def parse_interfaces(text: str) -> tuple[list[dict], list[str], str | None]:
    rows, bad = [], []
    for ln in body_lines(text):
        m = IFACE_ROW.match(ln.strip())
        if m:
            net = ipaddress.IPv4Network(f"{m.group(2)}/{m.group(3)}", strict=False)
            rows.append({"interface": m.group(1), "ip": m.group(2), "mask": m.group(3), "prefix_length": net.prefixlen,
                         "admin": m.group(4), "oper": m.group(5), "vlan": None if m.group(6) in ("--", "-") else m.group(6),
                         "brouter_port": m.group(7), "name": m.group(9)})
        elif IFACE_HINT.match(ln.strip()):
            bad.append(ln.strip())
    title = TITLE.search(text)
    return rows, bad, title.group(1) if title else None


ROUTE_COLS = ["DST", "MASK", "NEXT", "VRF/ISID", "COST", "FACE", "PROT", "AGE", "TYPE", "PRF"]


def parse_routes(text: str) -> tuple[list[dict], list[str], str | None]:
    """Fixed-width read: the NEXT column holds a host name (which can contain spaces) for fabric-learned routes."""
    lines = body_lines(text)
    head = next((i for i, ln in enumerate(lines) if ln.startswith("DST ") and "NEXT" in ln), None)
    rows, bad = [], []
    title = TITLE.search(text)
    if head is None:
        return rows, bad, title.group(1) if title else None
    st = column_starts(lines[head], ROUTE_COLS)
    for ln in lines[head + 1:]:
        if not ROUTE_HINT.match(ln.strip()):
            continue
        c = slice_row(ln, st)
        try:
            net = ipaddress.IPv4Network(f"{c[0]}/{c[1]}", strict=False)
            rows.append({"network": str(net), "prefix_length": net.prefixlen, "next_hop": c[2],
                         "next_hop_vrf": None if c[3] == "-" else c[3], "cost": int(c[4]), "interface": c[5],
                         "protocol": c[6], "age": int(c[7]), "flags": c[8], "preference": int(c[9])})
        except (ValueError, IndexError):
            bad.append(ln.strip())
    return rows, bad, title.group(1) if title else None


def lookup(routes: list[dict], destination: ipaddress.IPv4Address) -> dict | None:
    """Longest-prefix match among best routes ('B' flag); falls back to all routes if none is flagged best."""
    cands = [r for r in routes if destination in ipaddress.IPv4Network(r["network"])]
    best = [r for r in cands if "B" in r["flags"]] or cands
    if not best:
        return None
    return sorted(best, key=lambda r: (-r["prefix_length"], r["preference"], r["cost"]))[0]


async def get_routing(inv: Inventory, ssh: SshClient, switch: str, destination: str | None = None,
                      protocol: str | None = None, vrf: str | None = None, limit: int = 100) -> dict:
    sw = _fabric_ssh(inv, switch)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LINES:
        raise ValidationError(f"limit must be 1-{MAX_LINES}")
    dest = None
    if destination is not None:
        try:
            dest = ipaddress.IPv4Address(destination)
        except ValueError:
            raise ValidationError("destination must be an IPv4 address") from None
    if protocol is not None and protocol.upper() not in PROTOCOLS:
        raise ValidationError("protocol must be one of " + ", ".join(PROTOCOLS))
    if vrf is not None and not VRF_NAME.fullmatch(vrf):
        raise ValidationError("vrf must be 1-16 letters, digits, . _ -")

    if vrf:
        jobs = [{"key": "ip_interface_vrf", "args": {"vrf": vrf}}, {"key": "ip_route_vrf", "args": {"vrf": vrf}}]
    else:
        jobs = [{"key": "ip_interface"}, {"key": "ip_route"}]
    iface_t, route_t = await ssh.run_many(sw.management_ip, [dict(j, max_chars=400000) for j in jobs], timeout=60)
    ifaces, bad_i, router = parse_interfaces(iface_t)
    routes, bad_r, _ = parse_routes(route_t)
    total_routes = len(routes)
    shown = routes
    if protocol:
        shown = [r for r in shown if r["protocol"] == protocol.upper()]
    shown = sorted(shown, key=lambda r: (ipaddress.IPv4Network(r["network"]).network_address, r["prefix_length"]))

    out = {"switch": sw.name, "vrf": vrf or router,
           "ip_interfaces": ifaces,
           "interfaces_down": [f"{i['interface']} {i['ip']}" for i in ifaces if i["admin"] == "enable" and i["oper"] == "down"],
           "routes_in_table": total_routes, "routes_matched": len(shown), "routes": shown[:limit],
           "route_protocols": {p: sum(1 for r in routes if r["protocol"] == p) for p in sorted({r["protocol"] for r in routes})},
           "default_route": next((r for r in routes if r["network"] == "0.0.0.0/0" and "B" in r["flags"]), None)}
    if dest is not None:
        best = lookup(routes, dest)
        out["lookup"] = {"destination": str(dest), "best_route": best,
                         "result": "no matching route" if best is None else
                         f"{best['network']} via {best['next_hop']} on interface {best['interface']} ({best['protocol']})"}
    warns = []
    if bad_i or bad_r:
        warns.append(f"{len(bad_i) + len(bad_r)} line(s) looked like table rows but could not be parsed")
        out["unparsed_lines"] = (bad_i + bad_r)[:10]
    if not ifaces and "IP Interface" not in iface_t and iface_t.strip():
        warns.append("could not parse 'show ip interface'")
    if warns:
        out["parse_warnings"] = warns
    out["note"] = "flags: B=best route, D=direct, I=indirect, A=alternative, E=ECMP, U=unresolved, N=not in hardware; " \
                  "protocol LOC=connected, STAT=static"
    return out
