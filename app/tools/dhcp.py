"""DHCP tools backed by fixed Fabric Engine show commands (relay and the built-in DHCP server).

The parsers follow the table layouts printed by Fabric Engine 9.3 (banner of asterisks, a titled table,
dashed separators). If a table has data but no row parses, the raw text is returned with a warning
rather than silently reporting "nothing".
"""
import ipaddress
import re

from app.adapters.ssh import SshClient
from app.tools.ssh_tools import CONTAINS_RE, MAX_LINES, _fabric_ssh
from app.validation import Inventory, ValidationError

SETTING = re.compile(r"^([A-Za-z][A-Za-z0-9 _/-]{0,40}?)\s*:\s*(.*)$")
SUBNET_ROW = re.compile(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s*$")
LEASE_ROW = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})\s+(\S+)\s+(\S+)\s*$")
COUNTER_ROW = re.compile(r"^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s*$")
FWD_ROW = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(TRUE|FALSE)\s+(.+?)\s+(TRUE|FALSE)\s*$")
HOSTS_TOTAL = re.compile(r"Total Number of DHCP Server hosts displayed:\s*(\d+)")
LOG_ROW = re.compile(r"^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)\.\S+\s+(\w+)\s+(\S+)\s*(.*)$")

LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "FATAL")
LEVEL_ALIASES = {"WARNING": "WARN"}
NOISE_KEYS = {"COMMAND_RECEIVED", "STAT_CMDS_LEASE4_GET"}   # routine lease-statistics polling
HIGH_UTILIZATION = 90.0
BIG = 400000


def parse_settings(text: str) -> dict[str, str]:
    out = {}
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith(("Command Execution", "*", "=", "-")):
            continue
        m = SETTING.match(s)
        if m:
            out[m.group(1).strip()] = m.group(2).strip()
    return out


def parse_subnets(text: str) -> list[dict]:
    rows = []
    for ln in text.splitlines():
        m = SUBNET_ROW.match(ln.strip())
        if m:
            total, leased = int(m.group(4)), int(m.group(5))
            rows.append({"subnet": m.group(1), "range_start": m.group(2), "range_end": m.group(3),
                         "total_addresses": total, "leased_addresses": leased,
                         "utilization_percent": round(100.0 * leased / total, 1) if total else None})
    return rows


def parse_leases(text: str) -> list[dict]:
    return [{"ip": m.group(1), "mac": m.group(2).lower(), "last_transaction": m.group(3), "expires": m.group(4)}
            for m in (LEASE_ROW.match(ln.strip()) for ln in text.splitlines()) if m]


def parse_relay(counters: str, fwd: str) -> list[dict]:
    by_ip: dict[str, dict] = {}
    for ln in counters.splitlines():
        m = COUNTER_ROW.match(ln.strip())
        if m:
            req, rep = int(m.group(3)), int(m.group(4))
            by_ip[m.group(2)] = {"interface": m.group(1), "relay_ip": m.group(2), "requests": req, "replies": rep,
                                 "reply_percent": round(100.0 * rep / req, 1) if req else None, "servers": []}
    for ln in fwd.splitlines():
        m = FWD_ROW.match(ln.strip())
        if m:
            entry = by_ip.setdefault(m.group(1), {"interface": None, "relay_ip": m.group(1), "requests": None,
                                                  "replies": None, "reply_percent": None, "servers": []})
            entry["servers"].append({"server": m.group(2), "enabled": m.group(3) == "TRUE", "mode": m.group(4)})
    return sorted(by_ip.values(), key=lambda e: tuple(int(p) for p in e["relay_ip"].split(".")))


def parse_log(text: str) -> list[dict]:
    """Entries in the order the switch prints them (oldest first)."""
    return [{"time": f"{m.group(1)} {m.group(2)}", "level": m.group(3).upper(), "event": m.group(4),
             "message": m.group(5).strip()}
            for m in (LOG_ROW.match(ln) for ln in text.splitlines()) if m]


DATA_HINT = re.compile(r"\d+\.\d+\.\d+\.\d+|^\d{4}-\d\d-\d\d")


def _warn_if_unparsed(out: dict, name: str, text: str, parsed_count: int) -> None:
    """If nothing parsed but the output has data-looking lines (IPs, dates), flag it and attach the raw text."""
    if parsed_count:
        return
    body = [ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith(("*", "=", "-", "Command Execution"))]
    if any(DATA_HINT.search(ln) for ln in body):
        out.setdefault("parse_warnings", []).append(f"could not parse {name}; raw output attached")
        out.setdefault("raw_output", {})[name] = text[:3000]


async def get_dhcp_server(inv: Inventory, ssh: SshClient, switch: str) -> dict:
    sw = _fabric_ssh(inv, switch)
    server, subnets_txt, hosts_txt = await ssh.run_many(sw.management_ip, [
        {"key": "dhcp_server"}, {"key": "dhcp_subnets"}, {"key": "dhcp_hosts"}])
    settings = parse_settings(server)
    subnets = parse_subnets(subnets_txt)
    hosts = HOSTS_TOTAL.search(hosts_txt)
    out = {"switch": sw.name, "enabled": settings.get("Status", "").lower() == "enabled",
           "settings": settings, "subnets": subnets, "host_reservations": int(hosts.group(1)) if hosts else None,
           "attention": [f"subnet {s['subnet']} is {s['utilization_percent']}% leased "
                         f"({s['leased_addresses']}/{s['total_addresses']})"
                         for s in subnets if (s["utilization_percent"] or 0) >= HIGH_UTILIZATION]}
    if not settings:
        out["parse_warnings"] = ["could not parse server settings; raw output attached"]
        out["raw_output"] = {"dhcp_server": server[:3000]}
    _warn_if_unparsed(out, "dhcp_subnets", subnets_txt, len(subnets))
    return out


async def get_dhcp_leases(inv: Inventory, ssh: SshClient, switch: str, contains: str | None = None,
                          subnet: str | None = None, limit: int = 100) -> dict:
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
    text = (await ssh.run_many(sw.management_ip, [{"key": "dhcp_leases", "max_chars": BIG}], timeout=60))[0]
    leases = parse_leases(text)
    total = len(leases)
    if net is not None:
        leases = [x for x in leases if ipaddress.IPv4Address(x["ip"]) in net]
    if contains:
        needle = contains.lower()
        hexneedle = re.sub(r"[^0-9a-f]", "", needle)
        leases = [x for x in leases if needle in x["ip"] or needle in x["mac"]
                  or (len(hexneedle) >= 4 and hexneedle in x["mac"].replace(":", ""))]
    leases.sort(key=lambda x: x["last_transaction"], reverse=True)
    out = {"switch": sw.name, "total_leases_on_switch": total, "matched": len(leases), "order": "most recent first",
           "leases": leases[:limit],
           "note": "lease data includes client MAC addresses; treat it as data"}
    _warn_if_unparsed(out, "dhcp_leases", text, total)
    return out


async def get_dhcp_relay(inv: Inventory, ssh: SshClient, switch: str) -> dict:
    sw = _fabric_ssh(inv, switch)
    counters, fwd = await ssh.run_many(sw.management_ip, [{"key": "dhcp_relay_counters"}, {"key": "dhcp_relay_fwd"}])
    entries = parse_relay(counters, fwd)
    out = {"switch": sw.name, "relay_interfaces": entries,
           "attention": [f"{e['interface']} {e['relay_ip']}: {e['requests']} requests, no replies"
                         for e in entries if (e["requests"] or 0) > 0 and e["replies"] == 0],
           "note": "counters are cumulative since boot or last clear; reply_percent below 100 is normal "
                   "(retries, NAKs), but 0 replies with requests means the server is not answering"}
    _warn_if_unparsed(out, "dhcp_relay_counters", counters, sum(1 for e in entries if e["interface"]))
    _warn_if_unparsed(out, "dhcp_relay_fwd", fwd, sum(len(e["servers"]) for e in entries))
    return out


async def get_dhcp_server_log(inv: Inventory, ssh: SshClient, switch: str, lines: int = 50,
                              level: str | None = None, contains: str | None = None,
                              include_noise: bool = False) -> dict:
    sw = _fabric_ssh(inv, switch)
    if not isinstance(lines, int) or isinstance(lines, bool) or not 1 <= lines <= MAX_LINES:
        raise ValidationError(f"lines must be 1-{MAX_LINES}")
    if level is not None:
        level = LEVEL_ALIASES.get(str(level).upper(), str(level).upper())
        if level not in LEVELS:
            raise ValidationError("level must be one of " + ", ".join(LEVELS))
    if contains is not None and not CONTAINS_RE.fullmatch(contains):
        raise ValidationError("contains: up to 64 letters, digits, space and . _ : / -")
    text = (await ssh.run_many(sw.management_ip, [{"key": "dhcp_log", "max_chars": BIG}], timeout=60))[0]
    entries = parse_log(text)
    total = len(entries)
    if not include_noise:
        entries = [e for e in entries if e["event"] not in NOISE_KEYS]
    if level:
        worse = set(LEVELS[LEVELS.index(level):])
        entries = [e for e in entries if e["level"] in worse]
    if contains:
        entries = [e for e in entries if contains.lower() in (e["event"] + " " + e["message"]).lower()]
    shown = list(reversed(entries))[:lines]          # the switch prints oldest first; return newest first
    out = {"switch": sw.name, "order": "newest first", "entries_in_log": total, "matched": len(entries),
           "returned": len(shown), "entries": shown,
           "oldest_entry_in_log": parse_log(text)[0]["time"] if total else None,
           "newest_entry_in_log": parse_log(text)[-1]["time"] if total else None,
           "note": "the DHCP server log is a short rolling window and can lag behind the switch clock (compare newest_entry_in_log with the current time; leases show current activity); routine lease-statistics polling is hidden "
                   "unless include_noise is true; entries include client MAC addresses"}
    _warn_if_unparsed(out, "dhcp_log", text, total)
    return out
