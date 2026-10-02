"""All-ports summary over SNMPv3 (IF-MIB): state, speed, error counters and how long ago each port last changed
state. Works on Fabric Engine and Switch Engine; no SSH login needed."""
import re

from app.adapters.snmp import SnmpClient
from app.tools.ssh_tools import MAX_LINES
from app.validation import PORT_RES, Inventory, ValidationError

IF = "1.3.6.1.2.1.2.2.1"
IFX = "1.3.6.1.2.1.31.1.1.1"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OPER = {"1": "up", "2": "down", "3": "testing", "4": "unknown", "5": "dormant", "6": "not-present",
        "7": "lower-layer-down"}
STATES = ("up", "down", "admin_down")
WALK_LIMIT = 4000


def _col(table: dict[str, str], base: str) -> dict[str, str]:
    p = base + "."
    return {k[len(p):]: v for k, v in table.items() if k.startswith(p)}


def _int(v: str | None) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _natural(port: str) -> tuple:
    return tuple(int(p) for p in re.split(r"[/:]", port))


def _ago(seconds: int | None) -> str | None:
    if seconds is None:
        return None
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return f"{d}d {h}h" if d else (f"{h}h {m}m" if h else f"{m}m")


async def get_port_summary(inv: Inventory, snmp: SnmpClient, switch: str, state: str | None = None,
                           only_errors: bool = False, changed_within_minutes: int | None = None,
                           limit: int = 100) -> dict:
    sw = inv.resolve(switch)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LINES:
        raise ValidationError(f"limit must be 1-{MAX_LINES}")
    if state is not None:
        state = str(state).lower().replace("-", "_")
        if state not in STATES:
            raise ValidationError("state must be one of " + ", ".join(STATES))
    if changed_within_minutes is not None and (not isinstance(changed_within_minutes, int)
                                              or isinstance(changed_within_minutes, bool)
                                              or not 1 <= changed_within_minutes <= 10080):
        raise ValidationError("changed_within_minutes must be 1-10080")
    rx = PORT_RES.get(sw.platform)
    ip = sw.management_ip

    uptime = _int((await snmp.get(ip, [SYS_UPTIME]))[SYS_UPTIME])
    cols = {}
    for name, base in (("name", f"{IFX}.1"), ("admin", f"{IF}.7"), ("oper", f"{IF}.8"), ("speed", f"{IFX}.15"),
                       ("changed", f"{IF}.9"), ("in_err", f"{IF}.14"), ("out_err", f"{IF}.20"),
                       ("in_disc", f"{IF}.13"), ("out_disc", f"{IF}.19"), ("alias", f"{IFX}.18")):
        cols[name] = _col(await snmp.walk(ip, base, limit=WALK_LIMIT), base)

    ports = []
    for idx, pname in cols["name"].items():
        if rx is None or not rx.fullmatch(pname):
            continue                                    # skip VLAN, MLT, loopback and other logical interfaces
        admin_up = cols["admin"].get(idx) == "1"
        oper = OPER.get(cols["oper"].get(idx, ""), "unknown")
        st = "admin_down" if not admin_up else ("up" if oper == "up" else "down")
        changed = _int(cols["changed"].get(idx))
        ago = max(0, (uptime - changed) // 100) if uptime is not None and changed is not None and changed <= uptime else None
        errs = {"in_errors": _int(cols["in_err"].get(idx)) or 0, "out_errors": _int(cols["out_err"].get(idx)) or 0,
                "in_discards": _int(cols["in_disc"].get(idx)) or 0, "out_discards": _int(cols["out_disc"].get(idx)) or 0}
        ports.append({"port": pname, "state": st, "oper_status": oper, "speed_mbps": _int(cols["speed"].get(idx)),
                      "last_change_seconds_ago": ago, "last_change": _ago(ago), **errs,
                      "has_errors": any(errs.values()), "alias": cols["alias"].get(idx) or None})
    ports.sort(key=lambda p: _natural(p["port"]))
    summary = {"ports": len(ports), **{s: sum(1 for p in ports if p["state"] == s) for s in STATES},
               "with_errors": sum(1 for p in ports if p["has_errors"])}

    shown = ports
    if state:
        shown = [p for p in shown if p["state"] == state]
    if only_errors:
        shown = [p for p in shown if p["has_errors"]]
    if changed_within_minutes:
        limit_s = changed_within_minutes * 60
        shown = [p for p in shown if p["last_change_seconds_ago"] is not None and p["last_change_seconds_ago"] <= limit_s]
        shown.sort(key=lambda p: p["last_change_seconds_ago"])
    out = {"switch": sw.name, "summary": summary, "matched": len(shown), "ports": shown[:limit],
           "note": "error and discard counters are cumulative since boot (compare two readings for a rate); "
                   "last_change is time since the port last changed state; admin_down means disabled by configuration"}
    if not ports:
        out["parse_warnings"] = ["no physical ports recognised in the interface table"]
    return out
