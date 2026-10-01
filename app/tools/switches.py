"""Phase 1 read-only tools. Each builds results from fixed OIDs; callers never supply OIDs or commands."""
import re

from app.adapters.snmp import SnmpClient, SnmpError
from app.validation import Inventory, ValidationError, validate_port

SYS = "1.3.6.1.2.1.1"
IF = "1.3.6.1.2.1.2.2.1"       # ifTable columns
IFX = "1.3.6.1.2.1.31.1.1.1"   # ifXTable columns
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1"


def _col(table: dict[str, str], base: str) -> dict[str, str]:
    """Map index -> value for one table column (keys are '<base>.<index>')."""
    p = base + "."
    return {k[len(p):]: v for k, v in table.items() if k.startswith(p)}


async def list_switches(inv: Inventory) -> list[dict]:
    return [{"name": s.name, "site": s.site, "platform": s.platform, "protocols": list(s.protocols)}
            for s in inv.all()]


# Fabric Engine (Rapid City MIB) health OIDs
RC = "1.3.6.1.4.1.2272.1"
KHI_CPU = f"{RC}.85.10.1.1.2"      # rcKhiSlotCpuCurrentUtil.<slot>  (%)
KHI_MEM = f"{RC}.85.10.1.1.8"      # rcKhiSlotMemUtil.<slot>         (%)
TEMPS = f"{RC}.212"                # rcSingleCp temperatures, .1.0 = CPU, .2-.4 other sensors (deg C)
PSU_STATUS = f"{RC}.4.8.1.1.2"     # rcChasPowerSupplyOperStatus.<psu>
ENT_DESCR = "1.3.6.1.2.1.47.1.1.1.1.7"
DHCP_FWD = f"{RC}.8.9.1"           # rcIpDhcpForwardTable (relay agent entries)
PSU_STATES = {"1": "unknown", "2": "empty", "3": "up", "4": "down"}
DHCP_MODES = {"1": "other", "2": "bootp", "3": "dhcp", "4": "bootp+dhcp"}


async def _try(coro):
    """Run one optional SNMP section; a missing/unsupported subtree must not fail the whole report."""
    try:
        return await coro
    except (SnmpError, LookupError):
        return None


def _as_int(v: str):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _uptime(ticks: str) -> str:
    t = _as_int(ticks)
    if t is None:
        return ticks
    d, rem = divmod(t // 100, 86400)
    h, rem = divmod(rem, 3600)
    return f"{d}d {h}h {rem // 60}m"


async def get_switch_health(inv: Inventory, snmp: SnmpClient, switch: str) -> dict:
    sw = inv.resolve(switch)
    ip = sw.management_ip
    v = await snmp.get(ip, [f"{SYS}.{i}.0" for i in (1, 3, 5, 6)])
    descr, uptime, name, loc = (v[f"{SYS}.{i}.0"] for i in (1, 3, 5, 6))
    out = {"switch": sw.name, "sysName": name, "sysDescr": descr, "sysLocation": loc,
           "uptime": _uptime(uptime), "uptime_ticks": uptime}
    if sw.platform != "fabric":
        out["note"] = "CPU, memory, temperature and power detail is only implemented for Fabric Engine"
        return out

    cpu = await _try(snmp.walk(ip, KHI_CPU))
    mem = await _try(snmp.walk(ip, KHI_MEM))
    temps = await _try(snmp.walk(ip, TEMPS, limit=10))
    psu = await _try(snmp.walk(ip, PSU_STATUS))
    ent = await _try(snmp.walk(ip, ENT_DESCR))

    out["cpu_percent"] = None if cpu is None else {f"slot{i}": _as_int(x) for i, x in _col(cpu, KHI_CPU).items()}
    out["memory_percent"] = None if mem is None else {f"slot{i}": _as_int(x) for i, x in _col(mem, KHI_MEM).items()}
    if temps is not None:
        t = {k[len(TEMPS) + 1:]: _as_int(x) for k, x in temps.items()}
        out["temperature_c"] = {"cpu": t.get("1.0"), "other_sensors": [t[k] for k in ("2.0", "3.0", "4.0") if k in t]}
    else:
        out["temperature_c"] = None
    if psu is not None:
        out["power_supplies"] = {f"psu{i}": PSU_STATES.get(x, f"unknown({x})") for i, x in _col(psu, PSU_STATUS).items()}
    else:
        out["power_supplies"] = None
    if ent is not None:
        names = set(ent.values())
        out["fan_trays_present"] = sorted(n for n in names if re.fullmatch(r"FanTray \d+", n, re.I))
        out["fans_present"] = sorted(n for n in names if re.search(r"fan-\d+$", n, re.I))
    out["notes"] = ["fan speed/status is not exposed over SNMP on this platform; fan_trays_present/fans_present list "
                    "installed hardware only (use SSH get_system_info for fan status)"]
    out["attention"] = [f"{k} is down" for k, st in (out.get("power_supplies") or {}).items() if st == "down"]
    return out


async def get_dhcp_status(inv: Inventory, snmp: SnmpClient, switch: str) -> dict:
    """DHCP relay (forwarding) configuration. A relay whose server is the switch itself means a local DHCP server."""
    sw = inv.resolve(switch)
    if sw.platform != "fabric":
        raise ValidationError("DHCP status is only implemented for Fabric Engine switches")
    table = await snmp.walk(sw.management_ip, DHCP_FWD, limit=500)
    cols = {c: _col(table, f"{DHCP_FWD}.{c}") for c in (1, 2, 3, 4)}
    entries = [{"relay_interface_ip": cols[1].get(i), "server": cols[2].get(i),
                "enabled": cols[3].get(i) == "1", "mode": DHCP_MODES.get(cols[4].get(i), cols[4].get(i))}
               for i in sorted(cols[1])]
    servers = sorted({e["server"] for e in entries if e["server"]})
    local = sw.management_ip in servers
    return {"switch": sw.name, "dhcp_relay_configured": bool(entries), "entries": entries,
            "servers": servers, "local_dhcp_server_likely": local,
            "note": "Derived from the DHCP forwarding table. A server equal to the switch's own address "
                    "suggests a local DHCP server; confirm its leases/scopes over SSH."}


async def _find_ifindex(snmp: SnmpClient, ip: str, port: str) -> str:
    """ifName is the port label (EXOS '1:48', Fabric Engine '1/1'; verify on hardware), so match on ifName."""
    names = await snmp.walk(ip, f"{IFX}.1")
    for idx, nm in _col(names, f"{IFX}.1").items():
        if nm == port:
            return idx
    raise LookupError(f"port {port} not found on switch")


async def get_interface(inv: Inventory, snmp: SnmpClient, switch: str, port: str) -> dict:
    sw = inv.resolve(switch)
    port = validate_port(port, sw.platform)
    i = await _find_ifindex(snmp, sw.management_ip, port)
    oids = [f"{IF}.{c}.{i}" for c in (2, 7, 8)] + [f"{IFX}.{c}.{i}" for c in (15, 6, 10, 18)]
    v = await snmp.get(sw.management_ip, oids)
    return {"switch": sw.name, "port": port, "description": v[f"{IF}.2.{i}"],
            "admin_status": v[f"{IF}.7.{i}"], "oper_status": v[f"{IF}.8.{i}"],
            "speed_mbps": v[f"{IFX}.15.{i}"], "in_octets": v[f"{IFX}.6.{i}"],
            "out_octets": v[f"{IFX}.10.{i}"], "alias": v[f"{IFX}.18.{i}"]}


async def get_interface_errors(inv: Inventory, snmp: SnmpClient, switch: str, port: str) -> dict:
    sw = inv.resolve(switch)
    port = validate_port(port, sw.platform)
    i = await _find_ifindex(snmp, sw.management_ip, port)
    v = await snmp.get(sw.management_ip, [f"{IF}.{c}.{i}" for c in (13, 14, 19, 20)])
    return {"switch": sw.name, "port": port, "in_discards": v[f"{IF}.13.{i}"],
            "in_errors": v[f"{IF}.14.{i}"], "out_discards": v[f"{IF}.19.{i}"],
            "out_errors": v[f"{IF}.20.{i}"],
            "note": "cumulative counters; compare two samples for a rate"}


async def get_lldp_neighbors(inv: Inventory, snmp: SnmpClient, switch: str) -> dict:
    sw = inv.resolve(switch)
    rem = await snmp.walk(sw.management_ip, LLDP_REM)
    loc = _col(await snmp.walk(sw.management_ip, LLDP_LOC_PORT), f"{LLDP_LOC_PORT}.3")
    ports = _col(rem, f"{LLDP_REM}.7")   # lldpRemPortId
    sysn = _col(rem, f"{LLDP_REM}.9")    # lldpRemSysName
    out = []
    for key, rport in ports.items():     # key = timeMark.localPortNum.remIndex
        local_num = key.split(".")[1]
        out.append({"local_port": loc.get(local_num, local_num), "neighbor": sysn.get(key, ""),
                    "neighbor_port": rport})
    return {"switch": sw.name, "neighbors": out}
