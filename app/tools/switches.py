"""Phase 1 read-only tools. Each builds results from fixed OIDs; callers never supply OIDs or commands."""
from app.adapters.snmp import SnmpClient
from app.validation import Inventory, validate_port

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


async def get_switch_health(inv: Inventory, snmp: SnmpClient, switch: str) -> dict:
    sw = inv.resolve(switch)
    v = await snmp.get(sw.management_ip, [f"{SYS}.{i}.0" for i in (1, 3, 5, 6)])
    descr, uptime, name, loc = (v[f"{SYS}.{i}.0"] for i in (1, 3, 5, 6))
    return {"switch": sw.name, "sysName": name, "sysDescr": descr, "sysLocation": loc,
            "uptime_ticks": uptime}


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
