"""Phase 2 read-only tools backed by fixed Fabric Engine show commands over SSH.

Output is returned as raw CLI text (capped) because parsing is release-specific; MAC lookups
fetch the whole table and filter locally, so no caller-supplied text ever reaches the switch.
"""
import re

from app.adapters.ssh import SshClient
from app.validation import Inventory, ValidationError, validate_port

MAC_RE = re.compile(r"[0-9A-Fa-f]{2}([:.-]?[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{4}(\.[0-9A-Fa-f]{4}){2}")
MAX_MATCHES = 50


def _fabric_ssh(inv: Inventory, switch: str):
    sw = inv.resolve(switch, "ssh")
    if sw.platform != "fabric":
        raise ValidationError("SSH tools are only implemented for Fabric Engine switches")
    return sw


def _norm_mac(s: str) -> str:
    return re.sub(r"[^0-9a-f]", "", s.lower())


async def get_system_info(inv: Inventory, ssh: SshClient, switch: str) -> dict:
    sw = _fabric_ssh(inv, switch)
    return {"switch": sw.name, "output": await ssh.run(sw.management_ip, "sys_info")}


async def get_fabric_adjacencies(inv: Inventory, ssh: SshClient, switch: str) -> dict:
    sw = _fabric_ssh(inv, switch)
    return {"switch": sw.name, "output": await ssh.run(sw.management_ip, "isis_adjacencies")}


async def get_interface_detail(inv: Inventory, ssh: SshClient, switch: str, port: str) -> dict:
    sw = _fabric_ssh(inv, switch)
    port = validate_port(port, "fabric")
    return {"switch": sw.name, "port": port,
            "interface": await ssh.run(sw.management_ip, "interface", port=port),
            "statistics": await ssh.run(sw.management_ip, "interface_stats", port=port),
            "errors": await ssh.run(sw.management_ip, "interface_errors", port=port)}


async def find_mac_address(inv: Inventory, ssh: SshClient, switch: str, mac: str) -> dict:
    sw = _fabric_ssh(inv, switch)
    if not isinstance(mac, str) or not MAC_RE.fullmatch(mac):
        raise ValidationError("invalid MAC address")
    want = _norm_mac(mac)
    table = await ssh.run(sw.management_ip, "mac_table")
    matches = [ln.strip() for ln in table.splitlines() if want in _norm_mac(ln)]
    return {"switch": sw.name, "mac": mac, "matches": matches[:MAX_MATCHES]}
