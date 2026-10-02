"""Tools that need privileged mode (`enable`): per-port interface detail, fibre-optic modules, NTP status and MLT.
Each tool runs only fixed `show` commands, in its own privileged session, and returns the switch's own text (cleaned of
the banner and pager) because the readers are network administrators."""
import re

from app.adapters.ssh import SshClient
from app.tools.ssh_tools import _fabric_ssh
from app.validation import PORT_RES, Inventory, ValidationError

NOISE = ("****", "Command Execution Time", "Please widen the terminal")
PORT_BLOCK = re.compile(r"^Port:\s+(\S+)\s*$", re.M)
DDM = re.compile(r"DDM Supported\s*:\s*(TRUE|FALSE)", re.I)
BIG = 400000


def tidy(text: str) -> str:
    lines = [ln.rstrip() for ln in text.splitlines() if not ln.lstrip().startswith(NOISE)]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def _port(port: str) -> str:
    if not isinstance(port, str) or not PORT_RES["fabric"].fullmatch(port):
        raise ValidationError("invalid port; expected e.g. 1/1 or 1/1/1")
    return port


async def get_interface_detail(inv: Inventory, ssh: SshClient, switch: str, port: str) -> dict:
    sw = _fabric_ssh(inv, switch)
    port = _port(port)
    info, stats, errors = await ssh.run_many(sw.management_ip, [
        {"key": "interface", "args": {"port": port}}, {"key": "interface_stats", "args": {"port": port}},
        {"key": "interface_errors", "args": {"port": port}}])
    return {"switch": sw.name, "port": port, "interface": tidy(info), "statistics": tidy(stats), "errors": tidy(errors),
            "note": "counters are cumulative since boot or the last clear"}


def split_optics_detail(text: str) -> dict[str, str]:
    """port -> that module's detail block. Blocks start at 'Port: x' and end before the next module header."""
    marks = [(m.start(), m.group(1)) for m in PORT_BLOCK.finditer(text)]
    out = {}
    for n, (start, port) in enumerate(marks):
        end = marks[n + 1][0] if n + 1 < len(marks) else len(text)
        block = text[start:end]
        block = re.split(r"\n=+\n\s*Pluggable Optical Module Info", block)[0]      # drop the next module's header
        out[port] = block.strip()
    return out


async def get_optics(inv: Inventory, ssh: SshClient, switch: str, port: str | None = None) -> dict:
    sw = _fabric_ssh(inv, switch)
    if port is not None:
        port = _port(port)
    keys = [{"key": "optics_basic"}] + ([{"key": "optics_detail", "max_chars": BIG}] if port else [])
    texts = await ssh.run_many(sw.management_ip, keys, timeout=90)
    basic = tidy(texts[0])
    out = {"switch": sw.name, "modules_table": basic,
           "note": "DDM (digital diagnostics: light levels, temperature, voltage) is only reported by modules that "
                   "support it; DAC and copper cables usually do not"}
    if port:
        blocks = split_optics_detail(texts[1])
        out["port"] = port
        out["detail"] = blocks.get(port)
        ddm = DDM.search(blocks.get(port) or "")
        out["ddm_supported"] = None if not ddm else ddm.group(1).upper() == "TRUE"
        if out["detail"] is None:
            out["detail_note"] = "no optical module detail for that port (no module installed, or not a pluggable port)"
    return out


async def get_ntp_status(inv: Inventory, ssh: SshClient, switch: str) -> dict:
    sw = _fabric_ssh(inv, switch)
    servers, stats = await ssh.run_many(sw.management_ip, [{"key": "ntp_server"}, {"key": "ntp_stats"}])
    srv = tidy(servers)
    ips = re.findall(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(true|false)", srv, re.M)
    return {"switch": sw.name, "servers": [{"server": ip, "enabled": en == "true"} for ip, en in ips],
            "servers_table": srv, "statistics": tidy(stats),
            "note": "Sync Status 'System Peer' with Reachability 'Reachable' means the switch is synchronised to that server"}


async def get_mlt_status(inv: Inventory, ssh: SshClient, switch: str) -> dict:
    sw = _fabric_ssh(inv, switch)
    text = tidy((await ssh.run_many(sw.management_ip, [{"key": "mlt"}]))[0])
    none = bool(re.search(r"All 0 out of 0 Total Num of mlt displayed", text))
    return {"switch": sw.name, "mlt_configured": not none, "output": text}
