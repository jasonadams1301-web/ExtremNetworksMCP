"""Fabric (SPB / IS-IS) and spanning-tree status from fixed Fabric Engine show commands."""
import re

from app.adapters.ssh import SshClient
from app.tools.ssh_tools import _fabric_ssh
from app.tools.tables import body_lines
from app.validation import Inventory

SPBM_ROW = re.compile(r"^(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(enable|disable)\s+(enable|disable)\s+(enable|disable)\s+"
                      r"(enable|disable)\s+(\S+)\s+(enable|disable)\s+(\S+)\s*$")
SYSID_ROW = re.compile(r"^([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})\s+(\S+)(?:\s+(.+?))?\s*$")
ISIS_IF_ROW = re.compile(r"^(\S+)\s+(\S+)\s+Level (\d)\s+(UP|DOWN)\s+(UP|DOWN)\s+(\d+)\s+(\d+)\s+(\d+)(?:\s+\(A\))?\s+"
                         r"(\d+)\s+(\S+)\s+(\S+)(?:\s+(.+?))?\s*$")
ISIS_IF_HINT = re.compile(r"^\S+\s+(pt-pt|bcast)\s+Level\s")
ADJ_SUMMARY = re.compile(r"(\d+) out of (\d+) interfaces have formed an adjacency")
STP_A = re.compile(r"^(\d+)\s+([0-9A-Fa-f:]{17})\s+(\d+)\s+(\S+)\s+(\d+)\s*$")
STP_B = re.compile(r"^(\d+)\s+([0-9A-Fa-f:]{23})\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")
MAX_IF = 200


def parse_spbm(text: str) -> list[dict]:
    rows = []
    for ln in body_lines(text):
        m = SPBM_ROW.match(ln.strip())
        if m:
            rows.append({"instance": int(m.group(1)), "b_vids": m.group(2), "primary_vlan": int(m.group(3)),
                         "nickname": m.group(4), "ip_shortcuts": m.group(6) == "enable", "ipv6": m.group(7) == "enable",
                         "multicast": m.group(8) == "enable", "origin": m.group(11)})
    return rows


def parse_system_id(text: str) -> dict | None:
    for ln in body_lines(text):
        m = SYSID_ROW.match(ln.strip())
        if m:
            return {"system_id": m.group(1), "area": m.group(2)}
    return None


def parse_isis_interfaces(text: str) -> tuple[list[dict], list[str]]:
    rows, bad = [], []
    for ln in body_lines(text):
        s = ln.strip()
        m = ISIS_IF_ROW.match(s)
        if m:
            rows.append({"interface": m.group(1), "type": m.group(2), "level": int(m.group(3)),
                         "oper": m.group(4), "admin": m.group(5), "adjacencies": int(m.group(6)),
                         "up_adjacencies": int(m.group(7)), "metric": int(m.group(9)), "origin": m.group(10)})
        elif ISIS_IF_HINT.match(s):
            bad.append(s)
    return rows, bad


def parse_stp(text: str) -> list[dict]:
    first, second = {}, {}
    for ln in body_lines(text):
        s = ln.strip()
        m = STP_A.match(s)
        if m:
            first[int(m.group(1))] = {"stg": int(m.group(1)), "bridge_address": m.group(2).lower(),
                                      "ports": int(m.group(3)), "protocol": m.group(4),
                                      "topology_changes": int(m.group(5))}
            continue
        m = STP_B.match(s)
        if m:
            second[int(m.group(1))] = {"designated_root": m.group(2).lower(), "root_cost": int(m.group(3)),
                                       "root_port": m.group(4), "max_age": int(m.group(5)),
                                       "hello_time": int(m.group(6))}
    return [{**first[k], **second.get(k, {})} for k in sorted(first)]


async def get_fabric_status(inv: Inventory, ssh: SshClient, switch: str) -> dict:
    sw = _fabric_ssh(inv, switch)
    spbm_t, sysid_t, if_t, adj_t, stp_t = await ssh.run_many(sw.management_ip, [
        {"key": "isis_spbm"}, {"key": "isis_system_id"}, {"key": "isis_interface", "max_chars": 200000},
        {"key": "isis_adjacencies"}, {"key": "stp_status"}])
    spbm, sysid = parse_spbm(spbm_t), parse_system_id(sysid_t)
    ifs, bad = parse_isis_interfaces(if_t)
    adj = ADJ_SUMMARY.search(adj_t)
    stp = parse_stp(stp_t)

    down = [i for i in ifs if i["admin"] == "UP" and i["oper"] == "DOWN"]
    out = {"switch": sw.name,
           "spbm": spbm, "isis_system": sysid,
           "isis_adjacencies": {"formed": int(adj.group(1)), "interfaces": int(adj.group(2))} if adj else None,
           "isis_interfaces_total": len(ifs), "isis_interfaces_oper_down": len(down),
           "isis_interfaces": ifs[:MAX_IF], "spanning_tree": stp,
           "attention": ([f"{len(down)} IS-IS interface(s) are admin UP but operationally DOWN: "
                          + ", ".join(i["interface"] for i in down[:10]) + ("..." if len(down) > 10 else "")]
                         if down else []),
           "note": "adjacencies=0 on an interface means no IS-IS neighbour has formed on it; topology_changes is a "
                   "count since boot (a steadily rising number can mean a flapping link or a loop)"}
    if adj and int(adj.group(1)) == 0 and ifs:
        out["attention"].append("no IS-IS adjacencies are formed on this switch")
    warns = []
    if bad:
        warns.append(f"{len(bad)} IS-IS interface line(s) could not be parsed")
        out["unparsed_lines"] = bad[:10]
    if not spbm and re.search(r"\d+\s+\S+\s+\d+\s+\S+\s+(enable|disable)", spbm_t):
        warns.append("could not parse 'show isis spbm'")
    if not stp and "Spanning Tree Status" in stp_t:
        warns.append("could not parse 'show spanning-tree status'")
    if warns:
        out["parse_warnings"] = warns
    return out
