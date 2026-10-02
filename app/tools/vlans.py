"""VLAN tool: names/types from `show vlan basic`, port membership from `show vlan members`, I-SIDs from
`show vlan i-sid`, merged by VLAN id. Filters run locally."""
import re

from app.adapters.ssh import SshClient
from app.tools.ssh_tools import CONTAINS_RE, MAX_LINES, _fabric_ssh
from app.tools.tables import body_lines, column_starts, count_ports, slice_row
from app.validation import Inventory, ValidationError

BASIC_COLS = ["ID", "NAME", "TYPE", "INST_ID", "PROTOCOLID", "SUBNETADDR", "SUBNETMASK", "VRFID", "ORIGIN"]
MEMBER_COLS = ["VLAN", "PORT", "ACTIVE", "STATIC", "NOT_ALLOW"]
ISID_COLS = ["VLAN_ID", "I-SID", "VLAN NAME", "I-SID NAME"]


def parse_basic(text: str) -> dict[int, dict]:
    lines, out = body_lines(text), {}
    head = next((i for i, ln in enumerate(lines) if ln.startswith("ID ") and "NAME" in ln), None)
    if head is None:
        return out
    st = column_starts(lines[head], BASIC_COLS)
    for ln in lines[head + 1:]:
        if re.match(r"^\d+\s", ln):
            c = slice_row(ln, st)
            out[int(c[0])] = {"vlan": int(c[0]), "name": c[1], "type": c[2], "vrf_id": int(c[7]) if c[7].isdigit() else None,
                              "origin": c[8]}
    return out


def parse_members(text: str) -> dict[int, dict]:
    lines, out = body_lines(text), {}
    head = next((i for i, ln in enumerate(lines) if ln.startswith("VLAN PORT")), None)
    if head is None:
        return out
    st = column_starts(lines[head], MEMBER_COLS)
    cur = None
    for ln in lines[head + 2:]:
        if not ln.strip() or ln.startswith("All "):
            continue
        c = slice_row(ln, st)
        if re.match(r"^\d+\s*$", c[0]):            # new VLAN row
            cur = int(c[0])
            out[cur] = {"ports": c[1], "active": c[2], "static": c[3], "not_allowed": c[4]}
        elif cur is not None and not c[0]:          # wrapped continuation of the previous row
            for key, val in zip(("ports", "active", "static", "not_allowed"), c[1:]):
                out[cur][key] += val
    return out


def parse_isid(text: str) -> dict[int, dict]:
    lines, out = body_lines(text), {}
    head = next((i for i, ln in enumerate(lines) if ln.startswith("VLAN_ID")), None)
    if head is None:
        return out
    st = column_starts(lines[head], ISID_COLS)
    for ln in lines[head + 1:]:
        if re.match(r"^\d+ out of \d+", ln):          # footer such as '12 out of 12 Total Num of Vlans displayed'
            continue
        if re.match(r"^\d+\s", ln) or re.match(r"^\d+$", ln.strip()):
            c = slice_row(ln, st)
            out[int(c[0])] = {"i_sid": int(c[1]) if c[1].isdigit() else None, "i_sid_name": c[3] or None}
    return out


async def get_vlans(inv: Inventory, ssh: SshClient, switch: str, vlan: int | None = None,
                    name_contains: str | None = None, limit: int = 100) -> dict:
    sw = _fabric_ssh(inv, switch)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LINES:
        raise ValidationError(f"limit must be 1-{MAX_LINES}")
    if vlan is not None and (not isinstance(vlan, int) or isinstance(vlan, bool) or not 1 <= vlan <= 4094):
        raise ValidationError("vlan must be 1-4094")
    if name_contains is not None and not CONTAINS_RE.fullmatch(name_contains):
        raise ValidationError("name_contains: up to 64 letters, digits, space and . _ : / -")
    basic_t, members_t, isid_t = await ssh.run_many(
        sw.management_ip, [{"key": "vlan_basic"}, {"key": "vlan_members"}, {"key": "vlan_isid"}])
    basic, members, isid = parse_basic(basic_t), parse_members(members_t), parse_isid(isid_t)
    rows = []
    for vid in sorted(basic):
        m = members.get(vid, {})
        row = {**basic[vid], **isid.get(vid, {}), "ports": m.get("ports", ""), "active_ports": m.get("active", ""),
               "static_ports": m.get("static", ""), "not_allowed_ports": m.get("not_allowed", "")}
        row["port_count"] = count_ports(row["ports"])
        rows.append(row)
    total = len(rows)
    if vlan is not None:
        rows = [r for r in rows if r["vlan"] == vlan]
    if name_contains:
        rows = [r for r in rows if name_contains.lower() in r["name"].lower()]
    out = {"switch": sw.name, "vlans_on_switch": total, "matched": len(rows), "vlans": rows[:limit],
           "note": "ports are 'slot/port' ranges; active_ports are members that are up/forwarding now, "
                   "static_ports are configured members"}
    if not basic and basic_t.strip() and "Total Num of Vlans" not in basic_t:
        out["parse_warnings"] = ["could not parse 'show vlan basic'; raw output attached"]
        out["raw_output"] = basic_t[:3000]
    return out
