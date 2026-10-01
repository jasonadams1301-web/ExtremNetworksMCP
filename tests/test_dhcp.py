"""DHCP tools. The sample text mirrors the layout printed by Fabric Engine 9.3 (synthetic addresses and MACs)."""
import json

import pytest

from app.adapters.snmp import SnmpClient
from app.adapters.ssh import COMMANDS, SshClient
from app.audit import Audit
from app.main import build_server
from app.tools.dhcp import parse_leases, parse_log, parse_relay, parse_settings, parse_subnets
from app.validation import Inventory, Switch

BANNER = ("*" * 84 + "\n\t\tCommand Execution Time: Thu Oct 01 16:04:51 2026 EDT\n" + "*" * 84 + "\n\n")
EQ = "=" * 80 + "\n"
DASH = "-" * 80 + "\n"

SERVER = BANNER + EQ + "                              DHCP Server Settings\n" + EQ + (
    "Status                    : enabled\n\nMgmt-clip status          : enabled\n"
    "Mgmt-clip IP              : 192.0.2.20\nMgmt VRF                  : GlobalRouter\n\nHA peer                   : 0.0.0.0\n")
SERVER_OFF = SERVER.replace("enabled\n\nMgmt-clip status", "disabled\n\nMgmt-clip status", 1)
SUBNETS = BANNER + EQ + "                 DHCP Server Subnets Info\n" + EQ + (
    "SUBNET               IP ADDRESS RANGE                   TOTAL ADDRESSES   LEASED ADDRESSES  \n" + DASH +
    "198.51.100.0/25      198.51.100.10 - 198.51.100.126     117               6                 \n"
    "203.0.113.0/24       203.0.113.10 - 203.0.113.254       245               230               \n"
    "198.18.0.0/22        198.18.0.10 - 198.18.3.254         1013              0                 \n")
SUBNETS_NONE = BANNER + EQ + "Info\n" + EQ + "SUBNET  IP ADDRESS RANGE  TOTAL  LEASED\n" + DASH + DASH + (
    " Total Number of DHCP Server subnets displayed: 0\n") + DASH
HOSTS = BANNER + EQ + "Hosts Info\n" + EQ + "MAC ADDRESS  SUBNET  IP ADDRESS\n" + DASH + DASH + (
    " Total Number of DHCP Server hosts displayed: 2\n") + DASH
LEASES = BANNER + EQ + "DHCP Server Leases Info\n" + EQ + (
    "IP-ADDRESS         MAC-ADDRESS          LAST-TRANSACTION       EXPIRE-TIME           \n" + DASH +
    "198.51.100.10      02:00:00:00:00:01    2026-10-01T08:10:38    2026-10-02T08:10:38   \n"
    "198.51.100.11      02:00:00:00:00:AA    2026-10-01T09:30:00    2026-10-02T09:30:00   \n"
    "203.0.113.50       02:00:00:00:0b:0c    2026-10-01T07:00:00    2026-10-02T07:00:00   \n") + DASH + (
    " Total Number of DHCP Server Leases displayed: 3\n") + DASH
LEASES_NONE = BANNER + EQ + "Leases\n" + EQ + "IP-ADDRESS  MAC-ADDRESS\n" + DASH + DASH + (
    " Total Number of DHCP Server Leases displayed: 0\n") + DASH
COUNTERS = BANNER + EQ + "                 DHCP Counters - GlobalRouter\n" + EQ + (
    "INTERFACE       IP_ADDRESS            REQUESTS        REPLIES \n" + DASH +
    "Vlan10          198.51.100.1          1412            1194    \n"
    "Vlan200         203.0.113.1           0               0       \n"
    "Vlan300         198.18.0.1            40              0       \n")
FWD = BANNER + EQ + "                 DHCP Fwd-path - GlobalRouter\n" + EQ + (
    "INTERFACE       SERVER           ENABLE  MODE            SRC PORT 67\n" + DASH +
    "198.51.100.1    192.0.2.50       TRUE    DHCP            FALSE      \n"
    "198.51.100.1    192.0.2.51       TRUE    DHCP & BOOTP    FALSE      \n"
    "203.0.113.1     192.0.2.50       FALSE   DHCP            FALSE      \n")
LOG = "\n".join([
    "2026-10-01 09:53:01.232.849 INFO  COMMAND_RECEIVED Received command 'stat-lease4-get'",
    "2026-10-01 09:53:01.233.079 INFO  STAT_CMDS_LEASE4_GET stat-lease4-get command successful",
    "2026-10-01 09:54:09.633.620 INFO  DHCP4_LEASE_ALLOC [hwtype=1 02:00:00:00:00:01], tid=0x1: lease 198.51.100.10 allocated",
    "2026-10-01 09:55:00.000.001 WARN  DHCP4_PACKET_DROP [hwtype=1 02:00:00:00:00:AA]: dropped, no subnet",
    "2026-10-01 09:56:00.000.002 ERROR DHCP4_LEASE_ALLOC_FAIL [hwtype=1 02:00:00:00:00:BB]: no addresses left",
    "2026-10-01 09:57:00.000.003 INFO  COMMAND_RECEIVED Received command 'stat-lease4-get'"]) + "\n"
LOG_EMPTY = BANNER

TEXT = {"dhcp_server": SERVER, "dhcp_subnets": SUBNETS, "dhcp_hosts": HOSTS, "dhcp_leases": LEASES,
        "dhcp_log": LOG, "dhcp_relay_counters": COUNTERS, "dhcp_relay_fwd": FWD}


class FakeSsh(SshClient):
    def __init__(self, text=None):
        self.text, self.calls = dict(TEXT, **(text or {})), []

    async def run_many(self, ip, jobs, *, timeout=None):
        self.calls.append((ip, [j["key"] for j in jobs]))
        for j in jobs:
            assert j["key"] in COMMANDS and not j.get("args")     # only fixed, argument-free commands
        return [self.text[j["key"]] for j in jobs]


@pytest.fixture
def inv():
    return Inventory([Switch("fab1", "192.0.2.20", "fabric", "T", ("snmpv3", "ssh")),
                      Switch("exos1", "192.0.2.21", "exos", "T", ("snmpv3", "ssh"))])


def server(inv, ssh):
    return build_server(inv, SnmpClient(), Audit(None), ssh)


async def call(mcp, tool, **args):
    res = await mcp.call_tool(tool, args)
    return json.loads(res[0].text)


# ---- parsers ----
def test_parse_settings_skips_banner_and_reads_pairs():
    s = parse_settings(SERVER)
    assert s["Status"] == "enabled" and s["Mgmt-clip IP"] == "192.0.2.20" and s["HA peer"] == "0.0.0.0"
    assert not any(k.startswith("Command") for k in s)


def test_parse_subnets_utilization():
    rows = parse_subnets(SUBNETS)
    assert [r["subnet"] for r in rows] == ["198.51.100.0/25", "203.0.113.0/24", "198.18.0.0/22"]
    assert rows[0]["utilization_percent"] == 5.1 and rows[1]["utilization_percent"] == 93.9
    assert rows[2]["utilization_percent"] == 0.0 and rows[0]["range_end"] == "198.51.100.126"


def test_parse_leases_normalizes_mac():
    rows = parse_leases(LEASES)
    assert len(rows) == 3 and rows[1]["mac"] == "02:00:00:00:00:aa" and rows[0]["expires"].startswith("2026-10-02")


def test_parse_relay_merges_counters_and_forwarding():
    rows = parse_relay(COUNTERS, FWD)
    by = {r["relay_ip"]: r for r in rows}
    assert by["198.51.100.1"]["interface"] == "Vlan10" and by["198.51.100.1"]["reply_percent"] == 84.6
    assert [s["mode"] for s in by["198.51.100.1"]["servers"]] == ["DHCP", "DHCP & BOOTP"]
    assert by["203.0.113.1"]["servers"][0]["enabled"] is False and by["203.0.113.1"]["reply_percent"] is None


def test_parse_log_oldest_first():
    rows = parse_log(LOG)
    assert len(rows) == 6 and rows[0]["event"] == "COMMAND_RECEIVED" and rows[3]["level"] == "WARN"
    assert rows[2]["time"] == "2026-10-01 09:54:09"


# ---- tools ----
async def test_server_tool_flags_nearly_full_subnet(inv):
    out = await call(server(inv, FakeSsh()), "get_dhcp_server", switch="fab1")
    assert out["enabled"] is True and len(out["subnets"]) == 3 and out["host_reservations"] == 2
    assert out["attention"] == ["subnet 203.0.113.0/24 is 93.9% leased (230/245)"]
    assert "parse_warnings" not in out


async def test_server_tool_uses_one_login_for_three_commands(inv):
    ssh = FakeSsh()
    await call(server(inv, ssh), "get_dhcp_server", switch="fab1")
    assert ssh.calls == [("192.0.2.20", ["dhcp_server", "dhcp_subnets", "dhcp_hosts"])]


async def test_server_tool_relay_only_switch_reports_disabled(inv):
    ssh = FakeSsh({"dhcp_server": SERVER_OFF, "dhcp_subnets": SUBNETS_NONE})
    out = await call(server(inv, ssh), "get_dhcp_server", switch="fab1")
    assert out["enabled"] is False and out["subnets"] == [] and "parse_warnings" not in out


async def test_unparseable_output_is_flagged_not_hidden(inv):
    ssh = FakeSsh({"dhcp_subnets": BANNER + "SUBNET FORMAT CHANGED 198.51.100.0/25 something else\n"})
    out = await call(server(inv, ssh), "get_dhcp_server", switch="fab1")
    assert out["parse_warnings"] and "198.51.100.0/25" in out["raw_output"]["dhcp_subnets"]


async def test_leases_filters_and_ordering(inv):
    mcp = server(inv, FakeSsh())
    out = await call(mcp, "get_dhcp_leases", switch="fab1")
    assert out["total_leases_on_switch"] == 3 and out["matched"] == 3
    assert [x["ip"] for x in out["leases"]] == ["198.51.100.11", "198.51.100.10", "203.0.113.50"]  # recent first
    assert [x["ip"] for x in (await call(mcp, "get_dhcp_leases", switch="fab1", subnet="198.51.100.0/24"))["leases"]] \
        == ["198.51.100.11", "198.51.100.10"]
    for frag in ("02:00:00:00:00:aa", "0200.0000.00AA", "02-00-00-00-00-aa", "00:00:aa"):
        out = await call(mcp, "get_dhcp_leases", switch="fab1", contains=frag)
        assert [x["ip"] for x in out["leases"]] == ["198.51.100.11"], frag
    assert (await call(mcp, "get_dhcp_leases", switch="fab1", limit=1))["leases"][0]["ip"] == "198.51.100.11"


async def test_leases_empty_table_is_not_a_parse_warning(inv):
    out = await call(server(inv, FakeSsh({"dhcp_leases": LEASES_NONE})), "get_dhcp_leases", switch="fab1")
    assert out["total_leases_on_switch"] == 0 and "parse_warnings" not in out


@pytest.mark.parametrize("bad", [{"limit": 0}, {"limit": 201}, {"subnet": "192.0.2.0/33"}, {"subnet": "x; reload"},
                                 {"contains": "a;b"}, {"contains": "$(id)"}])
async def test_leases_bad_arguments_rejected_before_ssh(inv, bad):
    ssh = FakeSsh()
    with pytest.raises(Exception):
        await server(inv, ssh).call_tool("get_dhcp_leases", {"switch": "fab1", **bad})
    assert ssh.calls == []


async def test_relay_tool_attention_on_requests_without_replies(inv):
    ssh = FakeSsh()
    out = await call(server(inv, ssh), "get_dhcp_relay", switch="fab1")
    assert out["attention"] == ["Vlan300 198.18.0.1: 40 requests, no replies"]
    assert ssh.calls == [("192.0.2.20", ["dhcp_relay_counters", "dhcp_relay_fwd"])]
    assert len(out["relay_interfaces"]) == 3 and "parse_warnings" not in out


async def test_log_hides_noise_and_is_newest_first(inv):
    out = await call(server(inv, FakeSsh()), "get_dhcp_server_log", switch="fab1")
    assert out["order"] == "newest first" and out["entries_in_log"] == 6 and out["returned"] == 3
    assert [e["event"] for e in out["entries"]] == ["DHCP4_LEASE_ALLOC_FAIL", "DHCP4_PACKET_DROP", "DHCP4_LEASE_ALLOC"]
    assert out["oldest_entry_in_log"] == "2026-10-01 09:53:01" and out["newest_entry_in_log"] == "2026-10-01 09:57:00"


async def test_log_filters(inv):
    mcp = server(inv, FakeSsh())
    assert (await call(mcp, "get_dhcp_server_log", switch="fab1", include_noise=True))["returned"] == 6
    out = await call(mcp, "get_dhcp_server_log", switch="fab1", level="warning")
    assert [e["level"] for e in out["entries"]] == ["ERROR", "WARN"]
    out = await call(mcp, "get_dhcp_server_log", switch="fab1", contains="02:00:00:00:00:aa")
    assert [e["event"] for e in out["entries"]] == ["DHCP4_PACKET_DROP"]
    assert (await call(mcp, "get_dhcp_server_log", switch="fab1", lines=1))["entries"][0]["level"] == "ERROR"


async def test_empty_log_is_not_a_parse_warning(inv):
    out = await call(server(inv, FakeSsh({"dhcp_log": LOG_EMPTY})), "get_dhcp_server_log", switch="fab1")
    assert out["returned"] == 0 and out["oldest_entry_in_log"] is None and out["newest_entry_in_log"] is None and "parse_warnings" not in out


@pytest.mark.parametrize("bad", [{"lines": 0}, {"lines": 201}, {"level": "TRACE"}, {"contains": "a|b"}])
async def test_log_bad_arguments_rejected(inv, bad):
    ssh = FakeSsh()
    with pytest.raises(Exception):
        await server(inv, ssh).call_tool("get_dhcp_server_log", {"switch": "fab1", **bad})
    assert ssh.calls == []


@pytest.mark.parametrize("tool", ["get_dhcp_server", "get_dhcp_leases", "get_dhcp_relay", "get_dhcp_server_log"])
async def test_dhcp_tools_reject_exos_unknown_and_unregistered_without_ssh(inv, tool):
    ssh = FakeSsh()
    mcp = server(inv, ssh)
    for sw in ("exos1", "203.0.113.1"):
        with pytest.raises(Exception):
            await mcp.call_tool(tool, {"switch": sw})
    assert ssh.calls == []
    off = build_server(inv, SnmpClient(), Audit(None))
    assert tool not in {t.name for t in await off.list_tools()}
