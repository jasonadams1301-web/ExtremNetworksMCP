"""Privileged-mode tools (interface detail, optics, NTP, MLT). Samples mirror Fabric Engine output (synthetic values)."""
import json

import pytest

from app.adapters.snmp import SnmpClient
from app.adapters.ssh import PRIVILEGED, SshClient, build_command
from app.audit import Audit
from app.main import build_server
from app.tools.privileged import split_optics_detail, tidy
from app.validation import Inventory, Switch

BANNER = ("*" * 84 + "\n\t\tCommand Execution Time: Fri Oct 02 09:00:00 2026 EDT\n" + "*" * 84 + "\n\n")
EQ, DASH = "=" * 90 + "\n", "-" * 90 + "\n"

IFACE = BANNER + EQ + "                       Port Interface\n" + EQ + (
    "PORT                               LINK  PORT           PHYSICAL          STATUS\n"
    "NUM      INDEX DESCRIPTION         TRAP  LOCK     MTU   ADDRESS           ADMIN  OPERATE\n") + DASH + \
    "1/9      200   10GbCX              true  false    9600  02:00:00:00:09:08 up     up     \n"
STATS = BANNER + "Please widen the terminal for optimal viewing of data.\n" + EQ + "                Port Stats Interface\n" + EQ + (
    "PORT     IN                  OUT                  IN                   OUT\n"
    "NUM      OCTETS               OCTETS               PACKET               PACKET\n") + DASH + \
    "1/9      147990523685665      245699160225058      114229891274         183760770264\n"
ERRORS = BANNER + EQ + "                Port Ethernet Error\n" + EQ + (
    "PORT     ERROR   ERROR   FRAMES  TOO     LINK    CARRIER CARRIER SQETEST IN\n"
    "NUM      ALIGN   FCS     LONG    SHORT   FAILURE SENSE   ERRORS  ERRORS  DISCARD\n") + DASH + \
    "1/9      0       0       0       0       110     0       0       0       12\n"

OPTICS_BASIC = BANNER + EQ + "                Pluggable Optical Module Info\n" + EQ + (
    "PORT                  DDM\nNUM    TYPE           SUPPORTED          VENDOR NAME        PART NUMBER        SKU\n") + DASH + (
    "1/1    10GbCX         FALSE              Vendor A           PN-0001\n"
    "1/49   100GbSR4       TRUE               Vendor B           PN-0002\n")
HDR = EQ + "                    Pluggable Optical Module Info {p} Detail\n" + EQ
OPTICS_DETAIL = BANNER + HDR.format(p="1/1") + (
    "Port: 1/1\nType: 10GbCX\nDDM Supported : FALSE\nVendor Name  : Vendor A\nVendor SN  : SN-AAA-1\n"
    "Extreme Extended Diagnostic Information\n" + DASH + "Not Available \n") + HDR.format(p="1/49") + (
    "Port: 1/49\nType: 100GbSR4\nDDM Supported : TRUE\nVendor Name  : Vendor B\nVendor SN  : SN-BBB-2\n"
    "Temperature : 38.5 C\nTx Power : -1.2 dBm\nRx Power : -3.4 dBm\n")

NTP_SERVER = BANNER + EQ + "                NTP Server\n" + EQ + (
    "Server Ip                                Enabled Auth    Key Id     Auth Type\n") + DASH + (
    "192.0.2.50                               true    false   0          N/A\n"
    "198.51.100.7                             false   false   0          N/A\n")
NTP_STATS = ("              NTP Server : 192.0.2.50\n------------------------------------------\n"
             "                 Stratum : 4\n             Sync Status : System Peer\n            Reachability : Reachable\n")
MLT_NONE = BANNER + EQ + "                Mlt Info\n" + EQ + "MLTID IFINDEX NAME\n" + DASH + \
    "All 0 out of 0 Total Num of mlt displayed\n"
MLT_ONE = BANNER + EQ + "                Mlt Info\n" + EQ + "MLTID IFINDEX NAME\n" + DASH + \
    "1     6144    uplink1   trunk  norm  up   1/53,1/54\nAll 1 out of 1 Total Num of mlt displayed\n"

TEXT = {"interface": IFACE, "interface_stats": STATS, "interface_errors": ERRORS, "optics_basic": OPTICS_BASIC,
        "optics_detail": OPTICS_DETAIL, "ntp_server": NTP_SERVER, "ntp_stats": NTP_STATS, "mlt": MLT_NONE}


class FakeSsh(SshClient):
    def __init__(self, text=None):
        self.text, self.calls = dict(TEXT, **(text or {})), []

    async def run_many(self, ip, jobs, *, timeout=None):
        self.calls.append((ip, [(j["key"], j.get("args", {})) for j in jobs]))
        for j in jobs:
            build_command(j["key"], **j.get("args", {}))
        return [self.text[j["key"]] for j in jobs]


@pytest.fixture
def inv():
    return Inventory([Switch("fab1", "192.0.2.20", "fabric", "T", ("snmpv3", "ssh")),
                      Switch("exos1", "192.0.2.21", "exos", "T", ("snmpv3", "ssh"))])


def server(inv, ssh):
    return build_server(inv, SnmpClient(), Audit(None), ssh)


async def call(mcp, tool, **args):
    return json.loads((await mcp.call_tool(tool, args))[0].text)


def test_all_these_commands_are_privileged_and_never_mixed_with_unprivileged_ones():
    for key in ("interface", "interface_stats", "interface_errors", "optics_basic", "optics_detail", "ntp_server",
                "ntp_stats", "mlt"):
        assert key in PRIVILEGED
    assert build_command("interface", port="1/9") == "show interfaces gigabitEthernet interface 1/9"
    assert build_command("optics_detail") == "show pluggable-optical-modules detail"


def test_tidy_removes_banner_and_pager_notice():
    out = tidy(STATS)
    assert "Command Execution Time" not in out and "widen" not in out and out.startswith("=")


async def test_interface_detail_runs_three_fixed_commands_in_one_session(inv):
    ssh = FakeSsh()
    out = await call(server(inv, ssh), "get_interface_detail", switch="fab1", port="1/9")
    assert ssh.calls == [("192.0.2.20", [("interface", {"port": "1/9"}), ("interface_stats", {"port": "1/9"}),
                                         ("interface_errors", {"port": "1/9"})])]
    assert "10GbCX" in out["interface"] and "147990523685665" in out["statistics"] and "110" in out["errors"]
    assert out["management_ip"] == "192.0.2.20" and "Command Execution" not in out["interface"]


@pytest.mark.parametrize("bad", ["1/9; reload", "$(id)", "1:48", "", "1/9\nconf t", "x"])
async def test_interface_detail_rejects_bad_ports_before_ssh(inv, bad):
    ssh = FakeSsh()
    with pytest.raises(Exception):
        await server(inv, ssh).call_tool("get_interface_detail", {"switch": "fab1", "port": bad})
    assert ssh.calls == []


def test_optics_detail_is_split_per_port_without_the_next_modules_header():
    blocks = split_optics_detail(OPTICS_DETAIL)
    assert set(blocks) == {"1/1", "1/49"}
    assert "Tx Power : -1.2 dBm" in blocks["1/49"] and "Pluggable Optical Module Info" not in blocks["1/1"]
    assert "SN-AAA-1" in blocks["1/1"] and "SN-BBB-2" not in blocks["1/1"]


async def test_get_optics_without_a_port_only_reads_the_table(inv):
    ssh = FakeSsh()
    out = await call(server(inv, ssh), "get_optics", switch="fab1")
    assert ssh.calls == [("192.0.2.20", [("optics_basic", {})])] and "PN-0002" in out["modules_table"] and "detail" not in out


async def test_get_optics_with_a_port_returns_light_levels(inv):
    ssh = FakeSsh()
    mcp = server(inv, ssh)
    out = await call(mcp, "get_optics", switch="fab1", port="1/49")
    assert [k for k, _ in ssh.calls[0][1]] == ["optics_basic", "optics_detail"]
    assert out["ddm_supported"] is True and "Rx Power : -3.4 dBm" in out["detail"]
    out = await call(mcp, "get_optics", switch="fab1", port="1/1")
    assert out["ddm_supported"] is False
    out = await call(mcp, "get_optics", switch="fab1", port="1/7")
    assert out["detail"] is None and out["ddm_supported"] is None and "no optical module" in out["detail_note"]


async def test_get_ntp_status_lists_servers_and_stats(inv):
    ssh = FakeSsh()
    out = await call(server(inv, ssh), "get_ntp_status", switch="fab1")
    assert ssh.calls == [("192.0.2.20", [("ntp_server", {}), ("ntp_stats", {})])]
    assert out["servers"] == [{"server": "192.0.2.50", "enabled": True}, {"server": "198.51.100.7", "enabled": False}]
    assert "System Peer" in out["statistics"] and "Reachable" in out["statistics"]


async def test_get_mlt_status_detects_none_and_some(inv):
    out = await call(server(inv, FakeSsh()), "get_mlt_status", switch="fab1")
    assert out["mlt_configured"] is False and "All 0 out of 0" in out["output"]
    out = await call(server(inv, FakeSsh({"mlt": MLT_ONE})), "get_mlt_status", switch="fab1")
    assert out["mlt_configured"] is True and "uplink1" in out["output"]


@pytest.mark.parametrize("tool,args", [("get_interface_detail", {"port": "1/9"}), ("get_optics", {}),
                                       ("get_ntp_status", {}), ("get_mlt_status", {})])
async def test_rejected_for_exos_and_unknown_and_hidden_without_ssh(inv, tool, args):
    ssh = FakeSsh()
    mcp = server(inv, ssh)
    for sw in ("exos1", "203.0.113.9"):
        with pytest.raises(Exception):
            await mcp.call_tool(tool, {"switch": sw, **args})
    assert ssh.calls == []
    assert tool not in {t.name for t in await build_server(inv, SnmpClient(), Audit(None)).list_tools()}
