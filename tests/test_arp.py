"""ARP tool. Sample text mirrors the layout printed by Fabric Engine 9.3 (synthetic addresses and MACs)."""
import json

import pytest

from app.adapters.snmp import SnmpClient
from app.adapters.ssh import COMMANDS, SshClient, build_command
from app.audit import Audit
from app.main import build_server
from app.tools.arp import parse_arp
from app.validation import Inventory, Switch, ValidationError

BANNER = ("*" * 84 + "\n\t\tCommand Execution Time: Fri Oct 02 08:40:41 2026 EDT\n" + "*" * 84 + "\n\n")
HEAD = ("=" * 90 + "\n                                  IP Arp - {router}\n" + "=" * 90 + "\n"
        "IP_ADDRESS      MAC_ADDRESS        VLAN  PORT                 TYPE    TTL(10 Sec) TUNNEL            \n"
        + "-" * 90 + "\n")
ROWS = (
    "198.51.100.1    02:00:00:00:00:01  201   -                    LOCAL   2160       \n"
    "198.51.100.10   02:00:00:00:00:0a  201   1/48                 DYNAMIC 64                            \n"
    "198.51.100.11   02:00:00:00:00:AA  201   1/48                 DYNAMIC 62                            \n"
    "198.51.100.2    02:00:00:00:00:02  201   1/12                 DYNAMIC 30                            \n"
    "203.0.113.1     02:00:00:00:01:01  300   -                    LOCAL   2160       \n"
    "203.0.113.50    02:00:00:00:01:32  300   1/12                 DYNAMIC 10                            \n"
    "203.0.113.255   ff:ff:ff:ff:ff:ff  300   -                    LOCAL   2160       \n")
FOOT = "\n\n6 out of 7 ARP entries displayed\n\n\nARPs on TX-NNI: Current = 0, re-ARP count = 0\n"
ARP = BANNER + HEAD.format(router="GlobalRouter") + ROWS + FOOT
ARP_VRF = BANNER + HEAD.format(router="guest") + "192.0.2.77       02:00:00:00:02:02  400   1/5                  DYNAMIC 5\n" + \
    "\n\n1 out of 1 ARP entries displayed\n"
ARP_EMPTY = BANNER + HEAD.format(router="GlobalRouter") + "\n\n0 out of 0 ARP entries displayed\n"
ARP_ODD = BANNER + HEAD.format(router="GlobalRouter") + ROWS + \
    "198.51.100.99   02:00:00:00:00:99  201   MLT 5 odd port       DYNAMIC 7                             \n" + FOOT


class FakeSsh(SshClient):
    def __init__(self, text=None):
        self.text, self.calls = {"arp": ARP, "arp_vrf": ARP_VRF, **(text or {})}, []

    async def run_many(self, ip, jobs, *, timeout=None):
        self.calls.append((ip, [(j["key"], j.get("args", {})) for j in jobs]))
        for j in jobs:
            build_command(j["key"], **j.get("args", {}))          # same validation as the real client
        return [self.text[j["key"]] for j in jobs]


@pytest.fixture
def inv():
    return Inventory([Switch("fab1", "192.0.2.20", "fabric", "T", ("snmpv3", "ssh")),
                      Switch("exos1", "192.0.2.21", "exos", "T", ("snmpv3", "ssh"))])


def server(inv, ssh):
    return build_server(inv, SnmpClient(), Audit(None), ssh)


async def call(mcp, **args):
    res = await mcp.call_tool("get_arp_table", args)
    return json.loads(res[0].text)


def test_commands_are_fixed_shows():
    assert COMMANDS["arp"][0] == "show ip arp"
    assert build_command("arp_vrf", vrf="guest") == "show ip arp vrf guest"
    for bad in ("x; reload", "a b", "$(id)", "", "x" * 17, "-x"):
        with pytest.raises(ValidationError):
            build_command("arp_vrf", vrf=bad)


def test_parse_rows_footer_and_title():
    p = parse_arp(ARP)
    assert p["router"] == "GlobalRouter" and p["displayed_by_switch"] == 6 and p["total_in_switch_table"] == 7
    assert len(p["entries"]) == 7 and not p["unparsed"]
    e = {x["ip"]: x for x in p["entries"]}
    assert e["198.51.100.11"]["mac"] == "02:00:00:00:00:aa" and e["198.51.100.11"]["ttl_seconds"] == 620
    assert e["198.51.100.1"]["port"] is None and e["198.51.100.1"]["type"] == "LOCAL"
    assert e["203.0.113.50"]["vlan"] == 300 and e["203.0.113.50"]["port"] == "1/12"


async def test_full_table_sorted_by_ip_numerically(inv):
    out = await call(server(inv, FakeSsh()), switch="fab1")
    assert [e["ip"] for e in out["entries"]][:4] == ["198.51.100.1", "198.51.100.2", "198.51.100.10", "198.51.100.11"]
    assert out["entries_parsed"] == 7 and out["matched"] == 7 and out["vrf"] == "GlobalRouter"
    assert out["switch_reports"] == {"displayed": 6, "total_in_table": 7}
    assert out["management_ip"] == "192.0.2.20" and "parse_warnings" not in out


async def test_one_fixed_command_and_filters_stay_local(inv):
    ssh = FakeSsh()
    mcp = server(inv, ssh)
    await call(mcp, switch="fab1", contains="02:00:00:00:00:aa", vlan=201, subnet="198.51.100.0/24")
    assert ssh.calls == [("192.0.2.20", [("arp", {})])]


async def test_filters(inv):
    mcp = server(inv, FakeSsh())
    ips = lambda out: [e["ip"] for e in out["entries"]]
    assert ips(await call(mcp, switch="fab1", subnet="203.0.113.0/24")) == ["203.0.113.1", "203.0.113.50", "203.0.113.255"]
    assert ips(await call(mcp, switch="fab1", vlan=300, entry_type="dynamic")) == ["203.0.113.50"]
    assert ips(await call(mcp, switch="fab1", port="1/12")) == ["198.51.100.2", "203.0.113.50"]
    assert ips(await call(mcp, switch="fab1", entry_type="LOCAL"))[0] == "198.51.100.1"
    for frag in ("02:00:00:00:00:aa", "0200.0000.00AA", "02-00-00-00-00-aa", "00:00:aa", "198.51.100.11"):
        assert ips(await call(mcp, switch="fab1", contains=frag)) == ["198.51.100.11"], frag
    out = await call(mcp, switch="fab1", limit=2)
    assert out["matched"] == 7 and out["returned"] == 2 and len(out["entries"]) == 2


async def test_vrf_uses_the_vrf_command(inv):
    ssh = FakeSsh()
    out = await call(server(inv, ssh), switch="fab1", vrf="guest")
    assert ssh.calls == [("192.0.2.20", [("arp_vrf", {"vrf": "guest"})])]
    assert out["vrf"] == "guest" and [e["ip"] for e in out["entries"]] == ["192.0.2.77"]


async def test_empty_table_is_not_a_parse_warning(inv):
    out = await call(server(inv, FakeSsh({"arp": ARP_EMPTY})), switch="fab1")
    assert out["entries_parsed"] == 0 and out["returned"] == 0 and "parse_warnings" not in out


async def test_unparseable_row_is_reported_not_dropped(inv):
    out = await call(server(inv, FakeSsh({"arp": ARP_ODD})), switch="fab1")
    assert out["entries_parsed"] == 7 and out["parse_warnings"]
    assert any("198.51.100.99" in ln for ln in out["unparsed_lines"])


async def test_format_change_flags_raw_output(inv):
    out = await call(server(inv, FakeSsh({"arp": BANNER + "SOMETHING ELSE ENTIRELY\n"})), switch="fab1")
    assert out["parse_warnings"] and "SOMETHING ELSE" in out["raw_output"]


@pytest.mark.parametrize("bad", [
    {"limit": 0}, {"limit": 201}, {"subnet": "192.0.2.0/33"}, {"subnet": "x; reload"}, {"vlan": 0}, {"vlan": 4095},
    {"port": "1/1; reload"}, {"port": "1:48"}, {"entry_type": "DYN;AMIC"}, {"entry_type": "$(id)"},
    {"vrf": "a b"}, {"vrf": "x;y"}, {"vrf": "x" * 17}, {"contains": "a;b"}, {"contains": "$(id)"}])
async def test_bad_arguments_rejected_before_ssh(inv, bad):
    ssh = FakeSsh()
    with pytest.raises(Exception):
        await server(inv, ssh).call_tool("get_arp_table", {"switch": "fab1", **bad})
    assert ssh.calls == []


async def test_rejected_for_exos_unknown_and_when_ssh_disabled(inv):
    ssh = FakeSsh()
    mcp = server(inv, ssh)
    for sw in ("exos1", "203.0.113.9"):
        with pytest.raises(Exception):
            await mcp.call_tool("get_arp_table", {"switch": sw})
    assert ssh.calls == []
    assert "get_arp_table" not in {t.name for t in await build_server(inv, SnmpClient(), Audit(None)).list_tools()}


ERR_VRF = BANNER + "Error: The VRF Name entered does not correspond to any VRF\n"
ERR_GLOBAL = BANNER + "Error: The GlobalRouter cannot be accessed by name. \n"


async def test_switch_error_message_is_passed_through(inv):
    out = await call(server(inv, FakeSsh({"arp_vrf": ERR_VRF})), switch="fab1", vrf="nosuchvrf")
    assert out["switch_error"] == "The VRF Name entered does not correspond to any VRF"
    assert out["parse_warnings"] == ["the switch rejected the request: " + out["switch_error"]]
    assert "raw_output" not in out and "hint" not in out


async def test_globalrouter_by_name_gets_a_hint(inv):
    out = await call(server(inv, FakeSsh({"arp_vrf": ERR_GLOBAL})), switch="fab1", vrf="GlobalRouter")
    assert "cannot be accessed by name" in out["switch_error"] and "omit vrf" in out["hint"]
