"""VLAN, routing, fabric, auth and port-summary tools. Samples mirror the layouts printed by Fabric Engine 9.3
(synthetic names, addresses and MACs)."""
import json

import pytest

from app.adapters.snmp import SnmpClient
from app.adapters.ssh import COMMANDS, SshClient, SshError, build_command
from app.audit import Audit
from app.main import build_server
from app.tools.auth import parse_eapol, parse_reachability
from app.tools.fabric import parse_isis_interfaces, parse_spbm, parse_stp, parse_system_id
from app.tools.routing import lookup, parse_interfaces, parse_routes
from app.tools.tables import count_ports
from app.tools.vlans import parse_basic, parse_isid, parse_members
from app.validation import Inventory, Switch

BANNER = ("*" * 84 + "\n\t\tCommand Execution Time: Fri Oct 02 08:40:41 2026 EDT\n" + "*" * 84 + "\n\n")
EQ, DASH = "=" * 100 + "\n", "-" * 100 + "\n"


def rule(title):
    return EQ + f"{title:^100}\n" + EQ


# ---------------- VLANs ----------------
def basic_row(vid, name, typ="byPort", inst=0, vrf=0, origin="CONFIG"):
    return f"{vid:<6}{name:<17}{typ:<13}{inst:<8}{'none':<13}{'N/A':<16}{'N/A':<16}{vrf:<6}{origin}\n"


VLAN_BASIC = BANNER + rule("Vlan Basic") + (
    f"{'VLAN':<36}{'MSTP':<7}\n" + f"{'ID':<6}{'NAME':<17}{'TYPE':<13}{'INST_ID':<8}{'PROTOCOLID':<13}{'SUBNETADDR':<16}"
    f"{'SUBNETMASK':<16}{'VRFID':<6}{'ORIGIN'}\n") + DASH + basic_row(1, "Default") + basic_row(10, "Staff LAN") + \
    basic_row(91, "Voice") + basic_row(4051, "BVLAN4051", "spbm-bvlan", 62) + "All 4 out of 4 Total Num of Vlans displayed\n"


def member_row(vid, ports="", active="", static="", na=""):
    return f"{vid:<5}{ports:<19}{active:<19}{static:<19}{na}\n"


VLAN_MEMBERS = BANNER + rule("Vlan Port") + (
    f"{'VLAN':<5}{'PORT':<19}{'ACTIVE':<19}{'STATIC':<19}{'NOT_ALLOW':<10}\n"
    f"{'ID':<5}{'MEMBER':<19}{'MEMBER':<19}{'MEMBER':<19}{'MEMBER':<10}\n") + DASH + \
    member_row(1) + member_row(10, "1/1-1/2,1/5-1/45,", "1/1-1/2,1/5-1/45,") + member_row("", "1/47-1/52", "1/47-1/52") + \
    member_row(91, "1/48", "1/48", "", "1/3") + member_row(4051) + "All 4 out of 4 Total Num of Port Entries displayed\n"


def isid_row(vid, isid="", name="", isname=""):
    return f"{vid:<11}{isid:<21}{name:<33}{isname}\n"


VLAN_ISID = BANNER + rule("Vlan I-SID") + (
    f"{'VLAN_ID':<11}{'I-SID':<21}{'VLAN NAME':<33}{'I-SID NAME':<32}\n") + DASH + isid_row(1) + \
    isid_row(10, "298010", "Staff LAN", "ISID-298010") + isid_row(91, "298091", "Voice", "ISID-298091") + isid_row(4051) + \
    "4 out of 4 Total Num of Vlans displayed\n"

# ---------------- routing ----------------
IP_IF = BANNER + rule("IP Interface - GlobalRouter") + (
    "INTERFACE    IP               NET              ADMIN      OPER     VLAN  BROUTER    IPSEC   IP\n"
    "             ADDRESS          MASK             STATUS     STATE    ID    PORT       STATE   NAME\n") + DASH + (
    "Clip1        192.0.2.1        255.255.255.255  enable     up       --    false      disable\n"
    "Vlan10       198.51.100.1     255.255.254.0    enable     up       10    false      disable\n"
    "Vlan91       203.0.113.1      255.255.255.0    enable     down     91    false      disable   voice-gw\n"
    "Vlan99       192.0.2.65       255.255.255.192  disable    down     99    false      disable\n")


def route_row(dst, mask, nh, vrf, cost, face, prot, age, typ, pref):
    return f"{dst:<16}{mask:<16}{nh:<21}{vrf:<17}{cost:<7}{face:<9}{prot:<5}{age:<4}{typ:<7}{pref}\n"


IP_ROUTE = BANNER + rule("IP Route - GlobalRouter") + (
    "                                                     NH                      INTER   \n"
    "DST             MASK            NEXT                 VRF/ISID         COST   FACE     PROT AGE TYPE   PRF\n") + DASH + \
    route_row("0.0.0.0", "0.0.0.0", "192.0.2.254", "GlobalRouter", 1, 172, "STAT", 0, "IB", 5) + \
    route_row("198.51.100.0", "255.255.254.0", "198.51.100.1", "-", 1, 10, "LOC", 0, "DB", 0) + \
    route_row("198.51.100.128", "255.255.255.128", "198.51.100.200", "-", 7, 55, "ISIS", 3, "IBE", 7) + \
    route_row("203.0.113.0", "255.255.255.0", "203.0.113.1", "-", 1, 91, "LOC", 0, "DB", 0) + \
    route_row("203.0.113.0", "255.255.255.0", "203.0.113.9", "-", 9, 56, "ISIS", 3, "IA", 7) + \
    "5 out of 5 Total Num of Route Entries, 4 Total Num of Dest Networks displayed.\n" + DASH + "TYPE Legend:\nI=Indirect Route\n"

# ---------------- fabric ----------------
SPBM = BANNER + rule("ISIS SPBM Info") + (
    "SPBM       B-VID      PRIMARY    NICK     LSDB     IP       IPV6     MULTICAST  SPB-PIM-GW         STP-MULTI  ORIGIN  \n"
    "INSTANCE              VLAN       NAME     TRAP                                                     HOMING          \n") + DASH + (
    "1          4051-4052  4051       2.40.98  disable  enable   disable  disable    N/A                disable    config  \n"
    + rule("ISIS SPBM SMLT Info") + "SPBM       SMLT-SPLIT-BEB       SMLT-VIRTUAL-BMAC    SMLT-PEER-SYSTEM-ID \n" + DASH +
    "1          primary              00:00:00:00:00:00                        \n") + " Total Num of SPBM instances: 1\n"
SYSID = BANNER + rule("ISIS System-Id") + "SYSTEM-ID                AREA                 AREA-NAME           \n" + DASH + \
    "0049.0240.9800           HOME                                     \n"


def isis_row(name, oper, adm="UP", adj=0, upadj=0, metric=1000):
    return (f"{name:<18}{'pt-pt':<8}{'Level 1':<10}{oper:<8}{adm:<8}{adj:<7}{upadj:<8}{metric:<13}{metric:<13}"
            f"{'CONFIG':<11}{'HOME'}\n")


ISIS_IF = BANNER + rule("ISIS Interfaces") + (
    "INTERFACE         TYPE    LEVEL     OPER    ADM     ADJ    UP      ADM-SPBM     OPER-SPBM    ORIGIN     AREA       AREA-NAME      \n"
    "                                    STATE   STATE          ADJ     L1-METRIC    L1-METRIC                                         \n") + DASH + \
    isis_row("SiteA", "DOWN") + isis_row("SiteB", "DOWN") + isis_row("Core1", "UP", adj=1, upadj=1) + \
    "Legend:\n(A): l1 metric is automatically updated based on detected interface speed.\n"
ADJ_NONE = BANNER + rule("ISIS Adjacencies") + "INTERFACE  L STATE\n" + DASH + DASH + \
    "Home:   0 out of 0 interfaces have formed an adjacency\n"
ADJ_ONE = ADJ_NONE.replace("0 out of 0", "1 out of 3")
STP = BANNER + rule("Spanning Tree Status") + (
    "STG  BRIDGE            NUM   PROTOCOL      TOP     \nID   ADDRESS           PORTS SPECIFICATION CHANGES \n") + DASH + (
    "0    02:00:00:00:00:01 52    ieee8021s     36      \n62   00:00:00:00:00:00 0     ieee8021s     0       \n"
    "STG  DESIGNATED              ROOT  ROOT  MAX  HELLO  HOLD  FORWARD \nID   ROOT                    COST  PORT  AGE  TIME   TIME  DELAY   \n") + DASH + (
    "0    20:00:02:00:00:00:00:01 0     cpp   20   0      1     15      \n62   00:00:00:00:00:00:00:00 0     cpp   0    0      0     0       \n"
    "Total number of Spanning Tree IDs :  2\n")

# ---------------- auth ----------------
EAPOL = "EAP Clients (total):           0\nNEAP Radius Clients (total):   2\nNEAP LLDP Clients (total):     0\n"
RADIUS = ("\tEAP RADIUS reachability mode   : use-radius\n\tEAP RADIUS reachability status : unreachable\n"
          "\tEAP RADIUS reachable server    : none\n\tTime until next check          : 60\n"
          "\tRADIUS username                : testuser\n\tRADIUS password                : hunter2secret\n"
          "\tRADIUS keep-alive-timer        : 180\n")

TEXT = {"vlan_basic": VLAN_BASIC, "vlan_members": VLAN_MEMBERS, "vlan_isid": VLAN_ISID, "ip_interface": IP_IF,
        "ip_route": IP_ROUTE, "isis_spbm": SPBM, "isis_system_id": SYSID, "isis_interface": ISIS_IF,
        "isis_adjacencies": ADJ_NONE, "stp_status": STP, "eapol_summary": EAPOL, "radius_reachability": RADIUS}


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


def server(inv, ssh=None, snmp=None):
    return build_server(inv, snmp or SnmpClient(), Audit(None), ssh)


async def call(mcp, tool, **args):
    return json.loads((await mcp.call_tool(tool, args))[0].text)


# ---------------- commands / adapter safeguards ----------------
def test_new_commands_are_fixed_plain_shows():
    for key in ("vlan_basic", "vlan_members", "vlan_isid", "ip_interface", "ip_route", "isis_spbm", "isis_interface",
                "isis_system_id", "stp_status", "eapol_summary", "radius_reachability"):
        assert COMMANDS[key][0].startswith("show ") and not COMMANDS[key][1]
    assert build_command("ip_route_vrf", vrf="guest") == "show ip route vrf guest"
    assert "interface_stats" not in COMMANDS and "interface" not in COMMANDS      # never worked for this account


def test_count_ports():
    assert count_ports("1/1-1/2,1/5-1/45,1/47-1/52") == 2 + 41 + 6
    assert count_ports("1/48") == 1 and count_ports("") == 0 and count_ports("1/1-2/4") is None and count_ports("x") is None


async def test_switch_rejected_command_becomes_a_clear_error(monkeypatch, tmp_path):
    from app.adapters import ssh as ssh_mod

    async def fake_drive(proc, jobs, timeout):
        return ["                ^\n% Invalid input detected at '^' marker."]

    class Conn:
        async def create_process(self, **kw):
            return object()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(ssh_mod, "drive_commands", fake_drive)
    monkeypatch.setattr(ssh_mod.asyncssh, "connect", lambda *a, **k: Conn())
    monkeypatch.setenv("SSH_USERNAME", "ro")
    monkeypatch.setenv("SSH_PASSWORD", "x")
    kh = tmp_path / "kh"
    kh.write_text("x")
    monkeypatch.setenv("SSH_KNOWN_HOSTS", str(kh))
    with pytest.raises(SshError, match="rejected the command 'show sys-info'"):
        await SshClient().run("192.0.2.20", "sys_info")


# ---------------- VLANs ----------------
def test_vlan_parsers_handle_names_with_spaces_and_wrapped_members():
    basic, members, isid = parse_basic(VLAN_BASIC), parse_members(VLAN_MEMBERS), parse_isid(VLAN_ISID)
    assert basic[10]["name"] == "Staff LAN" and basic[4051]["type"] == "spbm-bvlan" and len(basic) == 4
    assert members[10]["ports"] == "1/1-1/2,1/5-1/45,1/47-1/52" and members[10]["active"] == "1/1-1/2,1/5-1/45,1/47-1/52"
    assert members[91]["not_allowed"] == "1/3" and members[1]["ports"] == ""
    assert isid[10] == {"i_sid": 298010, "i_sid_name": "ISID-298010"} and isid[4051]["i_sid"] is None


async def test_get_vlans_merges_three_tables_in_one_session(inv):
    ssh = FakeSsh()
    out = await call(server(inv, ssh), "get_vlans", switch="fab1")
    assert ssh.calls == [("192.0.2.20", [("vlan_basic", {}), ("vlan_members", {}), ("vlan_isid", {})])]
    v = {x["vlan"]: x for x in out["vlans"]}
    assert out["vlans_on_switch"] == 4 and v[10]["i_sid"] == 298010 and v[10]["port_count"] == 49
    assert v[91]["ports"] == "1/48" and out["management_ip"] == "192.0.2.20" and "parse_warnings" not in out


async def test_get_vlans_filters(inv):
    mcp = server(inv, FakeSsh())
    assert [x["vlan"] for x in (await call(mcp, "get_vlans", switch="fab1", vlan=91))["vlans"]] == [91]
    assert [x["vlan"] for x in (await call(mcp, "get_vlans", switch="fab1", name_contains="staff"))["vlans"]] == [10]


# ---------------- routing ----------------
def test_routing_parsers():
    ifs, bad, router = parse_interfaces(IP_IF)
    assert router == "GlobalRouter" and not bad and len(ifs) == 4
    v91 = next(i for i in ifs if i["interface"] == "Vlan91")
    assert v91["oper"] == "down" and v91["prefix_length"] == 24 and v91["vlan"] == "91" and v91["name"] == "voice-gw"
    assert next(i for i in ifs if i["interface"] == "Clip1")["vlan"] is None
    routes, bad, _ = parse_routes(IP_ROUTE)
    assert len(routes) == 5 and not bad and routes[0]["network"] == "0.0.0.0/0" and routes[2]["protocol"] == "ISIS"


def test_lookup_is_longest_prefix_and_prefers_best_routes():
    import ipaddress
    routes, _, _ = parse_routes(IP_ROUTE)
    ip = ipaddress.IPv4Address
    assert lookup(routes, ip("198.51.100.200"))["next_hop"] == "198.51.100.200"        # the /25 beats the /23
    assert lookup(routes, ip("198.51.101.5"))["network"] == "198.51.100.0/23"
    assert lookup(routes, ip("203.0.113.7"))["protocol"] == "LOC"                       # best route over alternative
    assert lookup(routes, ip("8.8.8.8"))["network"] == "0.0.0.0/0"
    assert lookup([r for r in routes if r["network"] != "0.0.0.0/0"], ip("8.8.8.8")) is None


async def test_get_routing_report(inv):
    ssh = FakeSsh()
    out = await call(server(inv, ssh), "get_routing", switch="fab1", destination="198.51.100.200")
    assert ssh.calls == [("192.0.2.20", [("ip_interface", {}), ("ip_route", {})])]
    assert out["lookup"]["result"] == "198.51.100.128/25 via 198.51.100.200 on interface 55 (ISIS)"
    assert out["interfaces_down"] == ["Vlan91 203.0.113.1"]
    assert out["default_route"]["next_hop"] == "192.0.2.254" and out["route_protocols"] == {"ISIS": 2, "LOC": 2, "STAT": 1}
    assert out["routes_in_table"] == 5 and "parse_warnings" not in out


async def test_get_routing_filters_and_vrf(inv):
    ssh = FakeSsh({"ip_route_vrf": IP_ROUTE, "ip_interface_vrf": IP_IF})
    mcp = server(inv, ssh)
    out = await call(mcp, "get_routing", switch="fab1", protocol="isis")
    assert out["routes_matched"] == 2 and all(r["protocol"] == "ISIS" for r in out["routes"])
    out = await call(mcp, "get_routing", switch="fab1", vrf="guest", destination="8.8.8.8")
    assert ssh.calls[-1] == ("192.0.2.20", [("ip_interface_vrf", {"vrf": "guest"}), ("ip_route_vrf", {"vrf": "guest"})])
    assert out["vrf"] == "guest" or out["vrf"] == "GlobalRouter"


# ---------------- fabric ----------------
def test_fabric_parsers():
    spbm = parse_spbm(SPBM)
    assert spbm == [{"instance": 1, "b_vids": "4051-4052", "primary_vlan": 4051, "nickname": "2.40.98",
                     "ip_shortcuts": True, "ipv6": False, "multicast": False, "origin": "config"}]
    assert parse_system_id(SYSID) == {"system_id": "0049.0240.9800", "area": "HOME"}
    ifs, bad = parse_isis_interfaces(ISIS_IF)
    assert [i["interface"] for i in ifs] == ["SiteA", "SiteB", "Core1"] and not bad and ifs[2]["adjacencies"] == 1
    stp = parse_stp(STP)
    assert stp[0]["topology_changes"] == 36 and stp[0]["designated_root"] == "20:00:02:00:00:00:00:01"
    assert stp[0]["root_port"] == "cpp" and len(stp) == 2


async def test_get_fabric_status_flags_interfaces_down_and_no_adjacencies(inv):
    ssh = FakeSsh()
    out = await call(server(inv, ssh), "get_fabric_status", switch="fab1")
    assert [k for k, _ in ssh.calls[0][1]] == ["isis_spbm", "isis_system_id", "isis_interface", "isis_adjacencies", "stp_status"]
    assert out["isis_interfaces_total"] == 3 and out["isis_interfaces_oper_down"] == 2
    assert out["isis_adjacencies"] == {"formed": 0, "interfaces": 0}
    assert any("SiteA, SiteB" in a for a in out["attention"]) and any("no IS-IS adjacencies" in a for a in out["attention"])
    assert out["spanning_tree"][0]["topology_changes"] == 36 and "parse_warnings" not in out
    out = await call(server(inv, FakeSsh({"isis_adjacencies": ADJ_ONE})), "get_fabric_status", switch="fab1")
    assert out["isis_adjacencies"] == {"formed": 1, "interfaces": 3}
    assert not any("no IS-IS adjacencies" in a for a in out["attention"])


# ---------------- auth ----------------
def test_auth_parsers_hide_credentials():
    assert parse_eapol(EAPOL) == {"EAP Clients": 0, "NEAP Radius Clients": 2, "NEAP LLDP Clients": 0}
    rad = parse_reachability(RADIUS)
    assert rad["RADIUS password"] == "<hidden>" and rad["RADIUS username"] == "testuser"
    assert rad["EAP RADIUS reachability status"] == "unreachable"


async def test_get_auth_status_never_returns_the_password(inv):
    ssh = FakeSsh()
    res = await server(inv, ssh).call_tool("get_auth_status", {"switch": "fab1"})
    text = res[0].text
    assert "hunter2secret" not in text
    out = json.loads(text)
    assert out["attention"] == ["RADIUS reachability is 'unreachable'"] and out["eapol_clients"]["NEAP Radius Clients"] == 2


async def test_auth_unparseable_output_never_attaches_radius_text(inv):
    ssh = FakeSsh({"eapol_summary": "garbage", "radius_reachability": "RADIUS password : hunter2secret garbage"})
    res = await server(inv, ssh).call_tool("get_auth_status", {"switch": "fab1"})
    assert "hunter2secret" not in res[0].text


# ---------------- argument validation / platform ----------------
@pytest.mark.parametrize("tool,bad", [
    ("get_vlans", {"vlan": 0}), ("get_vlans", {"vlan": 4095}), ("get_vlans", {"name_contains": "a;b"}),
    ("get_vlans", {"limit": 0}), ("get_vlans", {"limit": 201}),
    ("get_routing", {"destination": "999.1.1.1"}), ("get_routing", {"destination": "x; reload"}),
    ("get_routing", {"protocol": "FAKE"}), ("get_routing", {"vrf": "a b"}), ("get_routing", {"vrf": "x" * 17}),
    ("get_routing", {"limit": 0})])
async def test_bad_arguments_rejected_before_ssh(inv, tool, bad):
    ssh = FakeSsh()
    with pytest.raises(Exception):
        await server(inv, ssh).call_tool(tool, {"switch": "fab1", **bad})
    assert ssh.calls == []


@pytest.mark.parametrize("tool", ["get_vlans", "get_routing", "get_fabric_status", "get_auth_status"])
async def test_ssh_tools_reject_exos_unknown_and_are_hidden_without_ssh(inv, tool):
    ssh = FakeSsh()
    mcp = server(inv, ssh)
    for sw in ("exos1", "203.0.113.9"):
        with pytest.raises(Exception):
            await mcp.call_tool(tool, {"switch": sw})
    assert ssh.calls == []
    assert tool not in {t.name for t in await server(inv).list_tools()}


# ---------------- port summary (SNMP) ----------------
IF = "1.3.6.1.2.1.2.2.1"
IFX = "1.3.6.1.2.1.31.1.1.1"


def column(base, values):
    return {f"{base}.{idx}": val for idx, val in values.items()}


NAMES = {"1": "1/1", "2": "1/2", "3": "1/3", "4": "1/10", "5": "Vlan10", "6": "mlt1", "7": "1/48"}
PORT_TABLES = {
    f"{IFX}.1": column(f"{IFX}.1", NAMES),
    f"{IF}.7": column(f"{IF}.7", {"1": "1", "2": "1", "3": "2", "4": "1", "5": "1", "6": "1", "7": "1"}),
    f"{IF}.8": column(f"{IF}.8", {"1": "1", "2": "2", "3": "2", "4": "1", "5": "1", "6": "1", "7": "1"}),
    f"{IFX}.15": column(f"{IFX}.15", {"1": "1000", "2": "0", "3": "0", "4": "10000", "5": "0", "6": "0", "7": "10000"}),
    f"{IF}.9": column(f"{IF}.9", {"1": "100000", "2": "999000", "3": "0", "4": "1000000", "5": "0", "6": "0", "7": "1000990"}),
    f"{IF}.14": column(f"{IF}.14", {"1": "0", "2": "0", "3": "0", "4": "12", "5": "0", "6": "0", "7": "0"}),
    f"{IF}.20": column(f"{IF}.20", {"1": "0", "2": "0", "3": "0", "4": "0", "5": "0", "6": "0", "7": "0"}),
    f"{IF}.13": column(f"{IF}.13", {"1": "0", "2": "0", "3": "0", "4": "0", "5": "0", "6": "0", "7": "0"}),
    f"{IF}.19": column(f"{IF}.19", {"1": "0", "2": "0", "3": "0", "4": "0", "5": "0", "6": "0", "7": "0"}),
    f"{IFX}.18": column(f"{IFX}.18", {"1": "uplink", "2": "", "3": "", "4": "", "5": "", "6": "", "7": "to-core"}),
}


class PortSnmp(SnmpClient):
    def __init__(self):
        self.calls = []

    async def get(self, ip, oids):
        self.calls.append(("get", ip, oids))
        return {"1.3.6.1.2.1.1.3.0": "1001000"}              # uptime 10010 s

    async def walk(self, ip, oid, limit=500):
        self.calls.append(("walk", ip, oid))
        return PORT_TABLES[oid]


async def test_port_summary_lists_only_physical_ports_in_natural_order(inv):
    out = await call(server(inv, snmp=PortSnmp()), "get_port_summary", switch="fab1")
    assert [p["port"] for p in out["ports"]] == ["1/1", "1/2", "1/3", "1/10", "1/48"]      # no Vlan10 / mlt1
    assert out["summary"] == {"ports": 5, "up": 3, "down": 1, "admin_down": 1, "with_errors": 1}
    p = {x["port"]: x for x in out["ports"]}
    assert p["1/3"]["state"] == "admin_down" and p["1/2"]["state"] == "down" and p["1/1"]["speed_mbps"] == 1000
    assert p["1/10"]["in_errors"] == 12 and p["1/10"]["has_errors"] and p["1/1"]["alias"] == "uplink"
    assert p["1/1"]["last_change_seconds_ago"] == 9010 and p["1/1"]["last_change"] == "2h 30m"
    assert p["1/10"]["last_change_seconds_ago"] == 10 and out["management_ip"] == "192.0.2.20"


async def test_port_summary_filters(inv):
    mcp = server(inv, snmp=PortSnmp())
    ports = lambda out: [x["port"] for x in out["ports"]]
    assert ports(await call(mcp, "get_port_summary", switch="fab1", state="down")) == ["1/2"]
    assert ports(await call(mcp, "get_port_summary", switch="fab1", state="admin-down")) == ["1/3"]
    assert ports(await call(mcp, "get_port_summary", switch="fab1", only_errors=True)) == ["1/10"]
    recent = await call(mcp, "get_port_summary", switch="fab1", changed_within_minutes=5)
    assert ports(recent) == ["1/48", "1/10", "1/2"]                                         # newest change first
    assert ports(await call(mcp, "get_port_summary", switch="fab1", limit=2)) == ["1/1", "1/2"]


@pytest.mark.parametrize("bad", [{"state": "sideways"}, {"changed_within_minutes": 0}, {"changed_within_minutes": 10081},
                                 {"limit": 0}, {"limit": 201}])
async def test_port_summary_bad_arguments(inv, bad):
    snmp = PortSnmp()
    with pytest.raises(Exception):
        await server(inv, snmp=snmp).call_tool("get_port_summary", {"switch": "fab1", **bad})
    assert snmp.calls == []


async def test_port_summary_rejects_unknown_switch_and_uses_platform_port_format(inv):
    snmp = PortSnmp()
    with pytest.raises(Exception):
        await server(inv, snmp=snmp).call_tool("get_port_summary", {"switch": "198.51.100.9"})
    out = await call(server(inv, snmp=PortSnmp()), "get_port_summary", switch="exos1")
    assert out["parse_warnings"] == ["no physical ports recognised in the interface table"]   # '1/1' is not an EXOS port


# ---------------- layout variants seen on a switch with fabric-learned routes ----------------
ROUTE_HEAD = rule("IP Route - GlobalRouter") + (
    "                                                     NH                      INTER   \n"
    "DST             MASK            NEXT                 VRF/ISID         COST   FACE     PROT AGE TYPE   PRF\n") + DASH
ROUTE_NAMED = BANNER + ROUTE_HEAD + (
    route_row("192.0.2.3", "255.255.255.255", "Site A - Core 1", "GlobalRouter", 1, 4051, "ISIS", 0, "IBSE", 7)
    + route_row("192.0.2.3", "255.255.255.255", "Site A - Core 1", "GlobalRouter", 1, 4052, "ISIS", 0, "IBSE", 7)
    + route_row("198.51.100.0", "255.255.255.0", "198.51.100.1", "-", 1, 10, "LOC", 0, "DB", 0)
    + "3 out of 3 Total Num of Route Entries, 2 Total Num of Dest Networks displayed.\n")


def test_routes_with_a_hostname_next_hop_that_contains_spaces():
    routes, bad, _ = parse_routes(ROUTE_NAMED)
    assert not bad and len(routes) == 3
    assert routes[0]["next_hop"] == "Site A - Core 1" and routes[0]["interface"] == "4051" and routes[0]["flags"] == "IBSE"
    assert routes[2]["next_hop"] == "198.51.100.1" and routes[2]["next_hop_vrf"] is None


async def test_get_routing_reports_a_named_next_hop_without_warnings(inv):
    out = await call(server(inv, FakeSsh({"ip_route": ROUTE_NAMED})), "get_routing", switch="fab1", destination="192.0.2.3")
    assert out["lookup"]["result"] == "192.0.2.3/32 via Site A - Core 1 on interface 4051 (ISIS)"
    assert "parse_warnings" not in out and out["route_protocols"] == {"ISIS": 2, "LOC": 1}


def test_isis_interface_rows_with_the_auto_metric_marker():
    row = (f"{'Port1/48':<18}{'pt-pt':<8}{'Level 1':<10}{'UP':<8}{'UP':<8}{1:<7}{1:<8}{'2000 (A)':<13}{2000:<13}"
           f"{'AUTO-SENSE':<11}{'HOME'}\n")
    ifs, bad = parse_isis_interfaces(ISIS_IF.replace("Legend:", row + "Legend:"))
    assert not bad and [i["interface"] for i in ifs] == ["SiteA", "SiteB", "Core1", "Port1/48"]
    assert ifs[3]["metric"] == 2000 and ifs[3]["origin"] == "AUTO-SENSE" and ifs[3]["oper"] == "UP"
