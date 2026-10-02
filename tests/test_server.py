import json
import pathlib

import pytest

from app.adapters.snmp import SnmpClient, SnmpError, check_oid
from app.audit import Audit
from app.main import build_server
from app.validation import Inventory, Switch, ValidationError, validate_port

APPROVED_TOOLS = {"list_switches", "get_switch_health", "get_interface",
                  "get_interface_errors", "get_lldp_neighbors", "get_dhcp_status", "get_port_summary"}


class FakeSnmp(SnmpClient):
    def __init__(self):
        self.calls = []

    async def get(self, ip, oids):
        self.calls.append(("get", ip, oids))
        return {o: "1" for o in oids}

    tables: dict = {}

    async def walk(self, ip, oid, limit=500):
        self.calls.append(("walk", ip, oid))
        if oid in self.tables:
            return self.tables[oid]
        return {f"{oid}.1": "1/48"} if oid.startswith("1.3.6.1.2.1.31") else {}


@pytest.fixture
def inv():
    return Inventory([Switch("sw1", "192.0.2.10", "exos", "Test", ("snmpv3",)),
                      Switch("fabric1", "192.0.2.12", "fabric", "Test", ("snmpv3",)),
                      Switch("nosnmp", "192.0.2.11", "exos", "Test", ("ssh",))])


@pytest.fixture
def server(inv, tmp_path):
    audit_path = tmp_path / "audit.log"
    snmp = FakeSnmp()
    return build_server(inv, snmp, Audit(str(audit_path))), snmp, audit_path


async def test_tool_catalogue_is_only_approved_read_only_tools(server):
    mcp, _, _ = server
    names = {t.name for t in await mcp.list_tools()}
    assert names == APPROVED_TOOLS


@pytest.mark.parametrize("bad", ["203.0.113.1", "evil.example.com", "sw1; reboot", "", "sw1 "])
def test_unapproved_or_malformed_switch_rejected(inv, bad):
    with pytest.raises(ValidationError):
        inv.resolve(bad)


def test_protocol_not_enabled_rejected(inv):
    with pytest.raises(ValidationError):
        inv.resolve("nosnmp", "snmpv3")


@pytest.mark.parametrize("platform,bad", [
    ("fabric", "1/1; reboot"), ("fabric", "$(id)"), ("fabric", "1:48"), ("fabric", "48"),
    ("fabric", "1/1/1/1"), ("fabric", ""), ("exos", "1/1"), ("exos", "1:48; reboot"),
    ("exos", "1:2:3"), ("exos", "a"), ("unknown", "1/1")])
def test_bad_ports_rejected(platform, bad):
    with pytest.raises(ValidationError):
        validate_port(bad, platform)


@pytest.mark.parametrize("platform,good", [
    ("fabric", "1/1"), ("fabric", "1/12/1"), ("exos", "48"), ("exos", "1:48")])
def test_good_ports(platform, good):
    assert validate_port(good, platform) == good


async def test_fabric_port_flows_through_tool(server):
    mcp, snmp, _ = server
    await mcp.call_tool("get_interface_errors", {"switch": "fabric1", "port": "1/48"})
    assert snmp.calls[0] == ("walk", "192.0.2.12", "1.3.6.1.2.1.31.1.1.1.1")


def test_fabric_enterprise_oids_allowed():
    assert check_oid("1.3.6.1.4.1.2272.1.4.10")


def test_oid_outside_view_rejected():
    with pytest.raises(SnmpError):
        check_oid("1.3.6.1.4.1.9.9.1")  # Cisco enterprise: not approved
    assert check_oid("1.3.6.1.2.1.2.2.1.8.1")


def test_adapter_has_no_set_operation():
    src = (pathlib.Path(__file__).parent.parent / "app/adapters/snmp.py").read_text()
    assert "set_cmd" not in src and "def set" not in src


async def test_call_is_audited_without_secrets(server, monkeypatch):
    monkeypatch.setenv("SNMP_AUTH_PASSWORD", "TOPSECRETKEY")
    mcp, snmp, audit_path = server
    await mcp.call_tool("get_switch_health", {"switch": "sw1"})
    event = json.loads(audit_path.read_text().splitlines()[0])
    assert event["tool"] == "get_switch_health" and event["target"] == "sw1"
    assert event["backend"] == "snmpv3" and event["result"] == "success"
    assert "TOPSECRETKEY" not in audit_path.read_text()
    assert snmp.calls[0][1] == "192.0.2.10"


async def test_rejected_request_is_audited_and_never_reaches_switch(server):
    mcp, snmp, audit_path = server
    with pytest.raises(Exception):
        await mcp.call_tool("get_switch_health", {"switch": "203.0.113.9"})
    assert "error:ValidationError" in audit_path.read_text()
    assert snmp.calls == []


def test_non_loopback_bind_refused(inv, monkeypatch):
    monkeypatch.setenv("MCP_BIND_ADDRESS", "0.0.0.0")
    with pytest.raises(SystemExit):
        build_server(inv, FakeSnmp(), Audit(None))


@pytest.mark.parametrize("missing", ["SNMP_USERNAME", "SNMP_AUTH_PASSWORD", "SNMP_PRIV_PASSWORD"])
def test_authpriv_requires_all_three_credentials(monkeypatch, missing):
    for k in ("SNMP_USERNAME", "SNMP_AUTH_PASSWORD", "SNMP_PRIV_PASSWORD"):
        monkeypatch.setenv(k, "value-for-test-12345")
    monkeypatch.delenv(missing)
    with pytest.raises(SnmpError, match="not configured"):
        SnmpClient()._user()  # never falls back to noAuth or authNoPriv


def test_authpriv_user_builds_with_all_three(monkeypatch):
    for k in ("SNMP_USERNAME", "SNMP_AUTH_PASSWORD", "SNMP_PRIV_PASSWORD"):
        monkeypatch.setenv(k, "value-for-test-12345")
    assert SnmpClient()._user().userName


def test_secrets_read_from_systemd_credentials_dir(monkeypatch, tmp_path):
    for n, v in (("snmp_username", "svc"), ("snmp_auth_password", "a" * 12), ("snmp_priv_password", "p" * 12)):
        (tmp_path / n).write_text(v + "\n")
    for k in ("SNMP_USERNAME", "SNMP_AUTH_PASSWORD", "SNMP_PRIV_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert str(SnmpClient()._user().userName) == "svc"


RC = "1.3.6.1.4.1.2272.1"
HEALTH_TABLES = {
    f"{RC}.85.10.1.1.2": {f"{RC}.85.10.1.1.2.1": "5"},
    f"{RC}.85.10.1.1.8": {f"{RC}.85.10.1.1.8.1": "53"},
    f"{RC}.212": {f"{RC}.212.1.0": "33", f"{RC}.212.2.0": "32", f"{RC}.212.3.0": "32", f"{RC}.212.4.0": "34",
                  f"{RC}.212.5.0": "0"},
    f"{RC}.4.8.1.1.2": {f"{RC}.4.8.1.1.2.1": "3", f"{RC}.4.8.1.1.2.2": "2"},
    "1.3.6.1.2.1.47.1.1.1.1.7": {"1.3.6.1.2.1.47.1.1.1.1.7.1": "5420M", "1.3.6.1.2.1.47.1.1.1.1.7.9": "FanTray Slot-1",
                                  "1.3.6.1.2.1.47.1.1.1.1.7.82": "FanTray-1 Fan-1", "1.3.6.1.2.1.47.1.1.1.1.7.74": "FanTray 1"},
}


class HealthSnmp(FakeSnmp):
    tables = HEALTH_TABLES

    async def get(self, ip, oids):
        base = "1.3.6.1.2.1.1"
        return {f"{base}.1.0": "5420M (9.3.2.0)", f"{base}.3.0": "1029443700", f"{base}.5.0": "SW", f"{base}.6.0": ""}


async def test_fabric_health_has_cpu_mem_temp_power_fans(inv, tmp_path):
    mcp = build_server(inv, HealthSnmp(), Audit(None))
    res = json.loads((await mcp.call_tool("get_switch_health", {"switch": "fabric1"}))[0].text)
    assert res["cpu_percent"] == {"slot1": 5} and res["memory_percent"] == {"slot1": 53}
    assert res["temperature_c"] == {"cpu": 33, "other_sensors": [32, 32, 34]}
    assert res["power_supplies"] == {"psu1": "up", "psu2": "empty"}
    assert res["fan_trays_present"] == ["FanTray 1"] and res["fans_present"] == ["FanTray-1 Fan-1"]
    assert res["attention"] == []
    assert res["uptime"] == "119d 3h 33m"


async def test_down_power_supply_flagged(inv):
    snmp = HealthSnmp()
    snmp.tables = {**HEALTH_TABLES, f"{RC}.4.8.1.1.2": {f"{RC}.4.8.1.1.2.1": "3", f"{RC}.4.8.1.1.2.2": "4"}}
    mcp = build_server(inv, snmp, Audit(None))
    res = json.loads((await mcp.call_tool("get_switch_health", {"switch": "fabric1"}))[0].text)
    assert res["attention"] == ["psu2 is down"]


async def test_missing_vendor_sections_do_not_fail_health(inv):
    class Partial(HealthSnmp):
        async def walk(self, ip, oid, limit=500):
            raise SnmpError("noSuchObject")
    mcp = build_server(inv, Partial(), Audit(None))
    res = json.loads((await mcp.call_tool("get_switch_health", {"switch": "fabric1"}))[0].text)
    assert res["sysName"] == "SW" and res["cpu_percent"] is None and res["power_supplies"] is None


async def test_exos_health_is_base_only(inv):
    mcp = build_server(inv, HealthSnmp(), Audit(None))
    res = json.loads((await mcp.call_tool("get_switch_health", {"switch": "sw1"}))[0].text)
    assert "cpu_percent" not in res and "note" in res


async def test_dhcp_status_relay_and_local_server_detection(inv):
    f = f"{RC}.8.9.1"
    snmp = FakeSnmp()
    snmp.tables = {f: {
        f"{f}.1.198.51.100.1.192.0.2.12": "198.51.100.1", f"{f}.2.198.51.100.1.192.0.2.12": "192.0.2.12",
        f"{f}.3.198.51.100.1.192.0.2.12": "1", f"{f}.4.198.51.100.1.192.0.2.12": "3",
        f"{f}.1.198.51.100.2.203.0.113.9": "198.51.100.2", f"{f}.2.198.51.100.2.203.0.113.9": "203.0.113.9",
        f"{f}.3.198.51.100.2.203.0.113.9": "2", f"{f}.4.198.51.100.2.203.0.113.9": "4"}}
    mcp = build_server(inv, snmp, Audit(None))
    res = json.loads((await mcp.call_tool("get_dhcp_status", {"switch": "fabric1"}))[0].text)
    assert res["dhcp_relay_configured"] and res["servers"] == ["192.0.2.12", "203.0.113.9"]
    assert res["local_dhcp_server_likely"] is True  # 192.0.2.12 is fabric1's own address
    by = {e["relay_interface_ip"]: e for e in res["entries"]}
    assert by["198.51.100.1"]["enabled"] and by["198.51.100.1"]["mode"] == "dhcp"
    assert not by["198.51.100.2"]["enabled"] and by["198.51.100.2"]["mode"] == "bootp+dhcp"


async def test_dhcp_status_rejected_for_exos_and_unknown(inv):
    mcp = build_server(inv, FakeSnmp(), Audit(None))
    for sw in ("sw1", "203.0.113.1"):
        with pytest.raises(Exception):
            await mcp.call_tool("get_dhcp_status", {"switch": sw})
