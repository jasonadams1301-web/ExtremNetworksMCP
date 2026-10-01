import json
import pathlib

import pytest

from app.adapters.snmp import SnmpClient, SnmpError, check_oid
from app.audit import Audit
from app.main import build_server
from app.validation import Inventory, Switch, ValidationError, validate_port

APPROVED_TOOLS = {"list_switches", "get_switch_health", "get_interface",
                  "get_interface_errors", "get_lldp_neighbors"}


class FakeSnmp(SnmpClient):
    def __init__(self):
        self.calls = []

    async def get(self, ip, oids):
        self.calls.append(("get", ip, oids))
        return {o: "1" for o in oids}

    async def walk(self, ip, oid, limit=500):
        self.calls.append(("walk", ip, oid))
        return {f"{oid}.1": "1:48"} if oid.startswith("1.3.6.1.2.1.31") else {}


@pytest.fixture
def inv():
    return Inventory([Switch("sw1", "192.0.2.10", "exos", "Test", ("snmpv3",)),
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


@pytest.mark.parametrize("bad", ["1:48; reboot", "$(id)", "1:48 && x", "", "a", "1:2:3", "1" * 5])
def test_bad_ports_rejected(bad):
    with pytest.raises(ValidationError):
        validate_port(bad)


@pytest.mark.parametrize("good", ["48", "1:48"])
def test_good_ports(good):
    assert validate_port(good) == good


def test_oid_outside_view_rejected():
    with pytest.raises(SnmpError):
        check_oid("1.3.6.1.4.1.9.9.1")  # Cisco enterprise: not approved
    assert check_oid("1.3.6.1.2.1.2.2.1.8.1")


def test_adapter_has_no_set_operation():
    src = (pathlib.Path(__file__).parent.parent / "app/adapters/snmp.py").read_text()
    assert "set_cmd" not in src and "def set" not in src


async def test_call_is_audited_without_secrets(server, monkeypatch):
    monkeypatch.setenv("SNMP_AUTH_KEY", "TOPSECRETKEY")
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
