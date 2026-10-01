import pytest

from app.adapters.snmp import SnmpClient
from app.adapters.ssh import COMMANDS, SshClient, SshError, build_command
from app.audit import Audit
from app.main import build_server
from app.validation import Inventory, Switch, ValidationError

SSH_TOOLS = {"get_system_info", "get_fabric_adjacencies", "get_interface_detail", "find_mac_address"}
META = set(";|&$`<>\\\n\r()'\"!{}")


class FakeSsh(SshClient):
    def __init__(self):
        self.calls = []

    async def run(self, ip, key, **args):
        build_command(key, **args)  # same validation as the real client
        self.calls.append((ip, key, args))
        if key == "mac_table":
            return ("VLAN  MAC                SRC\n"
                    "100   00:11:22:33:44:55  Port1/12\n"
                    "100   aa:bb:cc:dd:ee:ff  Port1/13\n")
        return "output"


@pytest.fixture
def inv():
    both = ("snmpv3", "ssh")
    return Inventory([Switch("fab1", "192.0.2.20", "fabric", "T", both),
                      Switch("exos1", "192.0.2.21", "exos", "T", both),
                      Switch("snmponly", "192.0.2.22", "fabric", "T", ("snmpv3",))])


@pytest.fixture
def server(inv, tmp_path):
    ssh = FakeSsh()
    return build_server(inv, SnmpClient(), Audit(str(tmp_path / "a.log")), ssh), ssh


def test_every_command_is_a_plain_show():
    for key, (tmpl, rules) in COMMANDS.items():
        assert tmpl.startswith("show "), key
        static = tmpl
        for name in rules:
            static = static.replace("{" + name + "}", "")
        assert not (META & set(static)), key


@pytest.mark.parametrize("bad", ["1/1; reload", "1/1 && x", "$(id)", "1:48", "", "1/1\nconf t"])
def test_port_argument_injection_rejected(bad):
    with pytest.raises(ValidationError):
        build_command("interface", port=bad)


def test_unknown_or_arbitrary_commands_rejected():
    with pytest.raises(SshError):
        build_command("reload")
    with pytest.raises(SshError):
        build_command("sys_info", extra="x")
    with pytest.raises(SshError):
        build_command("interface")


async def test_ssh_tools_only_registered_when_enabled(inv, tmp_path):
    off = build_server(inv, SnmpClient(), Audit(None))
    assert not SSH_TOOLS & {t.name for t in await off.list_tools()}


async def test_ssh_catalogue_has_exactly_the_four_new_tools(server):
    mcp, _ = server
    names = {t.name for t in await mcp.list_tools()}
    assert SSH_TOOLS <= names and len(names) == 10
    assert not any("run" in n or "command" in n or "config" in n for n in names)


async def test_exos_and_snmp_only_switches_rejected_for_ssh(server):
    mcp, ssh = server
    for sw in ("exos1", "snmponly", "203.0.113.2"):
        with pytest.raises(Exception):
            await mcp.call_tool("get_system_info", {"switch": sw})
    assert ssh.calls == []


async def test_interface_detail_runs_three_fixed_commands(server):
    mcp, ssh = server
    await mcp.call_tool("get_interface_detail", {"switch": "fab1", "port": "1/12"})
    assert [c[1] for c in ssh.calls] == ["interface", "interface_stats", "interface_errors"]
    with pytest.raises(Exception):
        await mcp.call_tool("get_interface_detail", {"switch": "fab1", "port": "1/1; reload"})
    assert len(ssh.calls) == 3


@pytest.mark.parametrize("mac", ["00:11:22:33:44:55", "0011.2233.4455", "00-11-22-33-44-55", "001122334455"])
async def test_find_mac_filters_locally_in_any_format(server, mac):
    mcp, ssh = server
    result = await mcp.call_tool("find_mac_address", {"switch": "fab1", "mac": mac})
    assert "Port1/12" in str(result) and "Port1/13" not in str(result)
    assert ssh.calls == [("192.0.2.20", "mac_table", {})]  # MAC never reaches the command line


async def test_bad_mac_rejected_before_ssh(server):
    mcp, ssh = server
    with pytest.raises(Exception):
        await mcp.call_tool("find_mac_address", {"switch": "fab1", "mac": "00:11:22:33:44:55; reload"})
    assert ssh.calls == []


async def test_missing_known_hosts_refuses_to_connect(monkeypatch, tmp_path):
    monkeypatch.setenv("SSH_USERNAME", "ro")
    monkeypatch.setenv("SSH_PASSWORD", "x")
    monkeypatch.setenv("SSH_KNOWN_HOSTS", str(tmp_path / "missing"))
    with pytest.raises(SshError, match="known_hosts"):
        await SshClient().run("192.0.2.20", "sys_info")
