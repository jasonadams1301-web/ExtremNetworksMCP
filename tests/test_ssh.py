import pytest

from app.adapters.snmp import SnmpClient
from app.adapters.ssh import COMMANDS, SshClient, SshError, build_command
from app.audit import Audit
from app.main import build_server
from app.validation import Inventory, Switch, ValidationError

SSH_TOOLS = {"get_system_info", "get_fabric_adjacencies", "get_interface_detail", "find_mac_address",
             "get_switch_logs", "get_dhcp_server", "get_dhcp_leases", "get_dhcp_relay", "get_dhcp_server_log"}
META = set(";|&$`<>\\\n\r()'\"!{}")


def _entry(ts, sev, msg):
    return f"1 2026-10-01T{ts}-04:00 SW1 CP1 - 0x000d8602 - 00000000 Mgmt SSH {sev} {msg}"


# the switch prints its log NEWEST FIRST, after an asterisk banner
LOG_ENTRIES = [_entry("10:08:00.000", "FATAL", "watchdog reset"),
               _entry("10:07:00.000", "ERROR", "high cpu 95%"),
               _entry("10:05:09.000", "INFO", "Port 1/12 link up"),
               _entry("10:05:00.000", "WARNING", "Port 1/12 link down"),
               _entry("10:00:01.000", "INFO", "user login")]
LOG = ("*" * 40 + "\n\t\tCommand Execution Time: Thu Oct 01 15:40:00 2026 EDT\n" + "*" * 40 + "\n"
       + "\n".join(LOG_ENTRIES) + "\n")


class FakeSsh(SshClient):
    def __init__(self):
        self.calls = []

    async def run(self, ip, key, *, want_lines=None, max_chars=20000, **args):
        build_command(key, **args)  # same validation as the real client
        self.calls.append((ip, key, args))
        if key == "log_tail":
            return LOG
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


async def test_ssh_catalogue_has_exactly_the_five_ssh_tools(server):
    mcp, _ = server
    names = {t.name for t in await mcp.list_tools()}
    assert SSH_TOOLS <= names and len(names) == 15
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


import json


async def _logs(server, **args):
    mcp, ssh = server
    res = await mcp.call_tool("get_switch_logs", {"switch": "fab1", **args})
    return json.loads(res[0].text), ssh


async def test_logs_newest_first_and_fixed_command_only(server):
    out, ssh = await _logs(server, lines=2)
    assert out["order"] == "newest first" and out["returned"] == 2
    assert "FATAL" in out["entries"][0] and "ERROR" in out["entries"][1]
    assert ssh.calls == [("192.0.2.20", "log_tail", {})]
    assert all(e.startswith("1 2026-") for e in out["entries"])  # banner lines dropped


async def test_logs_severity_means_this_level_and_worse(server):
    out, _ = await _logs(server, severity="warning")
    assert len(out["entries"]) == 3 and "INFO" not in " ".join(out["entries"])
    out, _ = await _logs(server, severity="FATAL")
    assert out["returned"] == 1


async def test_logs_contains_filter_is_local(server):
    out, ssh = await _logs(server, contains="port 1/12")
    assert out["returned"] == 2
    assert ssh.calls == [("192.0.2.20", "log_tail", {})]  # filter text never reaches the switch


@pytest.mark.parametrize("bad", [{"lines": 0}, {"lines": 201}, {"severity": "DEBUG;x"}, {"contains": "a;reload"},
                                 {"contains": "$(id)"}, {"contains": "x" * 65}])
async def test_logs_bad_arguments_rejected_before_ssh(server, bad):
    mcp, ssh = server
    with pytest.raises(Exception):
        await mcp.call_tool("get_switch_logs", {"switch": "fab1", **bad})
    assert ssh.calls == []


async def test_logs_rejected_for_exos(server):
    mcp, ssh = server
    with pytest.raises(Exception):
        await mcp.call_tool("get_switch_logs", {"switch": "exos1"})
    assert ssh.calls == []


async def test_switch_logs_note_and_management_ip(server):
    out, _ = await _logs(server)
    assert out["management_ip"] == "192.0.2.20"
    assert "CLIENT" in out["note"] and "NOT the switch" in out["note"] and "management_ip" in out["note"]
