"""Running-config tool. The sample mirrors the layout of a Fabric Engine config (synthetic values; secrets are planted)."""
import json

import pytest

from app.adapters.snmp import SnmpClient
from app.adapters.ssh import SshClient, build_command
from app.audit import Audit
from app.main import build_server
from app.tools.config import clean_config, split_sections
from app.validation import Inventory, Switch

CONFIG = """\
************************************************************************************
\t\tCommand Execution Time: Fri Oct 02 09:00:00 2026 EDT
************************************************************************************
Preparing to Display Configuration...
# box type : VSP-4450GSX-PWR+
# software version : 9.3.2.0
#
# BOOT CONFIGURATION
#
boot config flags sshd
boot config flags telnetd
#
# SYSTEM CONFIGURATION
#
sys name "SW-TEST-1"
#
# SNMP CONFIGURATION
#
snmp-server community "Pu8l1cC0mm" index 1 ro
snmp-server host 192.0.2.9 port 162 v2c TrapC0mm1 filter-a
snmp-server user monitor sha "8f14e45fceea167a5a36dedd4bea2543" aes "c4ca4238a0b923820dcc509a6f75849b"
#
# LOG CONFIGURATION
#
syslog host 1 192.0.2.60
syslog host 1 severity info
#
# RADIUS CONFIGURATION
#
radius server host 192.0.2.5 key "Rad1usSh4red" used-by eapol
#
# SSH CONFIGURATION
#
ssh
ssh key-length 2048
"""
SECRETS = ["Pu8l1cC0mm", "TrapC0mm1", "8f14e45fceea167a5a36dedd4bea2543", "c4ca4238a0b923820dcc509a6f75849b",
           "Rad1usSh4red"]


class FakeSsh(SshClient):
    def __init__(self, text=CONFIG):
        self.text, self.calls = text, []

    async def run_many(self, ip, jobs, *, timeout=None):
        self.calls.append((ip, [(j["key"], j.get("args", {})) for j in jobs]))
        for j in jobs:
            build_command(j["key"], **j.get("args", {}))
        return [self.text for _ in jobs]


@pytest.fixture
def inv():
    return Inventory([Switch("fab1", "192.0.2.20", "fabric", "T", ("snmpv3", "ssh")),
                      Switch("exos1", "192.0.2.21", "exos", "T", ("snmpv3", "ssh"))])


def server(inv, ssh):
    return build_server(inv, SnmpClient(), Audit(None), ssh)


async def call(mcp, **args):
    res = await mcp.call_tool("get_running_config", args)
    return res[0].text, json.loads(res[0].text)


def test_sections_are_split_on_the_comment_headers():
    lines = clean_config(CONFIG)
    assert lines[0] == "# box type : VSP-4450GSX-PWR+" and not any("Preparing" in ln or "****" in ln for ln in lines)
    secs = split_sections(lines)
    assert [s["name"] for s in secs] == ["BOOT CONFIGURATION", "SYSTEM CONFIGURATION", "SNMP CONFIGURATION",
                                        "LOG CONFIGURATION", "RADIUS CONFIGURATION", "SSH CONFIGURATION"]
    assert secs[0]["first_line"] == 4 and sum(s["line_count"] for s in secs) == len(lines) - 3   # 3 preamble lines


async def test_default_returns_the_complete_unfiltered_config(inv):
    ssh = FakeSsh()
    raw, out = await call(server(inv, ssh), switch="fab1")
    assert ssh.calls == [("192.0.2.20", [("running_config", {})])]          # the one fixed, privileged command
    assert out["mode"] == "full" and out["redacted"] is False and "redactions" not in out
    assert out["config"].splitlines() == clean_config(CONFIG)               # every line, exactly as the switch printed it
    assert 'snmp-server community "Pu8l1cC0mm" index 1 ro' in out["config"] and "unfiltered" in out["note"]
    assert [s["name"] for s in out["sections"]][2] == "SNMP CONFIGURATION"
    assert out["management_ip"] == "192.0.2.20" and out["total_lines"] == len(clean_config(CONFIG))


async def test_full_mode_reports_truncation_and_how_to_continue(inv):
    _, out = await call(server(inv, FakeSsh()), switch="fab1", limit=5)
    assert len(out["config"].splitlines()) == 5 and "offset=5" in out["truncated"]


async def test_redaction_is_opt_in_and_then_no_planted_secret_comes_back_in_any_mode(inv, monkeypatch):
    monkeypatch.setenv("CONFIG_REDACT", "true")
    mcp = server(inv, FakeSsh())
    for args in ({}, {"section": "SNMP"}, {"search": "community"}, {"search": "radius", "context": 5},
                 {"offset": 0, "limit": 400}, {"search": "key"}):
        raw, out = await call(mcp, switch="fab1", **args)
        assert out["redacted"] is True and out["redactions"] >= 5
        for secret in SECRETS:
            assert secret not in raw, (args, secret)


@pytest.mark.parametrize("value", ["false", "0", "", "no", "off"])
async def test_redaction_stays_off_unless_explicitly_enabled(inv, monkeypatch, value):
    monkeypatch.setenv("CONFIG_REDACT", value)
    raw, out = await call(server(inv, FakeSsh()), switch="fab1")
    assert out["redacted"] is False and "Rad1usSh4red" in raw


async def test_section_mode_returns_that_section_numbered(inv):
    _, out = await call(server(inv, FakeSsh()), switch="fab1", section="snmp")
    assert out["mode"] == "section" and out["matched_sections"] == ["SNMP CONFIGURATION"]
    assert any(ln.endswith('snmp-server community "Pu8l1cC0mm" index 1 ro') for ln in out["lines"])
    assert all(ln.split(":")[0].isdigit() for ln in out["lines"])


async def test_search_mode_finds_lines_with_context_and_reports_absent_settings(inv):
    mcp = server(inv, FakeSsh())
    _, out = await call(mcp, switch="fab1", search="syslog host", context=1)
    assert out["mode"] == "search" and out["matches"] == 2 and len(out["lines"]) >= 3
    _, out = await call(mcp, switch="fab1", search="ntp server")
    assert out["matches"] == 0 and out["lines"] == [] and "absent" in out["note_search"]


async def test_offset_mode_pages_through_lines_and_truncation_is_reported(inv):
    mcp = server(inv, FakeSsh())
    _, out = await call(mcp, switch="fab1", offset=2, limit=3)
    assert out["mode"] == "lines" and len(out["lines"]) == 3 and out["lines"][0].startswith("3: ")
    _, out = await call(mcp, switch="fab1", section="CONFIGURATION", limit=4)
    assert len(out["lines"]) == 4 and "more lines" in out["truncated"] and "raise limit" in out["truncated"]


@pytest.mark.parametrize("bad", [{"limit": 0}, {"limit": 4001}, {"context": -1}, {"context": 6}, {"offset": -1},
                                 {"search": "a;b"}, {"section": "$(id)"}, {"search": "x" * 65}])
async def test_bad_arguments_rejected_before_ssh(inv, bad):
    ssh = FakeSsh()
    with pytest.raises(Exception):
        await server(inv, ssh).call_tool("get_running_config", {"switch": "fab1", **bad})
    assert ssh.calls == []


async def test_rejected_for_exos_unknown_and_hidden_without_ssh(inv):
    ssh = FakeSsh()
    mcp = server(inv, ssh)
    for sw in ("exos1", "203.0.113.9"):
        with pytest.raises(Exception):
            await mcp.call_tool("get_running_config", {"switch": sw})
    assert ssh.calls == []
    assert "get_running_config" not in {t.name for t in await build_server(inv, SnmpClient(), Audit(None)).list_tools()}


async def test_privilege_error_from_the_switch_is_reported_not_swallowed(inv):
    class Denied(FakeSsh):
        async def run_many(self, ip, jobs, *, timeout=None):
            from app.adapters.ssh import SshError
            raise SshError("this account cannot enter privileged mode (enable was not accepted)")

    with pytest.raises(Exception, match="cannot enter privileged mode"):
        await server(inv, Denied()).call_tool("get_running_config", {"switch": "fab1"})
