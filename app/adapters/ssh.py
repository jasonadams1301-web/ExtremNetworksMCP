"""Read-only SSH adapter for Fabric Engine (VOSS). Runs ONLY commands from the fixed table below.

Callers pass a command key plus validated arguments; they never supply CLI text. The command
table is the entire attack surface: every entry must start with "show " and may only contain
placeholders whose values match a strict regex. Host keys are verified against a pre-populated
known_hosts file (no trust-on-first-use). Use a dedicated read-only account on the switches.

Fabric Engine does not run one-off commands over an SSH exec channel, so each call opens an
interactive CLI session, waits for the prompt, sends the fixed command(s), answers the
--More-- pager (space to continue, q to stop) and closes. Only command text from the table and those
two pager keys are ever sent. The session logs in fresh each call (the switch may authenticate via
RADIUS), so tools that need several commands run them all in one session with run_many().
"""
import asyncio
import os
import re

import asyncssh

from app.secrets import get_secret
from app.validation import PORT_RES, ValidationError

VRF_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,15}")

# key -> (command template, {placeholder: validating regex})
COMMANDS: dict[str, tuple[str, dict[str, re.Pattern]]] = {
    "sys_info": ("show sys-info", {}),
    "log_tail": ("show logging file tail", {}),
    "isis_adjacencies": ("show isis adjacencies", {}),
    "mac_table": ("show vlan mac-address-entry", {}),
    "dhcp_server": ("show ip dhcp-server", {}),
    "dhcp_subnets": ("show ip dhcp-server subnet", {}),
    "dhcp_hosts": ("show ip dhcp-server host", {}),
    "dhcp_leases": ("show ip dhcp-server leases", {}),
    "dhcp_log": ("show ip dhcp-server log", {}),
    "dhcp_relay_counters": ("show ip dhcp-relay counters", {}),
    "dhcp_relay_fwd": ("show ip dhcp-relay fwd-path", {}),
    # --- privileged (need `enable`; see PRIVILEGED) ---
    "running_config": ("show running-config", {}),
    "interface": ("show interfaces gigabitEthernet interface {port}", {"port": PORT_RES["fabric"]}),
    "interface_stats": ("show interfaces gigabitEthernet statistics {port}", {"port": PORT_RES["fabric"]}),
    "interface_errors": ("show interfaces gigabitEthernet error {port}", {"port": PORT_RES["fabric"]}),
    "optics_basic": ("show pluggable-optical-modules basic", {}),
    "optics_detail": ("show pluggable-optical-modules detail", {}),
    "ntp_server": ("show ntp server", {}),
    "ntp_stats": ("show ntp statistics", {}),
    "mlt": ("show mlt", {}),
    # --- unprivileged ---
    "arp": ("show ip arp", {}),
    "arp_vrf": ("show ip arp vrf {vrf}", {"vrf": VRF_NAME}),
    "vlan_basic": ("show vlan basic", {}),
    "vlan_members": ("show vlan members", {}),
    "vlan_isid": ("show vlan i-sid", {}),
    "ip_interface": ("show ip interface", {}),
    "ip_interface_vrf": ("show ip interface vrf {vrf}", {"vrf": VRF_NAME}),
    "ip_route": ("show ip route", {}),
    "ip_route_vrf": ("show ip route vrf {vrf}", {"vrf": VRF_NAME}),
    "isis_spbm": ("show isis spbm", {}),
    "isis_interface": ("show isis interface", {}),
    "isis_system_id": ("show isis system-id", {}),
    "stp_status": ("show spanning-tree status", {}),
    "eapol_summary": ("show eapol summary", {}),
    "radius_reachability": ("show radius reachability", {}),
}
# Commands that only work in privileged mode (the account must be allowed to use `enable`, which needs no password
# here). They run in their OWN session, never mixed with unprivileged commands, and nothing but `show` commands
# is ever sent after `enable`.
PRIVILEGED = {"running_config", "interface", "interface_stats", "interface_errors", "optics_basic", "optics_detail",
              "ntp_server", "ntp_stats", "mlt"}
ENABLE = "enable"
MAX_OUTPUT = 20000
MAX_PAGES = 1000        # a safety stop only: max_chars bounds the output (a long running-config is hundreds of pages)

PROMPT_END = re.compile(r"(?:^|[\r\n\x08])[^\s\x08]+:\d+[>#] ?$")   # e.g. SWITCH-1:1> (may follow pager erasure)
REJECTED = re.compile(r"^\s*(?:\^\s*)?%\s*(Invalid input|Incomplete command|Ambiguous command|Unrecognized command)", re.M)
MORE = re.compile(r"--More--")
MORE_TEXT = re.compile(r"--More--(?: \(q = quit\))? ?")
ERASE = re.compile(r"(?:\x08 \x08)+|\x08")


class SshError(RuntimeError):
    pass


def build_command(key: str, **args: str) -> str:
    """Render a fixed command. Unknown keys, missing/extra args and bad values are all rejected."""
    if key not in COMMANDS:
        raise SshError("command is not in the approved list")
    template, rules = COMMANDS[key]
    if set(args) != set(rules):
        raise SshError("unexpected command arguments")
    for name, rx in rules.items():
        if not isinstance(args[name], str) or not rx.fullmatch(args[name]):
            raise ValidationError(f"invalid {name}")
    cmd = template.format(**args)
    if not cmd.startswith("show "):
        raise SshError("only show commands are permitted")
    return cmd


def clean_output(raw: str, cmd: str) -> str:
    """Strip the pager, backspace erasures, the echoed command and the trailing prompt."""
    text = MORE_TEXT.sub("", raw)
    text = ERASE.sub("", text).replace("\r\r\n", "\n").replace("\r\n", "\n").replace("\r", "")
    lines = text.split("\n")
    if lines and lines[0].strip() == cmd:
        lines = lines[1:]
    if lines and PROMPT_END.search("\n" + lines[-1]):
        lines = lines[:-1]
    return "\n".join(lines).strip("\n")


async def _read(proc, deadline: float) -> str:
    left = deadline - asyncio.get_running_loop().time()
    if left <= 0:
        raise SshError("timed out waiting for the switch")
    try:
        chunk = await asyncio.wait_for(proc.stdout.read(8192), left)
    except asyncio.TimeoutError:
        raise SshError("timed out waiting for the switch") from None
    if not chunk:
        raise SshError("switch closed the session")
    return chunk


async def _command(proc, cmd: str, want_lines: int | None, max_chars: int, deadline: float) -> str:
    """Send one command (the session is at a prompt), page through the output, return cleaned text."""
    proc.stdin.write(cmd + "\n")
    buf, seen, pages = "", 0, 0
    while True:
        buf += await _read(proc, deadline)
        if PROMPT_END.search(buf[seen:][-200:]):
            return clean_output(buf, cmd)
        m = MORE.search(buf, seen)
        if m and buf[m.end():].strip(" \x08") in ("", "(q = quit)"):  # pager is waiting for a key
            pages += 1
            seen = len(buf)
            enough = len(buf) >= max_chars or pages >= MAX_PAGES or (
                want_lines is not None and clean_output(buf, cmd).count("\n") >= want_lines)
            proc.stdin.write("q" if enough else " ")


async def _enable(proc, deadline: float) -> None:
    """Switch to privileged mode with `enable`. A password prompt is refused: we never type a password here."""
    proc.stdin.write(ENABLE + "\n")
    buf = ""
    while True:
        buf += await _read(proc, deadline)
        if re.search(r"[Pp]assword\s*:?\s*$", buf[-60:]):
            raise SshError("the switch asks for an enable password, which is not supported")
        if PROMPT_END.search(buf[-120:]):
            if not re.search(r":\d+# ?$", ERASE.sub("", buf)):
                raise SshError("this account cannot enter privileged mode (enable was not accepted)")
            return


async def drive_commands(proc, jobs: list[tuple[str, int | None, int]], timeout: float,
                         privileged: bool = False) -> list[str]:
    """Wait for the CLI prompt, optionally `enable`, then run each (cmd, want_lines, max_chars) in one session."""
    deadline = asyncio.get_running_loop().time() + timeout
    buf = ""
    while not PROMPT_END.search(buf):               # login banner, then the prompt
        buf += await _read(proc, deadline)
    if privileged:
        await _enable(proc, deadline)
    return [await _command(proc, cmd, wl, mc, deadline) for cmd, wl, mc in jobs]


async def drive_session(proc, cmd: str, want_lines: int | None, max_chars: int, timeout: float) -> str:
    return (await drive_commands(proc, [(cmd, want_lines, max_chars)], timeout))[0]


class SshClient:
    def __init__(self):
        self.known_hosts = os.environ.get("SSH_KNOWN_HOSTS", "/etc/extreme-mcp/known_hosts")
        self.connect_timeout = int(os.environ.get("SSH_CONNECT_TIMEOUT_SECONDS", "8"))
        self.command_timeout = int(os.environ.get("SSH_COMMAND_TIMEOUT_SECONDS", "20"))
        self.sem = asyncio.Semaphore(int(os.environ.get("SSH_MAX_PARALLEL", "5")))

    async def run(self, ip: str, key: str, *, want_lines: int | None = None, max_chars: int = MAX_OUTPUT,
                  timeout: float | None = None, **args: str) -> str:
        job = {"key": key, "args": args, "want_lines": want_lines, "max_chars": max_chars}
        return (await self.run_many(ip, [job], timeout=timeout))[0]

    async def run_many(self, ip: str, jobs: list[dict], *, timeout: float | None = None) -> list[str]:
        """Run several fixed commands in ONE login. Each job: {key, args, want_lines, max_chars}."""
        planned = [(build_command(j["key"], **j.get("args", {})), j.get("want_lines"),
                    j.get("max_chars", MAX_OUTPUT)) for j in jobs]   # validate everything before connecting
        flags = {j["key"] in PRIVILEGED for j in jobs}
        if len(flags) > 1:
            raise SshError("privileged and unprivileged commands cannot share a session")
        privileged = flags == {True}
        user, pw = get_secret("SSH_USERNAME"), get_secret("SSH_PASSWORD")
        keyfile = os.environ.get("SSH_KEY_FILE")
        if not user or not (pw or keyfile):
            raise SshError("SSH credentials are not configured")
        if not os.path.isfile(self.known_hosts):
            raise SshError("known_hosts file is missing; host keys must be pre-approved")
        try:
            async with self.sem:
                async with asyncssh.connect(
                        ip, username=user, password=pw, client_keys=[keyfile] if keyfile else None,
                        known_hosts=self.known_hosts, agent_path=None,
                        connect_timeout=self.connect_timeout, login_timeout=self.connect_timeout) as conn:
                    proc = await conn.create_process(term_type="vt100", term_size=(250, 50),
                                                     encoding="utf-8", errors="replace")
                    outs = await drive_commands(proc, planned, timeout or self.command_timeout, privileged)
        except asyncssh.HostKeyNotVerifiable:
            raise SshError("host key verification failed") from None  # never auto-trust a changed key
        except (asyncssh.Error, OSError, asyncio.TimeoutError) as e:
            raise SshError(f"ssh failed: {type(e).__name__}") from None
        for out, p in zip(outs, planned):
            if REJECTED.search(out[:400]):
                raise SshError(f"the switch rejected the command '{p[0]}' (this account or software release may not "
                               "support it)")
        return [out[:p[2]] for out, p in zip(outs, planned)]
