"""Read-only SSH adapter for Fabric Engine (VOSS). Runs ONLY commands from the fixed table below.

Callers pass a command key plus validated arguments; they never supply CLI text. The command
table is the entire attack surface: every entry must start with "show " and may only contain
placeholders whose values match a strict regex. Host keys are verified against a pre-populated
known_hosts file (no trust-on-first-use). Use a dedicated read-only account on the switches.

NOTE: the exact show syntax below follows the Fabric Engine CLI as documented; confirm each
command on real hardware (and that an exec channel works on your release) before relying on it.
"""
import asyncio
import os
import re

import asyncssh

from app.secrets import get_secret
from app.validation import PORT_RES, ValidationError

# key -> (command template, {placeholder: validating regex})
COMMANDS: dict[str, tuple[str, dict[str, re.Pattern]]] = {
    "sys_info": ("show sys-info", {}),
    "isis_adjacencies": ("show isis adjacencies", {}),
    "mac_table": ("show vlan mac-address-entry", {}),
    "interface": ("show interfaces gigabitEthernet interface {port}", {"port": PORT_RES["fabric"]}),
    "interface_stats": ("show interfaces gigabitEthernet statistics {port}", {"port": PORT_RES["fabric"]}),
    "interface_errors": ("show interfaces gigabitEthernet error {port}", {"port": PORT_RES["fabric"]}),
}
MAX_OUTPUT = 20000


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


class SshClient:
    def __init__(self):
        self.known_hosts = os.environ.get("SSH_KNOWN_HOSTS", "/etc/extreme-mcp/known_hosts")
        self.connect_timeout = int(os.environ.get("SSH_CONNECT_TIMEOUT_SECONDS", "8"))
        self.command_timeout = int(os.environ.get("SSH_COMMAND_TIMEOUT_SECONDS", "20"))
        self.sem = asyncio.Semaphore(int(os.environ.get("SSH_MAX_PARALLEL", "5")))

    async def run(self, ip: str, key: str, **args: str) -> str:
        cmd = build_command(key, **args)
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
                    res = await conn.run(cmd, check=False, timeout=self.command_timeout)
        except asyncssh.HostKeyNotVerifiable:
            raise SshError("host key verification failed") from None  # never auto-trust a changed key
        except (asyncssh.Error, OSError, asyncio.TimeoutError) as e:
            raise SshError(f"ssh failed: {type(e).__name__}") from None
        if res.exit_status not in (0, None):
            raise SshError(f"command exited with status {res.exit_status}")
        return str(res.stdout)[:MAX_OUTPUT]
