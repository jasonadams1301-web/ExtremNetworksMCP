# extreme-mcp

Read-only MCP server that lets OpenClaw Enterprise inspect Extreme Networks switches.
Spec: [docs/Extreme_Networks_Read-Only_MCP_Server_for_OCE.docx](docs/Extreme_Networks_Read-Only_MCP_Server_for_OCE.docx).

- Transport: Streamable HTTP on `127.0.0.1:8000/mcp` (non-loopback bind is refused).
- Platforms: Fabric Engine (`platform: fabric`, ports like `1/1`) is the primary target; Switch Engine/EXOS
  (`platform: exos`, ports like `1:48`) is also accepted. Set `platform` per switch in the inventory.
- Phase 1 (this code): SNMPv3 authPriv only. Tools: `list_switches`, `get_switch_health`,
  `get_interface`, `get_interface_errors`, `get_lldp_neighbors`.
- No generic command runner, SNMP SET, or write tools exist. Switches must be in the inventory allowlist.
- Phase 2 (opt-in, `SSH_ENABLED=true`, Fabric Engine only): fixed read-only `show` commands over SSH.
  Tools: `get_system_info`, `get_fabric_adjacencies`, `get_interface_detail`, `find_mac_address`.
  Needs a read-only switch account, `SSH_USERNAME` + `SSH_PASSWORD` (or `SSH_KEY_FILE`), and a pre-populated
  `known_hosts` (no trust-on-first-use). The commands live in `app/adapters/ssh.py`; verify each on hardware.
- Phase 3 (NetWatch / XIQ) is not built yet.

## Develop
```
python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.txt   # Linux: .venv/bin/pip
.venv/Scripts/python -m pytest
```

## Run
Copy `inventory.example.yaml` to `inventory.yaml` and `extreme-mcp.env.example` to `extreme-mcp.env`,
export `SNMP_USERNAME`, `SNMP_AUTH_PASSWORD`, `SNMP_PRIV_PASSWORD` (never commit them), then
`INVENTORY_FILE=inventory.yaml python -m app.main`. Production install: `bash install.sh`.
