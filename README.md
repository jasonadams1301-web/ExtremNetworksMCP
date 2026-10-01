# extreme-mcp

Read-only MCP server that lets OpenClaw Enterprise inspect Extreme Networks switches.
Spec: [docs/Extreme_Networks_Read-Only_MCP_Server_for_OCE.docx](docs/Extreme_Networks_Read-Only_MCP_Server_for_OCE.docx).

- Transport: Streamable HTTP on `127.0.0.1:8000/mcp` (non-loopback bind is refused).
- Platforms: Fabric Engine (`platform: fabric`, ports like `1/1`) is the primary target; Switch Engine/EXOS
  (`platform: exos`, ports like `1:48`) is also accepted. Set `platform` per switch in the inventory.
- Phase 1 (this code): SNMPv3 authPriv only. Tools: `list_switches`, `get_switch_health`,
  `get_interface`, `get_interface_errors`, `get_lldp_neighbors`.
- No generic command runner, SNMP SET, or write tools exist. Switches must be in the inventory allowlist.
- Phase 2 (fixed read-only SSH `show` commands) and Phase 3 (NetWatch / XIQ) are not built yet.

## Develop
```
python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.txt   # Linux: .venv/bin/pip
.venv/Scripts/python -m pytest
```

## Run
Copy `inventory.example.yaml` to `inventory.yaml` and `extreme-mcp.env.example` to `extreme-mcp.env`,
export `SNMP_USER`, `SNMP_AUTH_KEY`, `SNMP_PRIV_KEY` (never commit them), then
`INVENTORY_FILE=inventory.yaml python -m app.main`. Production install: `bash install.sh`.
