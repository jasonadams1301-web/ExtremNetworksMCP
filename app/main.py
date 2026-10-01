"""Read-only Extreme Networks MCP server (Streamable HTTP, loopback only).

Registers only the approved read-only tools. There is deliberately no generic command runner,
SNMP SET, or any configuration/reboot tool.
"""
import logging
import os

from mcp.server.fastmcp import FastMCP

from app.adapters.snmp import SnmpClient
from app.audit import Audit
from app.tools import switches as t
from app.validation import Inventory


def build_server(inv: Inventory, snmp: SnmpClient, audit: Audit) -> FastMCP:
    host = os.environ.get("MCP_BIND_ADDRESS", "127.0.0.1")
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise SystemExit("MCP_BIND_ADDRESS must be loopback")
    mcp = FastMCP("extreme-network-readonly", host=host, port=int(os.environ.get("MCP_PORT", "8000")))

    @mcp.tool()
    @audit.tool("list_switches", "inventory")
    async def list_switches() -> list[dict]:
        """List the approved managed switches."""
        return await t.list_switches(inv)

    @mcp.tool()
    @audit.tool("get_switch_health", "snmpv3")
    async def get_switch_health(switch: str) -> dict:
        """Return name, description, location and uptime for an approved switch."""
        return await t.get_switch_health(inv, snmp, switch)

    @mcp.tool()
    @audit.tool("get_interface", "snmpv3")
    async def get_interface(switch: str, port: str) -> dict:
        """Return state, speed and counters for one port (e.g. '1:48')."""
        return await t.get_interface(inv, snmp, switch, port)

    @mcp.tool()
    @audit.tool("get_interface_errors", "snmpv3")
    async def get_interface_errors(switch: str, port: str) -> dict:
        """Return discard and error counters for one port."""
        return await t.get_interface_errors(inv, snmp, switch, port)

    @mcp.tool()
    @audit.tool("get_lldp_neighbors", "snmpv3")
    async def get_lldp_neighbors(switch: str) -> dict:
        """Return LLDP neighbours and local-port mappings."""
        return await t.get_lldp_neighbors(inv, snmp, switch)

    return mcp


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    inv = Inventory.load(os.environ.get("INVENTORY_FILE", "/etc/extreme-mcp/inventory.yaml"))
    build_server(inv, SnmpClient(), Audit(os.environ.get("AUDIT_LOG"))).run(transport="streamable-http")


if __name__ == "__main__":
    main()
