"""Read-only Extreme Networks MCP server (Streamable HTTP, loopback only).

Registers only the approved read-only tools. There is deliberately no generic command runner,
SNMP SET, or any configuration/reboot tool.
"""
import logging
import os

from mcp.server.fastmcp import FastMCP

from app.adapters.snmp import SnmpClient
from app.adapters.ssh import SshClient
from app.audit import Audit
from app.tools import dhcp as dh
from app.tools import ssh_tools as st
from app.tools import switches as t
from app.validation import Inventory


def build_server(inv: Inventory, snmp: SnmpClient, audit: Audit, ssh: SshClient | None = None) -> FastMCP:
    host = os.environ.get("MCP_BIND_ADDRESS", "127.0.0.1")
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise SystemExit("MCP_BIND_ADDRESS must be loopback")
    mcp = FastMCP("extreme-network-readonly", host=host, port=int(os.environ.get("MCP_PORT", "8765")))

    @mcp.tool()
    @audit.tool("list_switches", "inventory")
    async def list_switches() -> list[dict]:
        """List the approved managed switches."""
        return await t.list_switches(inv)

    @mcp.tool()
    @audit.tool("get_switch_health", "snmpv3")
    async def get_switch_health(switch: str) -> dict:
        """Return uptime plus CPU %, memory %, temperatures, power supply state and fan trays for a switch."""
        return await t.get_switch_health(inv, snmp, switch)

    @mcp.tool()
    @audit.tool("get_interface", "snmpv3")
    async def get_interface(switch: str, port: str) -> dict:
        """Return state, speed and counters for one port (Fabric Engine e.g. '1/1'; Switch Engine e.g. '1:48')."""
        return await t.get_interface(inv, snmp, switch, port)

    @mcp.tool()
    @audit.tool("get_interface_errors", "snmpv3")
    async def get_interface_errors(switch: str, port: str) -> dict:
        """Return discard and error counters for one port."""
        return await t.get_interface_errors(inv, snmp, switch, port)

    @mcp.tool()
    @audit.tool("get_dhcp_status", "snmpv3")
    async def get_dhcp_status(switch: str) -> dict:
        """Return the DHCP relay configuration (relay interfaces and servers) and whether the switch likely runs a local DHCP server."""
        return await t.get_dhcp_status(inv, snmp, switch)

    @mcp.tool()
    @audit.tool("get_lldp_neighbors", "snmpv3")
    async def get_lldp_neighbors(switch: str) -> dict:
        """Return LLDP neighbours and local-port mappings."""
        return await t.get_lldp_neighbors(inv, snmp, switch)

    if ssh is not None:  # Phase 2: fixed read-only show commands, Fabric Engine only
        @mcp.tool()
        @audit.tool("get_system_info", "ssh")
        async def get_system_info(switch: str) -> dict:
            """Return detailed system, power, fan and temperature output (Fabric Engine)."""
            return await st.get_system_info(inv, ssh, switch)

        @mcp.tool()
        @audit.tool("get_fabric_adjacencies", "ssh")
        async def get_fabric_adjacencies(switch: str) -> dict:
            """Return IS-IS (SPB fabric) adjacencies for a Fabric Engine switch."""
            return await st.get_fabric_adjacencies(inv, ssh, switch)

        @mcp.tool()
        @audit.tool("get_interface_detail", "ssh")
        async def get_interface_detail(switch: str, port: str) -> dict:
            """Return detailed interface, statistics and error output for one port (e.g. '1/1')."""
            return await st.get_interface_detail(inv, ssh, switch, port)

        @mcp.tool()
        @audit.tool("get_switch_logs", "ssh")
        async def get_switch_logs(switch: str, lines: int = 100, severity: str | None = None,
                                  contains: str | None = None) -> dict:
            """Return the newest log entries from a Fabric Engine switch (lines 1-200). Optional severity
            (INFO, WARNING, ERROR, FATAL: that level and worse) and contains (text filter)."""
            return await st.get_switch_logs(inv, ssh, switch, lines, severity, contains)

        @mcp.tool()
        @audit.tool("get_dhcp_server", "ssh")
        async def get_dhcp_server(switch: str) -> dict:
            """Return whether the switch's built-in DHCP server is enabled, its settings, subnets with lease
            utilization, and the number of host reservations (Fabric Engine)."""
            return await dh.get_dhcp_server(inv, ssh, switch)

        @mcp.tool()
        @audit.tool("get_dhcp_leases", "ssh")
        async def get_dhcp_leases(switch: str, contains: str | None = None, subnet: str | None = None,
                                  limit: int = 100) -> dict:
            """Return DHCP server leases (IP, MAC, last transaction, expiry), most recent first. Optional
            contains (IP or MAC fragment) and subnet (e.g. 10.0.0.0/24) filters; limit 1-200."""
            return await dh.get_dhcp_leases(inv, ssh, switch, contains, subnet, limit)

        @mcp.tool()
        @audit.tool("get_dhcp_relay", "ssh")
        async def get_dhcp_relay(switch: str) -> dict:
            """Return DHCP relay interfaces with request/reply counters and their configured DHCP servers."""
            return await dh.get_dhcp_relay(inv, ssh, switch)

        @mcp.tool()
        @audit.tool("get_dhcp_server_log", "ssh")
        async def get_dhcp_server_log(switch: str, lines: int = 50, level: str | None = None,
                                      contains: str | None = None, include_noise: bool = False) -> dict:
            """Return the newest DHCP server log entries (lines 1-200). Optional level (INFO, WARN, ERROR,
            FATAL: that level and worse) and contains filter; routine polling is hidden unless include_noise."""
            return await dh.get_dhcp_server_log(inv, ssh, switch, lines, level, contains, include_noise)

        @mcp.tool()
        @audit.tool("find_mac_address", "ssh")
        async def find_mac_address(switch: str, mac: str) -> dict:
            """Locate a MAC address in the switch forwarding table."""
            return await st.find_mac_address(inv, ssh, switch, mac)

    return mcp


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    inv = Inventory.load(os.environ.get("INVENTORY_FILE", "/etc/extreme-mcp/inventory.yaml"))
    ssh = SshClient() if os.environ.get("SSH_ENABLED", "false").lower() == "true" else None
    build_server(inv, SnmpClient(), Audit(os.environ.get("AUDIT_LOG")), ssh).run(transport="streamable-http")


if __name__ == "__main__":
    main()
