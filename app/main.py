"""Read-only Extreme Networks MCP server (Streamable HTTP, loopback only).

Registers only the approved read-only tools. There is deliberately no generic command runner,
SNMP SET, or any configuration/reboot tool.
"""
import functools
import logging
import os

from mcp.server.fastmcp import FastMCP

from app.adapters.snmp import SnmpClient
from app.adapters.ssh import SshClient
from app.audit import Audit
from app.tools import arp as ar
from app.tools import auth as au
from app.tools import config as cf
from app.tools import dhcp as dh
from app.tools import fabric as fb
from app.tools import ports as pt
from app.tools import routing as rt
from app.tools import ssh_tools as st
from app.tools import switches as t
from app.tools import vlans as vl
from app.validation import Inventory


def build_server(inv: Inventory, snmp: SnmpClient, audit: Audit, ssh: SshClient | None = None) -> FastMCP:
    host = os.environ.get("MCP_BIND_ADDRESS", "127.0.0.1")
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise SystemExit("MCP_BIND_ADDRESS must be loopback")
    mcp = FastMCP("extreme-network-readonly", host=host, port=int(os.environ.get("MCP_PORT", "8765")))

    def tagged(fn):
        """Put the switch's own management_ip in every result, so the agent never has to infer it."""
        @functools.wraps(fn)
        async def wrapper(**params):
            result = await fn(**params)
            ip = inv.ip_of(params.get("switch"))
            if isinstance(result, dict) and ip:
                result = {"switch": result.get("switch", params.get("switch")), "management_ip": ip,
                          **{k: v for k, v in result.items() if k != "switch"}}
            return result
        return wrapper

    @mcp.tool()
    @audit.tool("list_switches", "inventory")
    async def list_switches(name_contains: str | None = None, site: str | None = None, platform: str | None = None,
                            limit: int = 50) -> dict:
        """List approved switches (name, management_ip, site, model, platform, snmp_security). Filter with name_contains,
        site or platform (fabric, exos, ers, other); limit up to 200. With no filter it also returns the site list."""
        return await t.list_switches(inv, name_contains, site, platform, limit)

    @mcp.tool()
    @audit.tool("get_switch_health", "snmpv3")
    @tagged
    async def get_switch_health(switch: str) -> dict:
        """Return uptime plus CPU %, memory %, temperatures, power supply state and fan trays for a switch."""
        return await t.get_switch_health(inv, snmp, switch)

    @mcp.tool()
    @audit.tool("get_interface", "snmpv3")
    @tagged
    async def get_interface(switch: str, port: str) -> dict:
        """Return state, speed and counters for one port (Fabric Engine e.g. '1/1'; Switch Engine e.g. '1:48')."""
        return await t.get_interface(inv, snmp, switch, port)

    @mcp.tool()
    @audit.tool("get_interface_errors", "snmpv3")
    @tagged
    async def get_interface_errors(switch: str, port: str) -> dict:
        """Return discard and error counters for one port."""
        return await t.get_interface_errors(inv, snmp, switch, port)

    @mcp.tool()
    @audit.tool("get_dhcp_status", "snmpv3")
    @tagged
    async def get_dhcp_status(switch: str) -> dict:
        """Return the DHCP relay configuration (relay interfaces and servers) and whether the switch likely runs a local DHCP server."""
        return await t.get_dhcp_status(inv, snmp, switch)

    @mcp.tool()
    @audit.tool("get_lldp_neighbors", "snmpv3")
    @tagged
    async def get_lldp_neighbors(switch: str) -> dict:
        """Return LLDP neighbours and local-port mappings."""
        return await t.get_lldp_neighbors(inv, snmp, switch)

    @mcp.tool()
    @audit.tool("get_port_summary", "snmpv3")
    @tagged
    async def get_port_summary(switch: str, state: str | None = None, only_errors: bool = False,
                               changed_within_minutes: int | None = None, limit: int = 100) -> dict:
        """Return every physical port with state (up, down, admin_down), speed, error/discard counters and how long
        ago it last changed state. Filters: state, only_errors, changed_within_minutes (finds recent flaps), limit."""
        return await pt.get_port_summary(inv, snmp, switch, state, only_errors, changed_within_minutes, limit)

    if ssh is not None:  # Phase 2: fixed read-only show commands, Fabric Engine only
        @mcp.tool()
        @audit.tool("get_system_info", "ssh")
        @tagged
        async def get_system_info(switch: str) -> dict:
            """Return detailed system, power, fan and temperature output (Fabric Engine)."""
            return await st.get_system_info(inv, ssh, switch)

        @mcp.tool()
        @audit.tool("get_fabric_adjacencies", "ssh")
        @tagged
        async def get_fabric_adjacencies(switch: str) -> dict:
            """Return IS-IS (SPB fabric) adjacencies for a Fabric Engine switch."""
            return await st.get_fabric_adjacencies(inv, ssh, switch)

        @mcp.tool()
        @audit.tool("get_vlans", "ssh")
        @tagged
        async def get_vlans(switch: str, vlan: int | None = None, name_contains: str | None = None,
                            limit: int = 100) -> dict:
            """Return VLANs with name, type, I-SID and port members (slot/port ranges). Optional filters: vlan
            (1-4094) or name_contains."""
            return await vl.get_vlans(inv, ssh, switch, vlan, name_contains, limit)

        @mcp.tool()
        @audit.tool("get_routing", "ssh")
        @tagged
        async def get_routing(switch: str, destination: str | None = None, protocol: str | None = None,
                              vrf: str | None = None, limit: int = 100) -> dict:
            """Return IP interfaces (address, up/down) and the route table. Give destination (an IPv4 address) to get
            the route the switch would use for it. Optional protocol (LOC, STAT, ISIS, OSPF, BGP, RIP, SPBM) and
            vrf (named VRFs only; omit for the global table)."""
            return await rt.get_routing(inv, ssh, switch, destination, protocol, vrf, limit)

        @mcp.tool()
        @audit.tool("get_fabric_status", "ssh")
        @tagged
        async def get_fabric_status(switch: str) -> dict:
            """Return SPB / IS-IS state (system id, nickname, interfaces up or down, adjacencies) and spanning-tree
            topology-change counters (Fabric Engine)."""
            return await fb.get_fabric_status(inv, ssh, switch)

        @mcp.tool()
        @audit.tool("get_auth_status", "ssh")
        @tagged
        async def get_auth_status(switch: str) -> dict:
            """Return 802.1X (EAPOL) client counts and RADIUS reachability. Credential fields are hidden."""
            return await au.get_auth_status(inv, ssh, switch)

        @mcp.tool()
        @audit.tool("get_running_config", "ssh")
        @tagged
        async def get_running_config(switch: str, section: str | None = None, search: str | None = None,
                                     context: int = 2, offset: int | None = None, limit: int = 4000) -> dict:
            """Return a switch's COMPLETE running configuration (unfiltered) as one text block, plus the list of sections
            (name, first line, line count). To read part of it instead: section (text from a section name, e.g. 'SNMP'),
            search (text to find, with context lines around each match, to check whether a setting exists such as 'ntp'),
            or offset+limit to read numbered lines."""
            return await cf.get_running_config(inv, ssh, switch, section, search, context, offset, limit)

        @mcp.tool()
        @audit.tool("get_switch_logs", "ssh")
        @tagged
        async def get_switch_logs(switch: str, lines: int = 100, severity: str | None = None,
                                  contains: str | None = None) -> dict:
            """Return the newest log entries from a Fabric Engine switch (lines 1-200). Optional severity
            (INFO, WARNING, ERROR, FATAL: that level and worse) and contains (text filter).
            In login lines, 'on host <IP>' is the connecting client (the MCP/OCE host), not the switch;
            the switch's own address is the management_ip field."""
            return await st.get_switch_logs(inv, ssh, switch, lines, severity, contains)

        @mcp.tool()
        @audit.tool("get_dhcp_server", "ssh")
        @tagged
        async def get_dhcp_server(switch: str) -> dict:
            """Return whether the switch's built-in DHCP server is enabled, its settings, subnets with lease
            utilization, and the number of host reservations (Fabric Engine)."""
            return await dh.get_dhcp_server(inv, ssh, switch)

        @mcp.tool()
        @audit.tool("get_dhcp_leases", "ssh")
        @tagged
        async def get_dhcp_leases(switch: str, contains: str | None = None, subnet: str | None = None,
                                  limit: int = 100) -> dict:
            """Return DHCP server leases (IP, MAC, last transaction, expiry), most recent first. Optional
            contains (IP or MAC fragment) and subnet (e.g. 192.0.2.0/24) filters; limit 1-200."""
            return await dh.get_dhcp_leases(inv, ssh, switch, contains, subnet, limit)

        @mcp.tool()
        @audit.tool("get_dhcp_relay", "ssh")
        @tagged
        async def get_dhcp_relay(switch: str) -> dict:
            """Return DHCP relay interfaces with request/reply counters and their configured DHCP servers."""
            return await dh.get_dhcp_relay(inv, ssh, switch)

        @mcp.tool()
        @audit.tool("get_dhcp_server_log", "ssh")
        @tagged
        async def get_dhcp_server_log(switch: str, lines: int = 50, level: str | None = None,
                                      contains: str | None = None, include_noise: bool = False) -> dict:
            """Return the newest DHCP server log entries (lines 1-200). Optional level (INFO, WARN, ERROR,
            FATAL: that level and worse) and contains filter; routine polling is hidden unless include_noise."""
            return await dh.get_dhcp_server_log(inv, ssh, switch, lines, level, contains, include_noise)

        @mcp.tool()
        @audit.tool("get_arp_table", "ssh")
        @tagged
        async def get_arp_table(switch: str, contains: str | None = None, subnet: str | None = None,
                                vlan: int | None = None, port: str | None = None, entry_type: str | None = None,
                                vrf: str | None = None, limit: int = 100) -> dict:
            """Return the switch's ARP table (IP, MAC, VLAN, port, type, TTL), sorted by IP. Optional filters:
            contains (IP or MAC fragment), subnet (e.g. 192.0.2.0/24), vlan (1-4094), port (e.g. 1/48),
            entry_type (DYNAMIC or LOCAL), vrf (name; default is the GlobalRouter), limit 1-200."""
            return await ar.get_arp_table(inv, ssh, switch, contains, subnet, vlan, port, entry_type, vrf, limit)

        @mcp.tool()
        @audit.tool("find_mac_address", "ssh")
        @tagged
        async def find_mac_address(switch: str, mac: str) -> dict:
            """Locate a MAC address in the switch forwarding table."""
            return await st.find_mac_address(inv, ssh, switch, mac)

    return mcp


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    inv = Inventory.load(os.environ.get("INVENTORY_FILE", "/etc/extreme-mcp/inventory.yaml"))
    ssh = SshClient() if os.environ.get("SSH_ENABLED", "false").lower() == "true" else None
    build_server(inv, SnmpClient(levels=inv.snmp_levels()), Audit(os.environ.get("AUDIT_LOG")), ssh).run(transport="streamable-http")


if __name__ == "__main__":
    main()
