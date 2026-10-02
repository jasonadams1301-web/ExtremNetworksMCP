# extreme-mcp

A **read-only** [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that lets an AI agent
inspect Extreme Networks switches for monitoring and troubleshooting, built for
[OpenClaw Enterprise](https://github.com/mholovetskyi/openclawenterprise) (OCE) on Ubuntu Server.

It can look. It cannot change anything.

- **Fabric Engine** (VOSS) is the primary target. **Switch Engine** (EXOS) is supported for the SNMP tools.
- **SNMPv3 authPriv** is the primary data path. **SSH** (opt-in) fills the gaps with fixed `show` commands.
- Runs as its own systemd service on the same host as OCE, bound to **127.0.0.1 only**.
- Backend credentials never leave the service. The agent receives results, not passwords.

## Tools

| Tool | Backend | Platforms | What it returns |
|---|---|---|---|
| `list_switches` | inventory | all | Approved switches |
| `get_switch_health` | SNMPv3 | Fabric Engine (basic fields on Switch Engine) | Uptime, CPU %, memory %, temperatures, power-supply state, fan hardware present |
| `get_interface` | SNMPv3 | all | Admin/oper state, speed, counters for one port |
| `get_interface_errors` | SNMPv3 | all | Error and discard counters for one port |
| `get_lldp_neighbors` | SNMPv3 | all | LLDP neighbours and local-port mapping |
| `get_dhcp_status` | SNMPv3 | Fabric Engine | DHCP relay interfaces and servers; flags a likely local DHCP server |
| `get_switch_logs` | SSH | Fabric Engine | Newest log entries, optional severity (that level and worse) and text filter |
| `get_dhcp_server` | SSH | Fabric Engine | Built-in DHCP server: enabled?, settings, subnets with lease utilization (flags 90%+), host reservations |
| `get_dhcp_leases` | SSH | Fabric Engine | Leases (IP, MAC, last transaction, expiry), newest first; filter by subnet or IP/MAC fragment |
| `get_dhcp_relay` | SSH | Fabric Engine | Relay interfaces with request/reply counters and configured servers; flags interfaces with requests but no replies |
| `get_dhcp_server_log` | SSH | Fabric Engine | Newest DHCP server log entries; filter by level or text; routine polling hidden |
| `get_port_summary` | SNMPv3 | all | Every physical port: state (up / down / admin_down), speed, error and discard counters, time since last change; filter by state, errors, or "changed in the last N minutes" |
| `get_vlans` | SSH | Fabric Engine | VLANs with name, type, I-SID and port members; filter by VLAN id or name |
| `get_routing` | SSH | Fabric Engine | IP interfaces (flags down ones), route table, default route, and the route the switch would use for a given destination |
| `get_fabric_status` | SSH | Fabric Engine | SPB / IS-IS system, interfaces up or down, adjacencies, spanning-tree topology-change counters |
| `get_auth_status` | SSH | Fabric Engine | 802.1X client counts and RADIUS reachability (credential fields hidden) |
| `get_system_info` | SSH | Fabric Engine | `show sys-info` output |
| `get_fabric_adjacencies` | SSH | Fabric Engine | IS-IS (SPB) adjacencies |
| `get_arp_table` | SSH | Fabric Engine | ARP table (IP, MAC, VLAN, port, type, TTL); filter by IP/MAC fragment, subnet, VLAN, port, type or VRF |
| `find_mac_address` | SSH | Fabric Engine | Where a MAC address is in the forwarding table |

The SSH tools are only registered when `SSH_ENABLED=true`.

## Security model

The point of this project is that a prompt-injected or confused agent **cannot** do harm through it.

- **No write path exists.** There is no generic command runner, no SNMP SET, and no configuration,
  reboot, port-toggle or account tool. A tool that is not registered cannot be called.
- **Inventory allowlist.** Every request must name a switch in `inventory.yaml`. Raw IPs and arbitrary hostnames are rejected.
- **SNMP:** GET, GETNEXT and GETBULK only, restricted to an OID allowlist (system, IF-MIB, ENTITY-MIB, LLDP-MIB, vendor subtrees).
  authPriv is mandatory. If any of the username, auth password or privacy password is missing, nothing is sent.
- **SSH:** callers never supply CLI text. Each tool maps to a fixed `show ...` command from a table in
  `app/adapters/ssh.py`; the only variable is a port, validated by a strict regex. Log filters run locally after the
  fixed command, so filter text never reaches the switch. Host keys must be pre-approved in `known_hosts`
  (no trust-on-first-use; a changed key is refused).
- **Loopback only.** The server refuses to start on a non-loopback bind address.
- **Secrets** are systemd credentials (`LoadCredential=`), readable only by the service. They are never logged or returned.
- **Audit log:** one JSON line per call (requester, tool, target, sanitized parameters, backend, result, duration).
- **Treat switch text as data.** Log lines and device strings come from the network and can contain attacker-influenced text.

## Architecture

```
OpenClaw Enterprise (agent)
        |  MCP, Streamable HTTP
        v
http://127.0.0.1:8765/mcp   extreme-mcp.service  (dedicated non-root account)
        |-- SNMPv3 authPriv --> approved switch management IPs
        '-- SSH (optional)  --> approved switch management IPs
```

## Requirements

- Ubuntu Server with Python 3.10+ and `python3-venv` (development also works on Windows/macOS)
- Network access from the server to each switch: UDP 161 (SNMP) and, optionally, TCP 22 (SSH)
- An SNMPv3 user on every switch with a **read-only view**, using authPriv
- For SSH: a **read-only** switch account (the same on every switch)

## Quick start (development)

```
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt        # Windows: .venv\Scripts\pip
.venv/bin/python -m pytest
```

To run it locally, copy `inventory.example.yaml` to `inventory.yaml`, export `SNMP_USERNAME`,
`SNMP_AUTH_PASSWORD` and `SNMP_PRIV_PASSWORD`, then:

```
INVENTORY_FILE=inventory.yaml .venv/bin/python -m app.main
```

## Deploy on Ubuntu

```
bash install.sh                                      # user, directories, venv, /opt/extreme-mcp, systemd unit
sudoedit /etc/extreme-mcp/inventory.yaml             # list your switches
bash set-secret.sh snmp_username                     # prompts without echo, stores a root-only credential file
bash set-secret.sh snmp_auth_password
bash set-secret.sh snmp_priv_password
sudo systemctl enable --now extreme-mcp
sudo ss -lntp | grep :8765                           # must show 127.0.0.1
```

Code is installed root-owned under `/opt/extreme-mcp`, config under `/etc/extreme-mcp`, audit log under
`/var/log/extreme-mcp`.

### Enable SSH tools (optional)

1. Create a read-only account on the switches and confirm it cannot enter configuration mode.
2. Add the switches' host keys to `/etc/extreme-mcp/known_hosts` and verify the fingerprints out of band.
3. `bash set-secret.sh ssh_username` and `bash set-secret.sh ssh_password`.
4. Uncomment the two `LoadCredential=ssh_*` lines in `extreme-mcp.service`, set `SSH_ENABLED=true` in
   `/etc/extreme-mcp/extreme-mcp.env`, add `ssh` to each switch's `protocols`, then `daemon-reload` and restart.

**Recording a switch's host key.** Add each switch's key to `/etc/extreme-mcp/known_hosts` and verify the fingerprint on
the switch. If `ssh-keyscan` fails (older switches offer only legacy key exchange), use the bundled helper, which uses the
same SSH library as the server:

```
/opt/extreme-mcp/venv/bin/python /opt/extreme-mcp/scan-host-key.py <switch-ip> | sudo tee -a /etc/extreme-mcp/known_hosts
```

**Older switches.** The SSH library accepts `diffie-hellman-group14-sha1` as a last-resort key exchange, so switches whose
SSH server offers nothing newer still work. Host keys are still verified against `known_hosts`. Modern switches negotiate
stronger algorithms automatically.

Fabric Engine does not run one-off commands over an SSH exec channel, so each call opens an interactive CLI session,
sends only the fixed `show` command, answers the `--More--` pager, and closes. The switch may authenticate each
login separately (for example via RADIUS).

### Register with OpenClaw Enterprise

```
openclaw mcp add extreme-network-readonly --transport streamable-http \
  --url http://127.0.0.1:8765/mcp \
  --include list_switches,get_switch_health,get_interface,get_interface_errors,get_lldp_neighbors,get_dhcp_status
openclaw mcp probe extreme-network-readonly
```

Add the SSH tool names to `--include` (via `openclaw mcp tools`) once SSH is enabled. The include list is a second guard
on top of the server's own registration. Give the tools only to the agent that should use them, and tell that agent
in its instructions to use these tools for switch questions.

## Configuration

Inventory (`/etc/extreme-mcp/inventory.yaml`), re-read on service restart:

```yaml
switches:
  - name: example-switch-01        # what the agent uses; letters, digits, . _ -
    management_ip: 192.0.2.10
    platform: fabric              # fabric (Fabric Engine / VOSS) or exos (Switch Engine)
    site: Example Site
    mcp_enabled: true
    protocols: [snmpv3, ssh]
```

Settings (`/etc/extreme-mcp/extreme-mcp.env`, see `extreme-mcp.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `MCP_BIND_ADDRESS` / `MCP_PORT` | `127.0.0.1` / `8765` | Listener (loopback only) |
| `INVENTORY_FILE` | `/etc/extreme-mcp/inventory.yaml` | Switch allowlist |
| `AUDIT_LOG` | unset | JSON audit log path |
| `SNMP_AUTH_PROTOCOL` | `sha` | `sha` or `sha256` |
| `SNMP_PRIV_PROTOCOL` | `aes` | `aes` or `aes256` |
| `SNMP_TIMEOUT_SECONDS` / `SNMP_RETRIES` | `5` / `1` | SNMP timing |
| `SSH_ENABLED` | `false` | Register the SSH tools |
| `SSH_KNOWN_HOSTS` | `/etc/extreme-mcp/known_hosts` | Approved host keys |
| `SSH_CONNECT_TIMEOUT_SECONDS` / `SSH_COMMAND_TIMEOUT_SECONDS` | `8` / `20` | SSH timing |
| `SSH_MAX_PARALLEL` | `5` | Concurrent SSH sessions |

Secrets are **not** in this file. They are systemd credentials named `snmp_username`, `snmp_auth_password`,
`snmp_priv_password`, `ssh_username`, `ssh_password`. For local testing only, the upper-case names
(`SNMP_USERNAME`, ...) are read from the environment.

## Adding a switch

Add an entry to `inventory.yaml`, make sure the switch has the same SNMPv3 user (and SSH account, if used), allow
UDP 161 / TCP 22 from the server, add its host key to `known_hosts` for SSH, then `sudo systemctl restart extreme-mcp`.
The inventory is a security boundary, so the agent cannot edit it.

## Project layout

```
app/main.py              server, tool registration, loopback guard
app/validation.py        inventory allowlist, port validation per platform
app/audit.py             one JSON audit event per tool call
app/secrets.py           systemd credential lookup (env fallback for tests)
app/adapters/snmp.py     SNMPv3 GET / bulk-walk only, OID allowlist
app/adapters/ssh.py      fixed command table, interactive session driver
app/tools/switches.py    SNMP-backed tools
app/tools/ssh_tools.py   SSH-backed tools
tests/                   pytest (SNMP and SSH are faked; no switch needed)
install.sh, set-secret.sh, extreme-mcp.service, *.example   deployment files
```

## Verified against

Fabric Engine 9.3 on 5420M switches and a VSP 7400 (SNMPv3 authPriv and SSH). CPU and memory use the Rapid City MIB
(`rcKhiSlotCpuCurrentUtil`, `rcKhiSlotMemUtil`); other vendor OIDs are documented in `app/tools/switches.py`.
Other platforms and releases may differ, so check the SNMP OIDs and `show` commands on your own hardware.

## Known limitations

- Fan speed and status are not exposed over SNMP on the tested platform. Only installed fan trays are listed.
- Switch Engine (EXOS) has no SSH tools yet, and only basic fields from `get_switch_health`.
- Stack health, LACP/MLT detail, fibre-optic (transceiver) levels and per-port CLI statistics are not available: the
  read-only account cannot run `show interfaces ...` on the tested release. Per-port state and errors come from SNMP.
- Stack health is not implemented. The DHCP server log is a short rolling window and can lag the switch clock.
- One shared SNMPv3 credential set and one shared SSH account for all switches.
- Log search looks back about 1,000 lines when a severity or text filter is used.

## Testing

`python -m pytest` runs the suite offline. SNMP and SSH are replaced by fakes, and the SSH session driver is tested
against a scripted transcript captured from a real Fabric Engine switch.

## License

Apache License 2.0. See [LICENSE](LICENSE).
