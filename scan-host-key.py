#!/usr/bin/env python3
"""Print a switch's SSH host key as a known_hosts line plus its SHA256 fingerprint.

Older switches (for example ones with a Mocana SSH stack) only offer legacy key exchange, which OpenSSH's
`ssh-keyscan` refuses. This uses the same SSH library as the server, so it works wherever the server does.
It only READS the key. Check the fingerprint against the switch, then append the line to
/etc/extreme-mcp/known_hosts yourself:

    /opt/extreme-mcp/venv/bin/python scan-host-key.py 192.0.2.10 | sudo tee -a /etc/extreme-mcp/known_hosts
"""
import asyncio
import sys

import asyncssh


async def main(host: str) -> None:
    key = await asyncio.wait_for(asyncssh.get_server_host_key(host), 15)
    line = " ".join(key.export_public_key("openssh").decode().split()[:2])
    print(f"{host} {line}")
    print(f"# {key.get_algorithm()} {key.get_fingerprint()}", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: scan-host-key.py <switch-ip>")
    asyncio.run(main(sys.argv[1]))
