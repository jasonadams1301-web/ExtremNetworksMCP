#!/bin/bash
# Install extreme-mcp on the Ubuntu server (run from the project folder).
#   bash install.sh
# Code lives in /opt/extreme-mcp (root-owned, so the agent cannot change it); config in /etc/extreme-mcp.
# SNMPv3 credentials are NOT written by this script: supply SNMP_USERNAME / SNMP_AUTH_PASSWORD / SNMP_PRIV_PASSWORD
# through systemd credentials or your secret store.
set -euo pipefail
cd "$(dirname "$0")"

id extreme-mcp >/dev/null 2>&1 || sudo useradd --system --home-dir /opt/extreme-mcp --shell /usr/sbin/nologin extreme-mcp
sudo install -d -o root -g root -m 755 /opt/extreme-mcp
sudo install -d -o root -g extreme-mcp -m 750 /etc/extreme-mcp
sudo install -d -o extreme-mcp -g extreme-mcp -m 750 /var/log/extreme-mcp
sudo python3 -m venv /opt/extreme-mcp/venv
sudo /opt/extreme-mcp/venv/bin/pip install -q -r requirements.txt
sudo cp -r app /opt/extreme-mcp/
sudo chown -R root:root /opt/extreme-mcp/app

[ -f /etc/extreme-mcp/extreme-mcp.env ] || sudo install -o root -g extreme-mcp -m 640 extreme-mcp.env.example /etc/extreme-mcp/extreme-mcp.env
[ -f /etc/extreme-mcp/inventory.yaml ] || sudo install -o root -g extreme-mcp -m 640 inventory.example.yaml /etc/extreme-mcp/inventory.yaml
sudo install -o root -g root -m 644 extreme-mcp.service /etc/systemd/system/extreme-mcp.service
sudo systemctl daemon-reload

echo "Edit /etc/extreme-mcp/inventory.yaml, provide the SNMPv3 secrets, then:"
echo "  sudo systemctl enable --now extreme-mcp && sudo ss -lntp | grep ':8000'   # must show 127.0.0.1"
