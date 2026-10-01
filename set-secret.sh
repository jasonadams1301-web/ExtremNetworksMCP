#!/bin/bash
# Store one secret as a root-only systemd credential file, without echoing it or putting it in shell history.
#   bash set-secret.sh snmp_username | snmp_auth_password | snmp_priv_password | ssh_username | ssh_password
set -euo pipefail
name="${1:-}"
case "$name" in
  snmp_username|snmp_auth_password|snmp_priv_password|ssh_username|ssh_password) ;;
  *) echo "usage: bash set-secret.sh <snmp_username|snmp_auth_password|snmp_priv_password|ssh_username|ssh_password>" >&2; exit 1 ;;
esac
read -rsp "$name: " value; echo
[ -n "$value" ] || { echo "empty value, nothing written" >&2; exit 1; }
printf %s "$value" | sudo install -o root -g root -m 600 /dev/stdin "/etc/extreme-mcp/credentials/$name"
echo "stored /etc/extreme-mcp/credentials/$name (restart the service to pick it up: sudo systemctl restart extreme-mcp)"
