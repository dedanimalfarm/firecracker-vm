#!/usr/bin/env bash
set -euo pipefail

BRIDGE_NAME="${BRIDGE_NAME:-fcbr0}"
SUBNET_CIDR="${SUBNET_CIDR:-172.16.0.0/24}"

echo "[*] Removing NAT rule (if exists)"
sudo iptables -t nat -D POSTROUTING -s "${SUBNET_CIDR}" '!' -o "${BRIDGE_NAME}" -j MASQUERADE 2>/dev/null || true

echo "[*] Disabling ip_forward"
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null

echo "[*] Deleting bridge ${BRIDGE_NAME} (if exists)"
sudo ip link set "${BRIDGE_NAME}" down 2>/dev/null || true
sudo ip link del "${BRIDGE_NAME}" 2>/dev/null || true

echo "[OK] Network cleaned"
