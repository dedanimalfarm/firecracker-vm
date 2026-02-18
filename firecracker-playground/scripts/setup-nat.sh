#!/usr/bin/env bash
set -e

SUBNET_CIDR="${SUBNET_CIDR:-172.16.0.0/24}"
BRIDGE_NAME="${BRIDGE_NAME:-fcbr0}"

echo "[*] Enabling IP forwarding..."

if [ "$(cat /proc/sys/net/ipv4/ip_forward)" -ne 1 ]; then
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
fi

echo "[*] Adding NAT rule..."

if ! sudo iptables -t nat -C POSTROUTING -s "${SUBNET_CIDR}" ! -o "${BRIDGE_NAME}" -j MASQUERADE 2>/dev/null; then
    sudo iptables -t nat -A POSTROUTING -s "${SUBNET_CIDR}" ! -o "${BRIDGE_NAME}" -j MASQUERADE
    echo "[+] NAT rule added"
else
    echo "[=] NAT rule already exists"
fi

echo "[OK] NAT configured"
