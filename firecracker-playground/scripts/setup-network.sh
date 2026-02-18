#!/usr/bin/env bash
set -e

BRIDGE_NAME="${BRIDGE_NAME:-fcbr0}"
BRIDGE_ADDR="${BRIDGE_ADDR:-172.16.0.1/24}"

echo "[*] Creating bridge ${BRIDGE_NAME} if not exists..."

if ! ip link show "${BRIDGE_NAME}" >/dev/null 2>&1; then
    sudo ip link add name "${BRIDGE_NAME}" type bridge
    echo "[+] Bridge created"
else
    echo "[=] Bridge already exists"
fi

echo "[*] Assigning address ${BRIDGE_ADDR}..."

if ! ip addr show "${BRIDGE_NAME}" | grep -q "${BRIDGE_ADDR}"; then
    sudo ip addr add "${BRIDGE_ADDR}" dev "${BRIDGE_NAME}" || true
fi

sudo ip link set "${BRIDGE_NAME}" up

echo "[OK] Bridge ready"
