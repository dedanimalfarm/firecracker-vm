#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   SSH_PUB_KEY=/srv/firecracker/keys/microvm_ed25519.pub \
#   OUT_DIR=../images \
#   OUT_IMG=bookworm.rootfs.ext4 \
#   SIZE=2G \
#   ./scripts/build-rootfs.sh
#
# Defaults are reasonable for your current layout.

SSH_PUB_KEY="${SSH_PUB_KEY:-/srv/firecracker/keys/microvm_ed25519.pub}"
OUT_DIR="${OUT_DIR:-../images}"
OUT_IMG="${OUT_IMG:-bookworm.rootfs.ext4}"
SIZE="${SIZE:-2G}"
HOSTNAME_VM="${HOSTNAME_VM:-debian-fc-uvm}"

MNT="$(mktemp -d)"
IMG_PATH="${OUT_DIR}/${OUT_IMG}"

cleanup() {
  set +e
  mountpoint -q "$MNT" && sudo umount "$MNT"
  rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT

if [ ! -f "$SSH_PUB_KEY" ]; then
  echo "ERROR: SSH public key not found: $SSH_PUB_KEY"
  exit 1
fi

mkdir -p "$OUT_DIR"

echo "[*] Creating ext4 image: $IMG_PATH size=$SIZE"
sudo rm -f "$IMG_PATH"
sudo truncate -s "$SIZE" "$IMG_PATH"
sudo mkfs.ext4 -F "$IMG_PATH" >/dev/null

echo "[*] Mounting image to $MNT"
sudo mount "$IMG_PATH" "$MNT"

echo "[*] Debootstrap Debian 12 (bookworm)"
sudo debootstrap --arch=amd64 bookworm "$MNT" http://deb.debian.org/debian

echo "[*] Basic config: hostname, hosts"
echo "$HOSTNAME_VM" | sudo tee "$MNT/etc/hostname" >/dev/null
sudo tee "$MNT/etc/hosts" >/dev/null <<EOF
127.0.0.1 localhost
127.0.1.1 $HOSTNAME_VM
EOF

echo "[*] Install minimal packages"
sudo chroot "$MNT" apt-get update
sudo chroot "$MNT" apt-get install -y --no-install-recommends \
  openssh-server \
  systemd-sysv \
  ca-certificates \
  iproute2 \
  net-tools \
  procps \
  vim-tiny

echo "[*] Configure SSH: root pubkey only"
sudo mkdir -p "$MNT/root/.ssh"
sudo cp "$SSH_PUB_KEY" "$MNT/root/.ssh/authorized_keys"
sudo chmod 700 "$MNT/root/.ssh"
sudo chmod 600 "$MNT/root/.ssh/authorized_keys"

# Ensure sshd can start in a minimal rootfs
sudo mkdir -p "$MNT/var/run/sshd"

# Harden sshd: key-only auth, allow root
sudo sed -i 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' "$MNT/etc/ssh/sshd_config"
sudo sed -i 's/^[#[:space:]]*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' "$MNT/etc/ssh/sshd_config" 2>/dev/null || true
sudo sed -i 's/^[#[:space:]]*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$MNT/etc/ssh/sshd_config" 2>/dev/null || true
sudo sed -i 's/^[#[:space:]]*UsePAM.*/UsePAM yes/' "$MNT/etc/ssh/sshd_config"
sudo sed -i 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' "$MNT/etc/ssh/sshd_config"

# Optional: speed up boot, avoid waiting for random
sudo mkdir -p "$MNT/etc/systemd/system/sshd.service.d"
sudo tee "$MNT/etc/systemd/system/sshd.service.d/override.conf" >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/sshd -D -e
EOF

echo "[*] Clean apt cache"
sudo chroot "$MNT" apt-get clean
sudo rm -rf "$MNT/var/lib/apt/lists/"*

echo "[*] Done, unmounting"
sudo umount "$MNT"

echo "[OK] Rootfs created: $IMG_PATH"
