# firecracker-playground

Web playground where users create isolated Firecracker microVM sessions and get a browser terminal.
Target scale: 10-20 concurrent sessions.

Recommended production mode: host `systemd` + `nginx`.
Docker is optional for development only.

## Architecture

Browser -> nginx :80 -> backend :8080 (localhost) -> create microVM + start ttyd -> backend proxies `/t/<token>/` to ttyd.
Only port 80 is exposed publicly.

## Repository layout

- `app/server.js`, `app/package.json`
- `deploy/nginx/firecracker.conf`
- `deploy/systemd/fc-backend.service`
- `scripts/setup-network.sh`, `scripts/setup-nat.sh`, `scripts/cleanup-network.sh`, `scripts/build-rootfs.sh`
- `Dockerfile`
- `.env.example`

## Requirements

Host OS:
- Debian 12 (or similar)

Host prerequisites:
- `/dev/kvm` available
- `firecracker`
- `ttyd`
- `iproute2`
- `iptables`
- `nodejs 18+` (host mode)

Host assets:
- Kernel: `/srv/firecracker/images/vmlinux.bin`
- Base rootfs: `/srv/firecracker/images/bionic.rootfs.ext4`
- SSH key pair: `/srv/firecracker/keys/microvm_ed25519` and `.pub`

## Host setup quickstart

### 1) Create host directories

```bash
sudo mkdir -p /srv/firecracker/images /srv/firecracker/keys /srv/firecracker/vms
sudo mkdir -p /opt/firecracker-playground /etc/firecracker-playground
```

### 2) Copy project and install backend deps

```bash
sudo rsync -a ./ /opt/firecracker-playground/
cd /opt/firecracker-playground/app
sudo npm install --omit=dev
```

### 3) Configure env file

```bash
sudo cp /opt/firecracker-playground/.env.example /etc/firecracker-playground/env
sudo chmod 600 /etc/firecracker-playground/env
sudo editor /etc/firecracker-playground/env
```

Set at least `API_TOKEN` for public deployments.

### 4) Configure host networking

```bash
cd /opt/firecracker-playground
chmod +x scripts/*.sh
./scripts/setup-network.sh
./scripts/setup-nat.sh
```

### 5) Install and start systemd service

```bash
sudo cp /opt/firecracker-playground/deploy/systemd/fc-backend.service /etc/systemd/system/fc-backend.service
sudo systemctl daemon-reload
sudo systemctl enable --now fc-backend.service
sudo systemctl status fc-backend.service --no-pager -l
```

### 6) Install nginx config

```bash
sudo cp /opt/firecracker-playground/deploy/nginx/firecracker.conf /etc/nginx/sites-available/firecracker.conf
sudo ln -sf /etc/nginx/sites-available/firecracker.conf /etc/nginx/sites-enabled/firecracker.conf
sudo nginx -t
sudo systemctl reload nginx
```

## API

### Create session

`POST /api/session`

Optional required header (if configured):
- `X-API-Token: <token>`

Example:

```bash
curl -sS -X POST http://127.0.0.1/api/session \
  -H 'X-API-Token: change-me'
```

Response:

```json
{"token":"<32-hex>","ttl_sec":900}
```

Open terminal in browser:

```text
http://<host>/t/<token>/
```

## Optional Docker development mode

Docker mode is not the primary production path because backend needs host networking and Firecracker control.

```bash
docker build -t firecracker-playground .
docker run --rm -it -p 8080:8080 firecracker-playground
```

## Troubleshooting

### nginx proxies incorrectly

```bash
curl -i http://127.0.0.1/
sudo nginx -T | sed -n '1,200p'
```

### backend port in use

```bash
sudo ss -lntp | grep 8080
sudo systemctl status fc-backend.service --no-pager -l
```

### backend logs

```bash
sudo journalctl -u fc-backend.service -n 200 --no-pager
```

### Cleanup host network

```bash
cd /opt/firecracker-playground
./scripts/cleanup-network.sh
```

## Do not commit

- Rootfs and kernel images
- Private keys
- Runtime VM directories
