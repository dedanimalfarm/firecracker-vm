const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { spawn } = require('child_process');
const fs = require('fs');
const httpProxy = require('http-proxy');

function env(name, fallback) {
  const value = process.env[name];
  return value === undefined || value === '' ? fallback : value;
}

function envInt(name, fallback) {
  const value = Number.parseInt(env(name, String(fallback)), 10);
  if (Number.isNaN(value)) {
    throw new Error(`Invalid integer env "${name}"`);
  }
  return value;
}

const PORT = envInt('PORT', 8080);
const MAX_SESSIONS = envInt('MAX_SESSIONS', 20);
const TTL_MS = envInt('TTL_MS', 900000);

const BRIDGE_NAME = env('BRIDGE_NAME', 'fcbr0');
const HOST_GW = env('HOST_GW', '172.16.0.1');
const IP_PREFIX = env('IP_PREFIX', '172.16.0.');
const IP_START = envInt('IP_START', 20);
const IP_MAX = envInt('IP_MAX', 250);

const VM_DIR = env('VM_DIR', '/srv/firecracker/vms');
const KERNEL_PATH = env('KERNEL_PATH', '/srv/firecracker/images/vmlinux.bin');
const BASE_ROOTFS_PATH = env('BASE_ROOTFS_PATH', '/srv/firecracker/images/bionic.rootfs.ext4');
const SSH_KEY_PATH = env('SSH_KEY_PATH', '/srv/firecracker/keys/microvm_ed25519');

const FIRECRACKER_BIN = env('FIRECRACKER_BIN', '/usr/local/bin/firecracker');
const TTYD_BIN = env('TTYD_BIN', '/usr/local/bin/ttyd');

const API_TOKEN = env('API_TOKEN', '');
const RATE_LIMIT_WINDOW_MS = envInt('RATE_LIMIT_WINDOW_MS', 60000);
const RATE_LIMIT_MAX = envInt('RATE_LIMIT_MAX', 10);

if (IP_START < 1 || IP_START > 254 || IP_MAX < 1 || IP_MAX > 254 || IP_START > IP_MAX) {
  throw new Error('Invalid IP allocation range. Check IP_START and IP_MAX.');
}

if (RATE_LIMIT_WINDOW_MS < 1 || RATE_LIMIT_MAX < 1) {
  throw new Error('Invalid rate limit settings. Check RATE_LIMIT_WINDOW_MS and RATE_LIMIT_MAX.');
}

const sessions = new Map(); // token -> session
const createRateByIp = new Map(); // ip -> { count, windowStart }
let nextIp = IP_START;

function allocToken() {
  return crypto.randomBytes(16).toString('hex');
}

function allocIp() {
  for (let i = 0; i < (IP_MAX - IP_START + 1); i += 1) {
    const ip = `${IP_PREFIX}${nextIp}`;
    nextIp += 1;
    if (nextIp > IP_MAX) {
      nextIp = IP_START;
    }

    let used = false;
    for (const session of sessions.values()) {
      if (session.ip === ip) {
        used = true;
        break;
      }
    }

    if (!used) {
      return ip;
    }
  }

  throw new Error('No free IPs');
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const address = srv.address();
      const port = typeof address === 'object' && address ? address.port : null;
      srv.close(() => {
        if (!port) {
          reject(new Error('Unable to allocate local port'));
          return;
        }
        resolve(port);
      });
    });
    srv.on('error', reject);
  });
}

function sh(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const processHandle = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], ...opts });
    let out = '';
    let err = '';

    processHandle.stdout.on('data', (chunk) => {
      out += chunk.toString();
    });
    processHandle.stderr.on('data', (chunk) => {
      err += chunk.toString();
    });

    processHandle.on('close', (code) => {
      if (code === 0) {
        resolve({ out, err });
        return;
      }
      reject(new Error(`${cmd} ${args.join(' ')} failed (${code}): ${err || out}`));
    });
  });
}

function fcReq(sockPath, method, path, bodyObj) {
  return new Promise((resolve, reject) => {
    const body = bodyObj ? Buffer.from(JSON.stringify(bodyObj)) : Buffer.alloc(0);
    const req = http.request({
      socketPath: sockPath,
      path,
      method,
      headers: {
        Host: 'localhost',
        'Content-Type': 'application/json',
        'Content-Length': body.length,
      },
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk.toString();
      });
      res.on('end', () => {
        if (res.statusCode === 200 || res.statusCode === 204) {
          resolve({ status: res.statusCode, data });
          return;
        }
        reject(new Error(`Firecracker API ${method} ${path} -> ${res.statusCode}: ${data}`));
      });
    });

    req.on('error', reject);
    if (body.length > 0) {
      req.write(body);
    }
    req.end();
  });
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0].trim();
  }
  if (Array.isArray(xff) && xff.length > 0) {
    return xff[0].split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function requireToken(req, res) {
  if (!API_TOKEN) {
    return true;
  }

  const header = req.headers['x-api-token'];
  if (typeof header === 'string' && header === API_TOKEN) {
    return true;
  }
  if (Array.isArray(header) && header.includes(API_TOKEN)) {
    return true;
  }

  res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('forbidden');
  return false;
}

function enforceRateLimit(req, res) {
  const ip = getClientIp(req);
  const now = Date.now();
  const rate = createRateByIp.get(ip);

  if (!rate || now - rate.windowStart >= RATE_LIMIT_WINDOW_MS) {
    createRateByIp.set(ip, { count: 1, windowStart: now });
    return true;
  }

  if (rate.count >= RATE_LIMIT_MAX) {
    const retryAfterSec = Math.max(
      1,
      Math.ceil((RATE_LIMIT_WINDOW_MS - (now - rate.windowStart)) / 1000),
    );
    res.writeHead(429, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Retry-After': String(retryAfterSec),
    });
    res.end('rate limit exceeded');
    return false;
  }

  rate.count += 1;
  return true;
}

async function createSession() {
  if (sessions.size >= MAX_SESSIONS) {
    throw new Error('Too many sessions');
  }

  const token = allocToken();
  const id = token.slice(0, 8);
  const ip = allocIp();
  const tap = `tap${id}`;
  const vmDir = `${VM_DIR}/${token}`;
  const rootfs = `${vmDir}/rootfs.ext4`;
  const sock = `${vmDir}/firecracker.socket`;

  let firecracker = null;
  let ttyd = null;

  try {
    await sh('mkdir', ['-p', vmDir]);
    await sh('cp', [BASE_ROOTFS_PATH, rootfs]);

    await sh('ip', ['tuntap', 'add', 'dev', tap, 'mode', 'tap']);
    await sh('ip', ['link', 'set', tap, 'master', BRIDGE_NAME]);
    await sh('ip', ['link', 'set', tap, 'up']);

    firecracker = spawn(FIRECRACKER_BIN, ['--api-sock', sock], { stdio: ['ignore', 'pipe', 'pipe'] });

    for (let i = 0; i < 50; i += 1) {
      if (fs.existsSync(sock)) {
        break;
      }
      // Wait until Firecracker API socket becomes available.
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve) => setTimeout(resolve, 50));
    }

    if (!fs.existsSync(sock)) {
      throw new Error('Firecracker socket not created');
    }

    const bootArgs = `console=ttyS0 reboot=k panic=1 pci=off ip=${ip}::${HOST_GW}:255.255.255.0::eth0:off`;

    await fcReq(sock, 'PUT', '/boot-source', {
      kernel_image_path: KERNEL_PATH,
      boot_args: bootArgs,
    });

    await fcReq(sock, 'PUT', '/drives/rootfs', {
      drive_id: 'rootfs',
      path_on_host: rootfs,
      is_root_device: true,
      is_read_only: false,
    });

    await fcReq(sock, 'PUT', '/network-interfaces/eth0', {
      iface_id: 'eth0',
      guest_mac: `AA:FC:${id.slice(0, 2)}:${id.slice(2, 4)}:${id.slice(4, 6)}:${id.slice(6, 8)}`,
      host_dev_name: tap,
    });

    await fcReq(sock, 'PUT', '/actions', { action_type: 'InstanceStart' });

    const port = await getFreePort();
    const ttydArgs = [
      '--writable',
      '-p', String(port),
      '-i', '127.0.0.1',
      'ssh',
      '-i', SSH_KEY_PATH,
      '-o', 'StrictHostKeyChecking=no',
      '-o', 'UserKnownHostsFile=/dev/null',
      '-o', 'LogLevel=ERROR',
      `root@${ip}`,
    ];
    ttyd = spawn(TTYD_BIN, ttydArgs, { stdio: ['ignore', 'pipe', 'pipe'] });

    const session = {
      token,
      id,
      ip,
      tap,
      vmDir,
      rootfs,
      sock,
      port,
      fcPid: firecracker.pid,
      ttydPid: ttyd.pid,
      expiresAt: Date.now() + TTL_MS,
    };
    sessions.set(token, session);

    setTimeout(() => {
      cleanupSession(token).catch(() => {});
    }, TTL_MS + 2000);

    return session;
  } catch (err) {
    if (ttyd && ttyd.pid) {
      try {
        process.kill(ttyd.pid, 'SIGKILL');
      } catch {}
    }
    if (firecracker && firecracker.pid) {
      try {
        process.kill(firecracker.pid, 'SIGKILL');
      } catch {}
    }
    try {
      await sh('ip', ['link', 'del', tap]);
    } catch {}
    try {
      await sh('rm', ['-rf', vmDir]);
    } catch {}
    throw err;
  }
}

async function cleanupSession(token) {
  const session = sessions.get(token);
  if (!session) {
    return;
  }

  sessions.delete(token);

  try {
    process.kill(session.ttydPid, 'SIGKILL');
  } catch {}

  try {
    process.kill(session.fcPid, 'SIGKILL');
  } catch {}

  try {
    await sh('ip', ['link', 'del', session.tap]);
  } catch {}

  try {
    await sh('rm', ['-rf', session.vmDir]);
  } catch {}
}

function htmlIndex() {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Firecracker Playground</title>
  <style>
    body { font-family: sans-serif; margin: 16px; }
    #controls { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; }
    #apiToken { width: 260px; }
    #frame { width: 100%; height: 80vh; border: 1px solid #333; }
  </style>
</head>
<body>
  <h3>Firecracker playground</h3>
  <div id="controls">
    <input id="apiToken" type="password" placeholder="X-API-Token (optional)">
    <button id="btn">Start session</button>
  </div>
  <iframe id="frame"></iframe>
  <script>
    document.getElementById('btn').onclick = async () => {
      const token = document.getElementById('apiToken').value.trim();
      const headers = {};
      if (token) headers['X-API-Token'] = token;

      const response = await fetch('/api/session', { method: 'POST', headers });
      if (!response.ok) {
        alert('failed: ' + (await response.text()));
        return;
      }
      const payload = await response.json();
      document.getElementById('frame').src = '/t/' + payload.token + '/';
    };
  </script>
</body>
</html>`;
}

function getSessFromUrl(url) {
  const match = url.match(/^\/t\/([a-f0-9]{32})(\/.*)?$/);
  if (!match) {
    return null;
  }

  const token = match[1];
  const rest = match[2] || '/';
  const session = sessions.get(token);
  if (!session) {
    return null;
  }

  return { session, rest };
}

const proxy = httpProxy.createProxyServer({ ws: true });

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(htmlIndex());
    return;
  }

  if (req.method === 'POST' && req.url === '/api/session') {
    if (!enforceRateLimit(req, res)) {
      return;
    }

    if (!requireToken(req, res)) {
      return;
    }

    try {
      const session = await createSession();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ token: session.token, ttl_sec: Math.floor(TTL_MS / 1000) }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(String(err.message || err));
    }
    return;
  }

  const proxied = getSessFromUrl(req.url || '');
  if (proxied) {
    req.url = proxied.rest;
    proxy.web(req, res, { target: `http://127.0.0.1:${proxied.session.port}` }, (err) => {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`proxy error: ${err.message}`);
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('not found');
});

server.on('upgrade', (req, socket, head) => {
  const proxied = getSessFromUrl(req.url || '');
  if (!proxied) {
    socket.destroy();
    return;
  }

  req.url = proxied.rest;
  proxy.ws(req, socket, head, { target: `ws://127.0.0.1:${proxied.session.port}` });
});

async function shutdown() {
  const tokens = Array.from(sessions.keys());
  for (const token of tokens) {
    // eslint-disable-next-line no-await-in-loop
    await cleanupSession(token);
  }
}

process.on('SIGTERM', () => {
  shutdown().finally(() => process.exit(0));
});

process.on('SIGINT', () => {
  shutdown().finally(() => process.exit(0));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`backend on 127.0.0.1:${PORT}`);
});
