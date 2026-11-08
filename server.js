'use strict';
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const dns = require('dns').promises;

const PORT = Number(process.env.PORT) || 8080;
const USER = "amir";
const PASS = "amirsssssssssdsdddddddssjnwjejdduhdbdusbsbdhdhddju93837";
const ALLOWED_PORTS = new Set(
  (process.env.ALLOWED_PORTS || '443').split(',').map(Number)
);
const IDLE_MS = 5 * 60 * 1000;

if (!USER || !PASS) {
  console.error('PROXY_USER and PROXY_PASS are required');
  process.exit(1);
}

const sha = (s) => crypto.createHash('sha256').update(s).digest();
const EXPECTED = sha('Basic ' + Buffer.from(`${USER}:${PASS}`).toString('base64'));
const authOk = (h) => typeof h === 'string' && crypto.timingSafeEqual(sha(h), EXPECTED);

// Blocks loopback, RFC1918, CGNAT, link-local and IPv6 ULA (covers Railway's private network)
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  const l = ip.toLowerCase();
  if (l.startsWith('::ffff:') && l.includes('.')) return isPrivate(l.slice(7));
  return l === '::' || l === '::1' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80');
}

// Anything that is not CONNECT is rejected
const server = http.createServer((req, res) => {
  res.writeHead(405, { Allow: 'CONNECT', Connection: 'close' });
  res.end('CONNECT only\n');
});

server.on('connect', async (req, client, head) => {
  client.on('error', () => {});
  const fail = (code, msg, extra = '') =>
    client.end(`HTTP/1.1 ${code} ${msg}\r\n${extra}Connection: close\r\n\r\n`);

  if (!authOk(req.headers['proxy-authorization'])) {
    return fail(407, 'Proxy Authentication Required', 'Proxy-Authenticate: Basic realm="proxy"\r\n');
  }

  const m = /^(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})$/.exec(req.url);
  if (!m) return fail(400, 'Bad Request');
  const host = m[1] || m[2];
  const port = Number(m[3]);
  if (!ALLOWED_PORTS.has(port)) return fail(403, 'Forbidden');

  let ip;
  try {
    ip = net.isIP(host) ? host : (await dns.lookup(host)).address;
  } catch {
    return fail(502, 'Bad Gateway');
  }
  if (isPrivate(ip)) return fail(403, 'Forbidden');

  let connected = false;
  const upstream = net.connect({ host: ip, port }, () => {
    connected = true;
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) upstream.write(head);
    upstream.pipe(client);
    client.pipe(upstream);
  });

  const close = () => { upstream.destroy(); client.destroy(); };
  upstream.on('error', () => (connected ? close() : fail(502, 'Bad Gateway')));
  upstream.on('close', close);
  client.on('close', close);
  upstream.setTimeout(IDLE_MS, close);
  client.setTimeout(IDLE_MS, close);
});

server.listen(PORT, '::', () => console.log(`CONNECT proxy listening on :${PORT}`));
