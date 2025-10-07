// index.ts
import express from 'express';
import dns from 'dns/promises';
import { pipeline } from 'stream';
import { promisify } from 'util';
import net from 'net';

const streamPipeline = promisify(pipeline);
const app = express();
const PORT = process.env.PORT || 3000;

// ---- User-Agent list ----
const userAgents = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 Safari/16.6",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
  "OpenAI-Client/1.0 (+https://openai.com/)",
  "curl/8.4.0"
];

// ---- Hop-by-hop headers ----
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'transfer-encoding',
  'upgrade',
  'host'
]);

// ---- Helper: private IPs ----
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return true;
  const n = ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
  if ((n & 0xff000000) === 0x0a000000) return true;          // 10.0.0.0/8
  if ((n & 0xfff00000) === 0xac100000) return true;          // 172.16.0.0/12
  if ((n & 0xffff0000) === 0xc0a80000) return true;          // 192.168.0.0/16
  if ((n & 0xff000000) === 0x7f000000) return true;          // 127.0.0.0/8
  if ((n & 0xffff0000) === 0xa9fe0000) return true;          // 169.254.0.0/16
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  if (ip === '::1') return true;
  if (ip.startsWith('fe80') || ip.startsWith('FE80')) return true;
  if (ip.startsWith('fc') || ip.startsWith('FC') || ip.startsWith('fd') || ip.startsWith('FD')) return true;
  if (ip.startsWith('::ffff:')) {
    const v4 = ip.split(':').pop();
    if (v4 && net.isIP(v4) === 4) return isPrivateIPv4(v4);
  }
  return false;
}

async function isPrivateAddress(host: string): Promise<boolean> {
  try {
    const answers = await dns.lookup(host, { all: true });
    for (const a of answers) {
      if (a.family === 4 && isPrivateIPv4(a.address)) return true;
      if (a.family === 6 && isPrivateIPv6(a.address)) return true;
    }
    return false;
  } catch {
    return true; // DNS error -> treat as unsafe
  }
}

// ---- Helper: build headers ----
function buildForwardHeaders(req: express.Request, chosenUA: string) {
  const out: Record<string,string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (HOP_BY_HOP.has(k.toLowerCase())) continue;
    if (typeof v === 'string') out[k] = v;
    else if (Array.isArray(v)) out[k] = v.join(', ');
  }
  out['user-agent'] = chosenUA;
  return out;
}

// ---- Proxy endpoint ----
app.all('/proxy', express.raw({ type: '*/*', limit: '10mb' }), async (req, res) => {
  const target = req.query.url as string;
  if (!target) return res.status(400).send("Missing 'url' query parameter.");

  let parsed: URL;
  try { parsed = new URL(target); } 
  catch { return res.status(400).send("Invalid URL."); }
  if (!['http:', 'https:'].includes(parsed.protocol)) return res.status(400).send("Only http/https allowed.");

  const blocked = await isPrivateAddress(parsed.hostname);
  if (blocked) return res.status(403).send("Blocked private or local IP.");

  const chosenUA = userAgents[Math.floor(Math.random() * userAgents.length)];
  const headers = buildForwardHeaders(req, chosenUA);

  let body: BodyInit | undefined;
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.body && (req.body as Buffer).length > 0) {
    body = req.body as Buffer;
  }

  const controller = new AbortController();
  const FETCH_TIMEOUT_MS = 30_000;
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const fetchOptions: RequestInit = {
      method: req.method,
      headers,
      body,
      redirect: 'follow',
      signal: controller.signal
    };
    const upstreamResp = await fetch(target, fetchOptions);
    clearTimeout(timeout);

    res.status(upstreamResp.status);
    upstreamResp.headers.forEach((val, name) => {
      if (!HOP_BY_HOP.has(name.toLowerCase())) res.setHeader(name, val);
    });

    if (upstreamResp.body) await streamPipeline(upstreamResp.body, res);
    else res.send(await upstreamResp.text());
  } catch (err: any) {
    clearTimeout(timeout);
    if (err.name === 'AbortError') return res.status(504).send('Upstream request timed out.');
    return res.status(502).send('Error fetching target URL.');
  }
});

app.get('/', (req, res) => res.type('text/plain').send('Node proxy. Use /proxy?url=...'));
app.listen(PORT, () => console.log(`Proxy running on http://localhost:${PORT}`));
