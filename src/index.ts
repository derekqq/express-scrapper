// index.ts
import express from 'express';
import dns from 'dns/promises';
import { pipeline } from 'stream';
import { promisify } from 'util';
import net from 'net';

const streamPipeline = promisify(pipeline);
const app = express();
const PORT = process.env.PORT || 3000;

const userAgents = [
  "Mozilla/5.0",
  "OpenAI-Client/1.0",
  "curl/8.4.0"
];

const HOP_BY_HOP = new Set([
  'connection','keep-alive','proxy-authenticate','proxy-authorization',
  'te','trailers','transfer-encoding','upgrade','host'
]);

function isPrivateIPv4(ip: string): boolean { /*...zostaje bez zmian...*/ return false; }
function isPrivateIPv6(ip: string): boolean { return false; }

async function isPrivateAddress(host: string): Promise<boolean> { return false; }

function buildForwardHeaders(req: express.Request, chosenUA: string) {
  const out: Record<string,string> = {};
  for (const [k,v] of Object.entries(req.headers)) {
    if (HOP_BY_HOP.has(k.toLowerCase())) continue;
    if (typeof v === 'string') out[k] = v;
    else if (Array.isArray(v)) out[k] = v.join(', ');
  }
  out['user-agent'] = chosenUA;
  return out;
}

// ---- PROXY endpoint ----
app.all('/proxy', express.raw({ type: '*/*', limit: '10mb' }), async (req, res) => {
  const target = req.query.url as string;
  if (!target) return res.status(400).send("Missing 'url' query parameter.");

  let parsed: URL;
  try { parsed = new URL(target); } catch { return res.status(400).send("Invalid URL."); }

  const blocked = await isPrivateAddress(parsed.hostname);
  if (blocked) return res.status(403).send("Blocked private IP.");

  const chosenUA = userAgents[Math.floor(Math.random() * userAgents.length)];
  const headers = buildForwardHeaders(req, chosenUA);

  // <- tu rozwiązanie "any" dla fetchOptions
  const fetchOptions: any = {
    method: req.method,
    headers,
    redirect: 'follow',
  };

  // body tylko dla metod które go mają
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.body && (req.body as Buffer).length > 0) {
    fetchOptions.body = req.body;
  }

  // Node 18+ ma global AbortController
  const controller = new AbortController();
  fetchOptions.signal = controller.signal;
  const FETCH_TIMEOUT_MS = 30_000;
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
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
    if (err.name === 'AbortError') return res.status(504).send('Upstream timeout.');
    return res.status(502).send('Error fetching target URL.');
  }
});

app.get('/', (req,res)=>res.send('Node proxy. Use /proxy?url=...'));
app.listen(PORT, ()=>console.log(`Proxy running on http://localhost:${PORT}`));
