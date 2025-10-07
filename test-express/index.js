// proxy.js
// Prosty serwerowy proxy w Node.js (Express + fetch wbudowany w Node 18+)
// Funkcje:
// - odbiera ?url=...
// - waliduje URL
// - resolver DNS i blokada prywatnych IP (podstawowe SSRF protection)
// - losowy User-Agent
// - forward metod i body (GET/POST/PUT/PATCH/DELETE etc.)
// - przekazywanie nagłówków (z pominięciem hop-by-hop)
// - streamowanie odpowiedzi do klienta

const express = require('express');
const dns = require('dns').promises;
const { pipeline } = require('stream');
const { promisify } = require('util');
const streamPipeline = promisify(pipeline);
const net = require('net');

const app = express();
const PORT = process.env.PORT || 3000;

// Rozszerzona lista User-Agentów (możesz dopisać/zmodyfikować)
const userAgents = [
  // Desktop
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
  // Mobile
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile Safari/604.1",
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
  // Bots/crawlers
  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
  // OpenAI / SDK-like examples (przykładowe)
  "OpenAI-Client/1.0 (+https://openai.com/)",
  "OpenAI-Node/3.2.1 (https://github.com/openai/openai-node)",
  "OpenAI-Python/1.0 (github.com/openai/openai-python)",
  // CLI/tools
  "curl/8.4.0",
  "Wget/1.21.3 (linux-gnu)",
  "python-requests/2.31.0",
  "Go-http-client/1.1",
  // misc
  "Discordbot/2.0 (+https://discordapp.com)",
  "Slack-ImgProxy/1.0 (+https://slack.com/)",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
];

// Hop-by-hop headers które NIE powinny być forwardowane
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

// Sprawdza czy IPv4 należy do prywatnego zakresu
function isPrivateIPv4(ip) {
  // convert dotted to number
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return true;
  const n = ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];

  // ranges:
  // 10.0.0.0/8
  if ((n & 0xff000000) === 0x0a000000) return true;
  // 172.16.0.0/12
  if ((n & 0xfff00000) === 0xac100000) return true;
  // 192.168.0.0/16
  if ((n & 0xffff0000) === 0xc0a80000) return true;
  // 127.0.0.0/8 loopback
  if ((n & 0xff000000) === 0x7f000000) return true;
  // 169.254.0.0/16 link-local
  if ((n & 0xffff0000) === 0xa9fe0000) return true;
  return false;
}

// Sprawdza czy IPv6 jest prywatne/link-local/loopback
function isPrivateIPv6(ip) {
  // loopback ::1
  if (ip === '::1') return true;
  // link-local fe80::/10
  if (ip.startsWith('fe80') || ip.startsWith('FE80')) return true;
  // unique local fc00::/7
  if (ip.startsWith('fc') || ip.startsWith('FC') || ip.startsWith('fd') || ip.startsWith('FD')) return true;
  // IPv4 mapped ::ffff:a.b.c.d -> check mapped IPv4
  if (ip.startsWith('::ffff:')) {
    const v4 = ip.split(':').pop();
    if (net.isIP(v4) === 4) return isPrivateIPv4(v4);
  }
  // broadly block other non-global addresses that are not explicitly public:
  // (this is conservative; adjust if you need)
  // we won't attempt to enumerate all special ranges here
  return false;
}

async function isPrivateAddress(host) {
  try {
    // resolve all addresses (IPv4 + IPv6)
    const answers = await dns.lookup(host, { all: true });
    if (!answers || answers.length === 0) return true;
    for (const a of answers) {
      if (a.family === 4) {
        if (isPrivateIPv4(a.address)) return true;
      } else if (a.family === 6) {
        if (isPrivateIPv6(a.address)) return true;
      } else {
        return true;
      }
    }
    return false;
  } catch (err) {
    // błąd DNS -> traktujemy jako niebezpieczne / nieosiągalne
    return true;
  }
}

// pomoc: kopiuje nagłówki z req do fetch, pomijając hop-by-hop i host
function buildForwardHeaders(req, chosenUA) {
  const out = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const lname = k.toLowerCase();
    if (HOP_BY_HOP.has(lname)) continue;
    // Nie forwardujemy accept-encoding by uniknąć rozbieżności kompresji (opcjonalne)
    // Możesz odkomentować jeśli chcesz forwardować encoding:
    // if (lname === 'accept-encoding') continue;
    out[k] = v;
  }
  // Nadpisz User-Agent losowym UA
  out['user-agent'] = chosenUA;
  return out;
}

// Endpoint proxy
app.all('/proxy', express.raw({ type: '*/*', limit: '10mb' }), async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing 'url' query parameter.");

  // Walidacja URL
  let parsed;
  try {
    parsed = new URL(target);
  } catch (err) {
    return res.status(400).send('Invalid URL.');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).send('Only http and https are allowed.');
  }

  // SSRF: resolve host and block private IP ranges
  const host = parsed.hostname;
  const blocked = await isPrivateAddress(host);
  if (blocked) return res.status(403).send('Blocked private or local IP.');

  // Wybierz losowy UA
  const chosenUA = userAgents[Math.floor(Math.random() * userAgents.length)];

  // Zbuduj nagłówki do forwardowania
  const forwardHeaders = buildForwardHeaders(req, chosenUA);

  // Przygotuj opcje dla fetch
  const fetchOptions = {
    method: req.method,
    headers: forwardHeaders,
    // domyślnie fetch w Node 18+ followuje redirecty do pewnego limitu
    // body: jeśli metoda ma body, ustawimy poniżej
    redirect: 'follow',
  };

  // Jeśli request ma body (POST/PUT/PATCH), ustaw body. Express.raw() wczytuje ciało jako Buffer.
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.body && req.body.length !== 0) {
    fetchOptions.body = req.body;
  }

  // Timeout (opcjonalnie) — tu proste podejście z AbortController
  const AbortController = globalThis.AbortController || (await import('abort-controller')).default;
  const controller = new AbortController();
  fetchOptions.signal = controller.signal;
  const FETCH_TIMEOUT_MS = 30_000;
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  let upstreamResp;
  try {
    upstreamResp = await fetch(target, fetchOptions);
  } catch (err) {
    clearTimeout(timeout);
    if (err.name === 'AbortError') return res.status(504).send('Upstream request timed out.');
    return res.status(502).send('Error fetching target URL: ' + String(err.message || err));
  }
  clearTimeout(timeout);

  // Przekazanie statusu
  res.status(upstreamResp.status);

  // Kopiuj nagłówki z upstream, pomijając hop-by-hop
  upstreamResp.headers.forEach((value, name) => {
    if (HOP_BY_HOP.has(name.toLowerCase())) return;
    // Nie pozwól nadpisać headerów ustawionych przez Express (np. transfer-encoding)
    res.setHeader(name, value);
  });

  // Streamuj ciało odpowiedzi do klienta
  try {
    if (!upstreamResp.body) {
      // brak body - odczytaj tekst i wyślij
      const txt = await upstreamResp.text();
      res.send(txt);
    } else {
      await streamPipeline(upstreamResp.body, res);
    }
  } catch (err) {
    // Jeżeli streaming przerwany
    if (!res.headersSent) res.status(500).send('Error streaming response.');
    else res.end();
  }
});

// Prosty home
app.get('/', (req, res) => {
  res.type('text/plain').send('Node proxy. Use /proxy?url=...');
});

app.listen(PORT, () => {
  console.log(`Proxy listening on http://localhost:${PORT} — usage: /proxy?url=...`);
});
