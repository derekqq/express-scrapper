import express from "express";
import fetch from "node-fetch";
import { URL } from "url";
import dns from "dns/promises";
import { gunzipSync } from "zlib";

const app = express();
app.use(express.json());
app.use(express.text({ type: "*/*" })); // obsługa surowego body

// Lista losowych User-Agentów
const userAgents = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
  "OpenAI-Client/1.0 (+https://openai.com/)",
  "curl/8.4.0",
];

// Funkcja sprawdzająca, czy IP jest prywatne
function isPrivateIp(ip) {
  const octets = ip.split(".").map(Number);
  if (octets.length !== 4 || octets.some(isNaN)) return true;

  const [a, b] = octets;
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127
  );
}

// Proxy endpoint
app.all("/proxy", async (req, res) => {
  const targetUrl = req.query.url;
  const responseType = req.query.responseType || "auto";

  if (!targetUrl) {
    return res.status(400).json({ status: 400, error: "Missing 'url' parameter." });
  }

  let url;
  try {
    url = new URL(targetUrl);
    if (!["http:", "https:"].includes(url.protocol)) throw new Error();
  } catch {
    return res.status(400).json({ status: 400, error: "Invalid URL." });
  }

  // Blokada prywatnych IP
  try {
    const ips = await dns.lookup(url.hostname, { all: true });
    if (ips.some(ipObj => isPrivateIp(ipObj.address))) {
      return res.status(403).json({ status: 403, error: "Blocked private or local IP." });
    }
  } catch {
    return res.status(403).json({ status: 403, error: "Blocked private or local IP." });
  }

  // Nagłówki
  const headers = {};
  headers["User-Agent"] = userAgents[Math.floor(Math.random() * userAgents.length)];
  for (const [key, value] of Object.entries(req.headers)) {
    if (!["host", "connection", "content-length", "user-agent"].includes(key.toLowerCase())) {
      headers[key] = value;
    }
  }

  // Body
  let body;
  if (["POST", "PUT", "PATCH"].includes(req.method)) {
    body = req.body;
  }

  try {
    const response = await fetch(targetUrl, {
      method: req.method,
      headers,
      body: body && typeof body === "string" ? body : undefined,
      redirect: "manual", // nie podążaj za redirectami
    });

    let data = await response.arrayBuffer();
    const contentType = response.headers.get("content-type") || "text/plain";

    let responseData;

    // Obsługa gzip
    const buf = Buffer.from(data);
    if (responseType === "json" && buf[0] === 0x1f && buf[1] === 0x8b) {
      try {
        responseData = gunzipSync(buf).toString("utf-8");
      } catch {
        responseData = buf.toString("base64");
      }
    } else if (responseType === "json") {
      responseData = buf.toString("utf-8");
    } else if (responseType === "html") {
      responseData = buf.toString("utf-8");
    } else if (responseType === "text") {
      responseData = buf.toString("utf-8");
    } else {
      // auto
      if (contentType.startsWith("image/") || contentType.startsWith("application/pdf")) {
        responseData = buf.toString("base64");
      } else {
        responseData = buf.toString("utf-8");
      }
    }

    // Zwróć JSON
    res.status(response.status === 301 ? 200 : response.status).json({
      status: response.status === 301 ? 200 : response.status,
      contentType,
      data: responseData,
    });
  } catch (err) {
    res.status(502).json({ status: 502, error: "Error fetching target URL." });
  }
});

app.listen(3000, () => {
  console.log("Proxy server running on http://localhost:3000");
});
