
import express from "express";
import axios from "axios";
import { URL } from "url";
import dns from "dns/promises";
import { gunzipSync } from "zlib";

const app = express();
app.use(express.json());
app.use(express.text({ type: "*/*" })); // obsługa surowego body

// Lista losowych User-Agentów
const userAgents = [
  // Ogólne przeglądarki
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/129.0",

  // Klienci API i boty AI
  "OpenAI-API/1.0 (ChatGPT/5.0)",
  "Anthropic-AI/1.0 (Claude/3.5)",
  "Google-LLM/1.0 (Gemini/2.0)",
  "PerplexityBot/1.3 (+https://www.perplexity.ai)",
  "Copilot/1.0 (GitHub; Microsoft AI Assistant)",
  "DuckAssist/1.0 (+https://duckduckgo.com/assist)",
  "YouChat/2.0 (+https://you.com/)",
  "MistralAI/1.0 (+https://mistral.ai)",
  "HuggingFace-Transformers/4.43 (InferenceAPI)",
  "LLaMA-Agent/1.0 (Meta AI)",
  "Cohere-CommandR/1.0 (+https://cohere.ai)",
  "ChatGPTBot/1.0 (+https://chat.openai.com)",

  // Inne boty indeksujące i testowe
  "Googlebot/2.1 (+http://www.google.com/bot.html)",
  "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
  "DuckDuckBot/1.1 (+http://duckduckgo.com/duckduckbot.html)",
  "GPTBot/1.0 (+https://openai.com/gptbot)",
  "ClaudeBot/1.0 (+https://www.anthropic.com/bot)",
  "FacebookBot/1.0 (+https://www.facebook.com/externalhit_uatext.php)",
  "TwitterBot/1.0 (+https://developer.twitter.com/en/docs/twitter-for-websites)",
  "Applebot/0.1 (+http://www.apple.com/go/applebot)",
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
  const headers = { "User-Agent": userAgents[Math.floor(Math.random() * userAgents.length)] };
  for (const [key, value] of Object.entries(req.headers)) {
    if (!["host", "connection", "content-length", "user-agent"].includes(key.toLowerCase())) {
      headers[key] = value;
    }
  }

  try {
    const axiosConfig = {
      method: req.method,
      url: targetUrl,
      headers,
      data: ["POST", "PUT", "PATCH"].includes(req.method) ? req.body : undefined,
      responseType: "arraybuffer", // pobierz surowe dane
      maxRedirects: 0, // nie podążaj za redirectami
      validateStatus: () => true, // nie rzucaj dla kodów 4xx/5xx
    };

    const response = await axios(axiosConfig);

    const buf = Buffer.from(response.data);
    let contentType = response.headers["content-type"] || "text/plain";
    let responseData;

    // Obsługa responseType
    if (responseType === "json") {
      if (buf[0] === 0x1f && buf[1] === 0x8b) { // gzip magic number
        try {
          responseData = gunzipSync(buf).toString("utf-8");
          contentType = "application/json; charset=utf-8";
        } catch {
          responseData = buf.toString("base64");
          contentType = "application/octet-stream";
        }
      } else {
        responseData = buf.toString("utf-8");
        contentType = "application/json; charset=utf-8";
      }
    } else if (responseType === "html") {
      responseData = buf.toString("utf-8");
      contentType = "text/html; charset=utf-8";
    } else if (responseType === "text") {
      responseData = buf.toString("utf-8");
      contentType = "text/plain; charset=utf-8";
    } else {
      // auto
      if (contentType.startsWith("image/") || contentType.startsWith("application/pdf")) {
        responseData = buf.toString("base64");
      } else if (contentType.startsWith("application/octet-stream")) {
        responseData = buf.toString("base64");
      } else if (buf.includes(Buffer.from("<html")) || buf.includes(Buffer.from("<!DOCTYPE"))) {
        responseData = buf.toString("utf-8");
        contentType = "text/html; charset=utf-8";
      } else {
        responseData = buf.toString("utf-8");
      }
    }

    const statusCode = response.status === 301 ? 200 : response.status;

    res.status(statusCode).json({
      status: statusCode,
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
