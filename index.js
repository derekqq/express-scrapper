import express from "express";
import axios from "axios";
import dns from "dns";
import net from "net";
import { promisify } from "util";

const app = express();
app.use(express.text({ type: "*/*" }));

// Asynchroniczna wersja dns.lookup
const lookup = promisify(dns.lookup);

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

// Sprawdzenie czy IP jest prywatne
function isPrivateIp(ip) {
  if (!net.isIP(ip)) return true; // odrzuć IPv6 i niepoprawne
  const parts = ip.split(".").map(Number);
  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
  );
}

app.all("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target) {
    return res.status(400).json({ status: 400, error: "Missing 'url' parameter." });
  }

  try {
    const url = new URL(target);
    if (!["http:", "https:"].includes(url.protocol)) {
      return res.status(400).json({ status: 400, error: "Only http/https allowed." });
    }

    const { address: ip } = await lookup(url.hostname, { family: 4 });
    if (isPrivateIp(ip)) {
      return res.status(403).json({ status: 403, error: "Blocked private or local IP." });
    }

    const ua = userAgents[Math.floor(Math.random() * userAgents.length)];

    const config = {
      method: req.method,
      url: target,
      headers: { "User-Agent": ua },
      responseType: "arraybuffer", // zawsze jako surowe bajty
      maxRedirects: 0,              // nie śledź przekierowań
      validateStatus: () => true    // pozwól zwrócić każdy kod
    };

    if (["POST", "PUT", "PATCH"].includes(req.method)) {
      config.data = req.body;
      if (req.headers["content-type"]) {
        config.headers["Content-Type"] = req.headers["content-type"];
      }
    }

    const response = await axios(config);

    // Zamień 301 -> 200
    const statusToReturn = response.status === 301 ? 200 : response.status;

    const contentType = response.headers["content-type"] || "application/octet-stream";
    let data;

    try {
      if (contentType.includes("application/json")) {
        // JSON jako tekst (zachowujemy strukturę)
        data = response.data.toString("utf8");
      } else if (contentType.startsWith("text/") || contentType.includes("html") || contentType.includes("xml")) {
        data = response.data.toString("utf8");
      } else {
        // inne typy binarne → base64
        data = response.data.toString("base64");
      }
    } catch {
      data = "[[unreadable response data]]";
    }

    res.status(statusToReturn).json({
      status: statusToReturn,
      contentType,
      data
    });

  } catch (err) {
    res.status(502).json({
      status: 502,
      error: "Error fetching target URL.",
      details: err.message
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Proxy listening at http://localhost:${PORT}/proxy?url=...`));

