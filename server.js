require("dotenv").config();
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bodyParser = require("body-parser");
const nacl = require("tweetnacl");
const fs = require("fs-extra");
const crypto = require("crypto");
const fetch = require("node-fetch");
const { Connection, clusterApiUrl, PublicKey } = require("@solana/web3.js");
const { Buffer } = require("buffer");

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = "./db.json";

let cachedSolUsd = null;
let lastFetchTime = 0;
const CACHE_DURATION_MS = 5 * 60 * 1000; // 5 minut

const TOKEN_PRICE_USD = (() => {
  const val = parseFloat(process.env.TOKEN_PRICE_USD);
  if (isNaN(val)) {
    console.warn("⚠️ Brak lub nieprawidłowa wartość TOKEN_PRICE_USD – używam domyślnej 0.0003");
    return 0.0003;
  }
  return val;
})();

const RECIPIENT = process.env.RECIPIENT;
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "").split(",");

app.use(cors({ origin: allowedOrigins }));
app.use(bodyParser.json());

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: { error: "Za dużo żądań, spróbuj ponownie później." },
  standardHeaders: true,
  legacyHeaders: false,
});

function readDB() {
  if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, "{}");
  return JSON.parse(fs.readFileSync(DB_PATH));
}

function writeDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

async function getSolToUsd() {
  const now = Date.now();
  if (cachedSolUsd && now - lastFetchTime < CACHE_DURATION_MS) {
    return cachedSolUsd;
  }
  try {
    const response = await fetch("https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd");
    const data = await response.json();
    const price = data.solana.usd;
    if (typeof price === "number" && price > 0) {
      cachedSolUsd = price;
      lastFetchTime = now;
      return price;
    }
  } catch (err) {
    console.warn("❌ Nie udało się pobrać kursu SOL/USD:", err.message);
  }
  return parseFloat(process.env.SOL_TO_USD || "150");
}

app.get("/nonce/:wallet", (req, res) => {
  const { wallet } = req.params;
  if (!wallet) return res.status(400).json({ error: "Brak portfela" });

  const db = readDB();
  const existing = db[`nonce_${wallet}`];
  const now = Date.now();

  if (existing && existing.expires > now) {
    return res.json({ nonce: existing.value });
  }

  const nonce = crypto.randomBytes(16).toString("hex");
  db[`nonce_${wallet}`] = { value: nonce, expires: now + 5 * 60 * 1000 };
  writeDB(db);

  res.json({ nonce });
});

app.post("/register", limiter, async (req, res) => {
  const origin = req.headers.origin || req.headers.referer;
  if (!allowedOrigins.some(o => origin && origin.startsWith(o))) {
    return res.status(403).json({ error: "Nieautoryzowane źródło żądania" });
  }

  const { signature, wallet, signedMessage, message } = req.body;
  if (!signature || !wallet || !signedMessage || !message) {
    return res.status(400).json({ error: "Brakuje wymaganych danych" });
  }

  const db = readDB();
  const nonceEntry = db[`nonce_${wallet}`];
  if (!nonceEntry || nonceEntry.expires < Date.now()) {
    return res.status(400).json({ error: "Nonce wygasł lub nie istnieje" });
  }

  const expectedNonce = nonceEntry.value;
  if (message !== expectedNonce) {
    return res.status(400).json({ error: "Nieprawidłowa wiadomość" });
  }

  try {
    const pubKey = new PublicKey(wallet);
    const decodedSignature = Uint8Array.from(Buffer.from(signedMessage, 'base64'));
    const messageBytes = new TextEncoder().encode(message);

    if (!nacl.sign.detached.verify(messageBytes, decodedSignature, pubKey.toBytes())) {
      return res.status(403).json({ error: "Nieprawidłowy podpis wiadomości" });
    }
  } catch (e) {
    return res.status(400).json({ error: "Błąd weryfikacji podpisu" });
  }

  if (db[signature]) {
    return res.status(400).json({ error: "Transakcja już zarejestrowana" });
  }

  for (const txId in db) {
    const rec = db[txId];
    if (typeof rec === "object" && rec.wallet === wallet) {
      const lastTxTime = new Date(rec.timestamp || 0).getTime();
      if (Date.now() - lastTxTime < 1 * 60 * 1000) {
        return res.status(429).json({ error: "Za częsta rejestracja. Poczekaj minutę." });
      }
    }
  }

  try {
    const connection = new Connection(clusterApiUrl("devnet"), "confirmed");
    const tx = await connection.getTransaction(signature, { commitment: "confirmed" });

    if (!tx || !tx.transaction || !tx.meta) {
      return res.status(400).json({ error: "Nie znaleziono transakcji" });
    }

    const from = tx.transaction.message.accountKeys[0].toBase58();
    const to = tx.transaction.message.accountKeys[1].toBase58();
    if (to !== RECIPIENT) {
      return res.status(400).json({ error: "Nieprawidłowy odbiorca" });
    }

    const lamports = tx.meta.postBalances[1] - tx.meta.preBalances[1];
    const sol = lamports / 1_000_000_000;
    const solToUsd = await getSolToUsd();
    const mem = Math.floor((sol * solToUsd) / TOKEN_PRICE_USD);

    db[signature] = { wallet: from, sol, mem, solToUsd, timestamp: Date.now() };
    delete db[`nonce_${wallet}`];
    writeDB(db);

    res.json({ success: true, mem });
  } catch (err) {
    res.status(500).json({ error: "Błąd serwera" });
  }
});

app.post("/balance", limiter, (req, res) => {
  const origin = req.headers.origin || req.headers.referer;
  if (!allowedOrigins.some(o => origin && origin.startsWith(o))) {
    return res.status(403).json({ error: "Nieautoryzowane źródło żądania" });
  }

  try {
    const { wallet, signature, message } = req.body;
    if (!wallet || !signature || !message) {
      return res.status(400).json({ error: "Brakuje danych" });
    }

    const db = readDB();
    const nonceEntry = db[`nonce_${wallet}`];
    if (!nonceEntry || nonceEntry.expires < Date.now()) {
      return res.status(400).json({ error: "Nonce wygasł lub nie istnieje" });
    }

    const expectedMessage = `Sprawdz moje MEM | ${nonceEntry.value}`;
    if (message !== expectedMessage) {
      return res.status(400).json({ error: "Nieprawidłowa wiadomość" });
    }

    const pubKey = new PublicKey(wallet);
    const decodedSignature = Uint8Array.from(Buffer.from(signature, 'base64'));
    const messageBytes = new TextEncoder().encode(message);

    if (!nacl.sign.detached.verify(messageBytes, decodedSignature, pubKey.toBytes())) {
      return res.status(403).json({ error: "Nieprawidłowy podpis" });
    }

    let totalMem = 0;
    for (const key in db) {
      if (db[key].wallet === wallet) {
        totalMem += db[key].mem || 0;
      }
    }

    delete db[`nonce_${wallet}`];
    writeDB(db);
    res.json({ wallet, balance: totalMem });
  } catch (e) {
    res.status(500).json({ error: "Błąd podpisu", details: e.message });
  }
});

function verifyAdminAuth(req, res, next) {
  const token = req.headers['x-api-key'];
  if (!token || token !== ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Brak autoryzacji administratora' });
  }
  next();
}

app.get("/admin/db", verifyAdminAuth, (req, res) => {
  try {
    const db = readDB();
    res.json(db);
  } catch (err) {
    res.status(500).json({ error: "Nie można odczytać bazy danych" });
  }
});

app.get("/config", async (req, res) => {
  const solToUsd = await getSolToUsd();
  res.json({ TOKEN_PRICE_USD, SOL_TO_USD: solToUsd });
});

app.listen(PORT, () => {
  console.log(`Serwer działa na http://localhost:${PORT}`);
});
