// Novidades Cool - verificação de pagamentos M-Pesa / e-Mola por SMS
// e desbloqueio de vídeos (pay-per-view).
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const https = require("https");
const http = require("http");

const app = express();
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  res.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const PORT = process.env.PORT || 3000;
const SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString("hex");
const SMS_KEY = process.env.SMS_KEY || ""; // chave que a app de SMS envia em ?key=
const FORWARD_URL = process.env.FORWARD_URL || ""; // ex.: http://5.182.33.81:3002/api/pagamentos
const TOKEN_HOURS = Number(process.env.TOKEN_HOURS || 6);
const DATA_FILE = path.join(__dirname, "data", "transacoes.json");

// Lista de vídeos (id: título, preço em MZN, link do ficheiro mp4)
const videos = {
  "a-festa-de-roubo": { title: "A festa de roubo", price: 10, source: "" },
  "charge": { title: "Charge", price: 10, source: "" },
  "tears-of-steel": { title: "Tears of Steel", price: 10, source: "" },
  "sintel": { title: "Sintel", price: 10, source: "" },
};

// ---------- armazenamento simples ----------
let db = { tx: {} };
try { db = JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); } catch (_) {}
function save() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(db));
}

// ---------- leitura dos SMS ----------
function parseSms(text) {
  const t = String(text || "").replace(/\s+/g, " ").trim();
  let id = null;
  // M-Pesa: "Confirmado DJK7ABC123. Recebeste 10.00MT de ..."
  let m = t.match(/Confirmado\s+([A-Z0-9]{6,20})/i);
  if (m) id = m[1];
  // e-Mola: "ID da transacao: PP251017.1234.A12345" / "ID: ..."
  if (!id) { m = t.match(/ID(?:\s+da\s+transa[cç][aã]o)?\s*[:\-]?\s*([A-Z0-9.]{6,30})/i); if (m) id = m[1]; }
  let amount = null;
  m = t.match(/Rece(?:beste|beu)\s+([\d.,]+)\s*MT/i) || t.match(/([\d.,]+)\s*MT/i);
  if (m) amount = parseFloat(m[1].replace(/\.(?=\d{3}\b)/g, "").replace(",", "."));
  if (id) id = id.replace(/\.$/, "").toUpperCase();
  return { id, amount, received: /Rece(beste|beu)/i.test(t) };
}

function forward(body) {
  if (!FORWARD_URL) return;
  try {
    const u = new URL(FORWARD_URL);
    const lib = u.protocol === "https:" ? https : http;
    const data = JSON.stringify(body);
    const r = lib.request(u, { method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } });
    r.on("error", () => {});
    r.end(data);
  } catch (_) {}
}

// Recebe os SMS encaminhados pelo telemóvel (mesmo formato da API SMS V1.7)
app.post("/api/pagamentos", (req, res) => {
  if (SMS_KEY && req.query.key !== SMS_KEY) return res.status(401).json({ success: false, message: "Chave inválida" });
  const message = req.body.message || req.body.mensagem || req.body.sms || "";
  forward(req.body);
  const p = parseSms(message);
  if (!p.id || !p.received) return res.json({ success: true, stored: false, message: "SMS sem pagamento recebido" });
  if (!db.tx[p.id]) {
    db.tx[p.id] = { amount: p.amount, at: Date.now(), used: false, sender: req.body.sender || "" };
    save();
  }
  res.json({ success: true, stored: true, id: p.id, amount: p.amount });
});

// ---------- tokens de acesso ----------
function sign(videoId, exp) {
  const payload = `${videoId}.${exp}`;
  const sig = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  return Buffer.from(payload).toString("base64url") + "." + sig;
}
function check(token) {
  const [p, sig] = String(token).split(".");
  if (!p || !sig) return null;
  const payload = Buffer.from(p, "base64url").toString();
  const good = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  if (good.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(good), Buffer.from(sig))) return null;
  const [videoId, exp] = payload.split(".");
  if (Date.now() > Number(exp)) return null;
  return videoId;
}

// O site envia { videoId, transactionId }
app.post("/api/verify", (req, res) => {
  const videoId = String(req.body.videoId || "");
  const txId = String(req.body.transactionId || "").trim().replace(/\.$/, "").toUpperCase();
  const video = videos[videoId];
  if (!video) return res.status(404).json({ ok: false, message: "Vídeo não encontrado" });
  const tx = db.tx[txId];
  if (!tx) return res.json({ ok: false, message: "Pagamento não encontrado. Confirme o ID e tente de novo." });
  if (tx.used && tx.video !== videoId) return res.json({ ok: false, message: "Este ID já foi usado." });
  if (tx.amount != null && tx.amount < (video.price || 10)) return res.json({ ok: false, message: "Valor pago insuficiente." });
  if (!tx.used) { tx.used = true; tx.video = videoId; tx.usedAt = Date.now(); save(); }
  const exp = Date.now() + TOKEN_HOURS * 3600 * 1000;
  const base = `${req.headers["x-forwarded-proto"] || req.protocol}://${req.get("host")}`;
  res.json({ ok: true, url: `${base}/v/${sign(videoId, exp)}` });
});

// ---------- entrega do vídeo ----------
app.get("/v/:token", (req, res) => {
  const videoId = check(req.params.token);
  if (!videoId || !videos[videoId]) return res.status(403).send("Acesso expirado ou inválido.");
  const v = videos[videoId];
  const local = path.join(__dirname, "videos", `${videoId}.mp4`);
  if (fs.existsSync(local)) return res.sendFile(local); // suporta Range
  if (!v.source) return res.status(404).send("Vídeo ainda não carregado.");
  const u = new URL(v.source);
  const lib = u.protocol === "https:" ? https : http;
  const headers = req.headers.range ? { Range: req.headers.range } : {};
  lib.get(u, { headers }, (up) => {
    res.status(up.statusCode);
    ["content-type", "content-length", "content-range", "accept-ranges"].forEach((h) => up.headers[h] && res.set(h, up.headers[h]));
    up.pipe(res);
  }).on("error", () => res.status(502).end());
});

app.get("/", (_, res) => res.json({ ok: true, servico: "Novidades Cool pagamentos", videos: Object.keys(videos) }));

app.listen(PORT, () => console.log("A correr na porta " + PORT));
