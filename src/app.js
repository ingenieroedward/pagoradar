import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { analyzeEmail } from "./analyze.js";
import { deliverDue, paymentEvent, queueEvent } from "./webhooks.js";

const MAX_EMAIL_BYTES = 5 * 1024 * 1024;
const INGEST_TOLERANCE_SEC = 300;

const safeEqual = (a, b) => {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};

/** What the Worker sends: HMAC-SHA256(INGEST_SECRET, "<timestamp>.<sha256 hex of the raw email>"). */
export function ingestSignature(secret, timestamp, raw) {
  const digest = createHash("sha256").update(raw).digest("hex");
  return createHmac("sha256", secret).update(`${timestamp}.${digest}`).digest("hex");
}

/**
 * The HTTP side of pagoradar, as a plain (req, res) handler:
 *   POST /ingest                    raw email from the Cloudflare Worker (signed)
 *   GET  /v1/payments?since=&limit= the source's payments (Authorization: Bearer <apiKey>)
 *   POST /v1/webhooks/test          sends a test event to the source's webhooks
 *   GET  /admin/inbox | /admin/deliveries, POST /admin/deliveries/<id>/retry   (Bearer ADMIN_TOKEN)
 *   GET  /health
 */
export function createApp({ config, store, resolver, log = console.log }) {
  const sourceByAddress = new Map();
  for (const s of config.sources) for (const a of s.addresses) sourceByAddress.set(a, s);

  async function ingest(req, res) {
    const raw = await readBody(req, MAX_EMAIL_BYTES);
    if (raw === null) return send(res, 413, { error: "Correo demasiado grande" });
    const ts = Number(req.headers["x-pagoradar-timestamp"]);
    const sig = String(req.headers["x-pagoradar-signature"] ?? "");
    if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > INGEST_TOLERANCE_SEC || !safeEqual(sig, ingestSignature(config.ingestSecret, ts, raw))) {
      return send(res, 401, { error: "Firma inválida" });
    }
    const to = String(req.headers["x-pagoradar-to"] ?? "").trim().toLowerCase();
    const source = sourceByAddress.get(to);
    const result = await analyzeEmail(raw, { ownerEmails: source?.ownerEmails ?? [], banks: source?.banks, resolver });

    if (result.reason === "gmail_forwarding_confirmation") {
      store.addInbox({ source: source?.id, reason: result.reason, from: result.from, subject: result.subject, code: result.code, snippet: result.text });
      log(`Gmail pide confirmar el reenvío hacia ${to}. Código: ${result.code ?? "(no se encontró)"} · Asunto: ${result.subject}`);
      if (result.link) log(`…o abre este enlace para confirmarlo: ${result.link}`);
      return send(res, 200, { result: "rejected", reason: result.reason });
    }
    if (!source) {
      store.addInbox({ reason: "unknown_address", from: result.from, subject: result.subject, snippet: `Para: ${to}` });
      log(`correo para una dirección sin fuente: ${to}`);
      return send(res, 200, { result: "rejected", reason: "unknown_address" });
    }
    if (!result.ok) {
      // Keep the text only for formats worth fixing (a genuine bank email we couldn't read).
      const keepText = result.reason === "unrecognized" || result.reason === "not_approved";
      store.addInbox({ source: source.id, reason: result.reason, from: result.from, subject: result.subject, snippet: keepText ? result.text : null });
      log(`[${source.id}] correo rechazado (${result.reason}) de ${result.from || "?"}`);
      return send(res, 200, { result: "rejected", reason: result.reason });
    }
    const payment = store.addPayment(source.id, result.payment);
    if (!payment) {
      log(`[${source.id}] aviso repetido de ${result.payment.bank}, ignorado`);
      return send(res, 200, { result: "duplicate" });
    }
    queueEvent(store, source, paymentEvent(payment));
    log(`[${source.id}] pago ${payment.id}: ${payment.bank} $${payment.amount.toLocaleString("es-CO")}`);
    void deliverDue(store, config.sources, { log }).catch(() => {});
    return send(res, 200, { result: "accepted", paymentId: payment.id });
  }

  function sourceFor(req) {
    const key = bearer(req);
    return key ? config.sources.find((s) => safeEqual(s.apiKey, key)) : undefined;
  }
  const isAdmin = (req) => config.adminToken && safeEqual(bearer(req) ?? "", config.adminToken);

  return async function handle(req, res) {
    try {
      const url = new URL(req.url, "http://x");
      const path = url.pathname.replace(/\/+$/, "") || "/";
      if (path === "/health" && req.method === "GET") {
        store.db.prepare("SELECT 1").get();
        return send(res, 200, { ok: true });
      }
      if (path === "/ingest" && req.method === "POST") return await ingest(req, res);

      if (path === "/v1/payments" && req.method === "GET") {
        const source = sourceFor(req);
        if (!source) return send(res, 401, { error: "API key inválida" });
        const since = url.searchParams.get("since") ?? undefined;
        if (since && Number.isNaN(Date.parse(since))) return send(res, 400, { error: "since debe ser una fecha ISO" });
        const payments = store.listPayments(source.id, { since: since ? new Date(since).toISOString() : undefined, limit: Number(url.searchParams.get("limit") ?? 100) || 100 });
        return send(res, 200, { payments, next: payments.at(-1)?.receivedAt ?? since ?? null });
      }
      if (path === "/v1/webhooks/test" && req.method === "POST") {
        const source = sourceFor(req);
        if (!source) return send(res, 401, { error: "API key inválida" });
        if (source.webhooks.length === 0) return send(res, 400, { error: "Esta fuente no tiene webhooks" });
        const sample = {
          id: `pay_test${Date.now().toString(36)}`, source: source.id, bank: "nequi_negocios", method: "breb_qr", methodText: "QR Negocios Bre-B",
          amount: 1000, amountCents: 100000, currency: "COP", payerName: "Prueba Pagoradar", payerNameNormalized: "PRUEBA PAGORADAR",
          payerBank: "Nequi", reference: null, transactionId: null, accountHint: null, paidAt: new Date().toISOString(), receivedAt: new Date().toISOString(),
        };
        queueEvent(store, source, paymentEvent(sample, "payment.test"));
        await deliverDue(store, config.sources, { log });
        return send(res, 200, { queued: source.webhooks.length, deliveries: store.listDeliveries({ source: source.id, limit: source.webhooks.length }) });
      }

      if (path.startsWith("/admin/")) {
        if (!isAdmin(req)) return send(res, 401, { error: "No autorizado" });
        if (path === "/admin/inbox" && req.method === "GET") return send(res, 200, { inbox: store.listInbox(Number(url.searchParams.get("limit") ?? 50) || 50) });
        if (path === "/admin/deliveries" && req.method === "GET") {
          return send(res, 200, { deliveries: store.listDeliveries({ source: url.searchParams.get("source") ?? undefined, status: url.searchParams.get("status") ?? undefined }) });
        }
        const m = path.match(/^\/admin\/deliveries\/(\d+)\/retry$/);
        if (m && req.method === "POST") {
          const ok = store.retryDelivery(Number(m[1]));
          if (ok) await deliverDue(store, config.sources, { log });
          return send(res, ok ? 200 : 404, ok ? { ok: true } : { error: "No existe o ya se entregó" });
        }
      }
      return send(res, 404, { error: "No encontrado" });
    } catch (e) {
      log(`error: ${e?.stack ?? e}`);
      if (!res.headersSent) send(res, 500, { error: "Error interno" });
    }
  };
}

function bearer(req) {
  const m = String(req.headers.authorization ?? "").match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooBig = false;
    req.on("data", (c) => {
      size += c.length;
      if (size > max) tooBig = true;
      else chunks.push(c);
    });
    req.on("end", () => resolve(tooBig ? null : Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
