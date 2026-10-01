import { sendJson } from "./http.js";
import { deliverDue, makeEvent, queueEvent } from "./webhooks.js";

/**
 * The API for apps, authenticated with one of the app's keys (Authorization: Bearer prk_…):
 *   GET  /v1/payments?since=&limit=   the app's payments in arrival order (catch-up for missed webhooks)
 *   POST /v1/webhooks/test            sends a payment.test event to the app's webhook
 * Returns false when the path isn't an API route.
 */
export async function handleApi(req, res, url, { store, log }) {
  const path = url.pathname.replace(/\/+$/, "");
  if (!path.startsWith("/v1/")) return false;

  const bearer = String(req.headers.authorization ?? "").match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  const app = store.keys.appFor(bearer);
  if (!app) return sendJson(res, 401, { error: "API key inválida" }), true;

  if (path === "/v1/payments" && req.method === "GET") {
    const since = url.searchParams.get("since") ?? undefined;
    if (since && Number.isNaN(Date.parse(since))) return sendJson(res, 400, { error: "since debe ser una fecha ISO" }), true;
    const payments = store.payments.listForApp(app.id, {
      since: since ? new Date(since).toISOString() : undefined,
      limit: Number(url.searchParams.get("limit") ?? 100) || 100,
    });
    return sendJson(res, 200, { payments, next: payments.at(-1)?.receivedAt ?? since ?? null }), true;
  }

  if (path === "/v1/webhooks/test" && req.method === "POST") {
    const result = await sendTestEvent(store, app, log);
    if (!result) return sendJson(res, 400, { error: "Esta app no tiene webhook" }), true;
    return sendJson(res, 200, result), true;
  }

  return sendJson(res, 404, { error: "No encontrado" }), true;
}

/** A payment.test event (fake data) to the app's webhook, delivered right away. Null when there's no webhook. */
export async function sendTestEvent(store, app, log = () => {}) {
  const at = new Date().toISOString();
  const event = makeEvent("payment.test", app.id, {
    id: `pay_test${Date.now().toString(36)}`, source: app.id, appId: app.id, accountId: null, bank: "nequi_negocios", method: "breb_qr",
    methodText: "QR Negocios Bre-B", amount: 1000, amountCents: 100000, currency: "COP", payerName: "Prueba Pagoradar",
    payerNameNormalized: "PRUEBA PAGORADAR", payerBank: "Nequi", reference: null, transactionId: null, accountHint: null,
    paidAt: at, receivedAt: at, account: null,
  });
  if (!queueEvent(store, app, event)) return null;
  await deliverDue(store, { log });
  return { queued: 1, deliveries: store.deliveries.list({ appId: app.id, limit: 1 }) };
}
