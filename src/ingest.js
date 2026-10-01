import { createHash, createHmac } from "node:crypto";
import { analyzeEmail } from "./analyze.js";
import { matchPayment } from "./charges.js";
import { safeEqual } from "./security.js";
import { deliverDue, makeEvent, paymentEvent, queueEvent } from "./webhooks.js";

export const MAX_EMAIL_BYTES = 5 * 1024 * 1024;
const TOLERANCE_SEC = 300;

/** What the Worker sends: HMAC-SHA256(INGEST_SECRET, "<timestamp>.<sha256 hex of the raw email>"). */
export function ingestSignature(secret, timestamp, raw) {
  const digest = createHash("sha256").update(raw).digest("hex");
  return createHmac("sha256", secret).update(`${timestamp}.${digest}`).digest("hex");
}

export function validIngestSignature(secret, headers, raw, now = Date.now()) {
  const ts = Number(headers["x-pagoradar-timestamp"]);
  const sig = String(headers["x-pagoradar-signature"] ?? "");
  return Number.isFinite(ts) && Math.abs(now / 1000 - ts) <= TOLERANCE_SEC && safeEqual(sig, ingestSignature(secret, ts, raw));
}

/**
 * One email from the Worker, addressed to `to`. The receiving account is found by that address; its owner
 * emails and banks decide whether the notice counts (see analyze.js). Returns { result, reason?, paymentId? }.
 */
export async function ingestEmail(store, raw, to, { resolver, publicUrl = null, log = () => {} } = {}) {
  const address = String(to ?? "").trim().toLowerCase();
  const account = store.accounts.byAddress(address);
  const app = account ? store.apps.get(account.appId) : null;
  const active = account && account.status !== "disabled" && app?.active;
  const result = await analyzeEmail(raw, { ownerEmails: account?.ownerEmails ?? [], banks: account?.banks, resolver });

  if (result.reason === "gmail_forwarding_confirmation") {
    store.inbox.add({ appId: app?.id, accountId: account?.id, reason: result.reason, from: result.from, subject: result.subject, code: result.code, link: result.link, snippet: result.text });
    if (account) {
      store.accounts.recordConfirmation(account.id, result.code, result.link);
      queueEvent(store, app, makeEvent("account.confirmation_code", app.id, { account: { id: account.id, name: account.name, tenantRef: account.tenantRef, address }, code: result.code, link: result.link }));
      void deliverDue(store, { log }).catch(() => {});
    }
    log(`Gmail pide confirmar el reenvío hacia ${address}. Código: ${result.code ?? "(no se encontró)"} · Asunto: ${result.subject}`);
    if (result.link) log(`…o abre este enlace para confirmarlo: ${result.link}`);
    return { result: "rejected", reason: result.reason };
  }
  if (!account) {
    store.inbox.add({ reason: "unknown_address", from: result.from, subject: result.subject, snippet: `Para: ${address}` });
    log(`correo para una dirección que no es de ninguna cuenta: ${address}`);
    return { result: "rejected", reason: "unknown_address" };
  }
  if (!active) {
    store.inbox.add({ appId: app?.id, accountId: account.id, reason: "account_disabled", from: result.from, subject: result.subject });
    return { result: "rejected", reason: "account_disabled" };
  }
  if (!result.ok) {
    // Keep the text only for formats worth fixing (a genuine bank email we couldn't read).
    const keepText = result.reason === "unrecognized" || result.reason === "not_approved";
    store.inbox.add({ appId: app.id, accountId: account.id, reason: result.reason, from: result.from, subject: result.subject, snippet: keepText ? result.text : null });
    log(`[${account.id}] correo rechazado (${result.reason}) de ${result.from || "?"}`);
    return { result: "rejected", reason: result.reason };
  }

  if (store.accounts.markActive(account.id)) {
    queueEvent(store, app, makeEvent("account.activated", app.id, { account: { id: account.id, name: account.name, tenantRef: account.tenantRef, address } }));
  }
  const payment = store.payments.add(app.id, account.id, result.payment);
  if (!payment) {
    log(`[${account.id}] aviso repetido de ${result.payment.bank}, ignorado`);
    return { result: "duplicate" };
  }
  store.accounts.touchPayment(account.id);
  const matched = matchPayment(store, app, account, payment, { publicUrl });
  queueEvent(store, app, paymentEvent(payment, account, matched?.charge));
  if (matched) queueEvent(store, app, matched.event);
  log(`[${app.id}/${account.id}] pago ${payment.id}: ${payment.bank} $${payment.amount.toLocaleString("es-CO")}${matched ? ` · paga el cobro ${matched.charge.id}` : ""}`);
  void deliverDue(store, { log }).catch(() => {});
  return { result: "accepted", paymentId: payment.id, chargeId: matched?.charge.id ?? null };
}
