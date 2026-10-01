import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Waits after each failed attempt: 30 s, 2 min, 10 min, 30 min, 1 h, 3 h, 6 h, 12 h, 24 h — then it gives up. */
export const RETRY_DELAYS_MS = [30e3, 120e3, 600e3, 1800e3, 3600e3, 3 * 3600e3, 6 * 3600e3, 12 * 3600e3, 24 * 3600e3];

/** `Pagoradar-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">` (same idea as Stripe's). */
export function signatureHeader(secret, body, t = Math.floor(Date.now() / 1000)) {
  return `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;
}

/** For the receiving app: is this body really from pagoradar, signed in the last `toleranceSec`? */
export function verifySignature(secret, header, body, toleranceSec = 300, now = Date.now()) {
  const parts = Object.fromEntries(String(header || "").split(",").map((p) => p.trim().split("=", 2)));
  const t = Number(parts.t);
  if (!Number.isFinite(t) || !parts.v1 || Math.abs(now / 1000 - t) > toleranceSec) return false;
  const expected = Buffer.from(createHmac("sha256", secret).update(`${t}.${body}`).digest("hex"));
  const given = Buffer.from(parts.v1);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

/** An event for an app. `type`: payment.received, payment.test, account.confirmation_code, account.activated… */
export function makeEvent(type, appId, data, id = `evt_${randomBytes(10).toString("hex")}`) {
  return { id, type, createdAt: new Date().toISOString(), source: appId, data };
}

/** payment.received for a stored payment; the receiving account (and the app's own id for it) and the charge it paid ride along. */
export function paymentEvent(payment, account, charge = null, type = "payment.received") {
  const data = {
    ...payment,
    account: account ? { id: account.id, name: account.name, tenantRef: account.tenantRef } : null,
    charge: charge ? { id: charge.id, reference: charge.reference } : null,
  };
  return makeEvent(type, payment.source, data, `evt_${payment.id.replace(/^pay_/, "")}`);
}

/** Queues an event for the app's webhook (nothing when the app has none). */
export function queueEvent(store, app, event) {
  if (!app?.webhookUrl) return false;
  store.deliveries.queue(event.id, app.id, app.webhookUrl, JSON.stringify(event));
  return true;
}

/**
 * Sends what is due, to the app's current webhook URL (so fixing a wrong URL and retrying works) and signed with
 * its current secret. Returns how many were attempted. `fetchImpl` is for tests.
 */
export async function deliverDue(store, { fetchImpl = fetch, now = Date.now(), log = () => {} } = {}) {
  const due = store.deliveries.due(new Date(now).toISOString());
  await Promise.all(
    due.map(async (d) => {
      const app = store.apps.get(d.source);
      if (!app?.webhookUrl || !app.active) {
        store.deliveries.markFailedAttempt(d.id, null, app ? "La app no tiene webhook o está inactiva" : "La app ya no existe", null);
        return;
      }
      const nextAt = d.attempts < RETRY_DELAYS_MS.length ? new Date(now + RETRY_DELAYS_MS[d.attempts]).toISOString() : null;
      const host = (() => {
        try {
          return new URL(app.webhookUrl).host;
        } catch {
          return app.webhookUrl;
        }
      })();
      try {
        const res = await fetchImpl(app.webhookUrl, {
          method: "POST",
          redirect: "manual",
          signal: AbortSignal.timeout(10_000),
          headers: {
            "Content-Type": "application/json",
            "User-Agent": "pagoradar/2",
            "Pagoradar-Event-Id": d.event_id,
            "Pagoradar-Signature": signatureHeader(store.apps.secret(app.id), d.body),
          },
          body: d.body,
        });
        if (res.status >= 200 && res.status < 300) {
          store.deliveries.markDelivered(d.id, res.status);
          log(`webhook ${d.event_id} -> ${host}: ${res.status}`);
        } else {
          store.deliveries.markFailedAttempt(d.id, res.status, `HTTP ${res.status}`, nextAt);
          log(`webhook ${d.event_id} -> ${host}: HTTP ${res.status}${nextAt ? `, reintento ${nextAt}` : ", sin más reintentos"}`);
        }
      } catch (e) {
        store.deliveries.markFailedAttempt(d.id, null, e?.name === "TimeoutError" ? "Tiempo de espera agotado" : (e?.message ?? "Error de red"), nextAt);
        log(`webhook ${d.event_id} -> ${host}: ${e?.message ?? e}${nextAt ? `, reintento ${nextAt}` : ", sin más reintentos"}`);
      }
    }),
  );
  return due.length;
}
