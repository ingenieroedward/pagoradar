import { createHmac, timingSafeEqual } from "node:crypto";

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

export function paymentEvent(payment, type = "payment.received") {
  return {
    id: `evt_${payment.id.replace(/^pay_/, "")}`,
    type,
    createdAt: new Date().toISOString(),
    source: payment.source,
    data: payment,
  };
}

/** Queues one event for every webhook of its source. */
export function queueEvent(store, source, event) {
  const body = JSON.stringify(event);
  for (const w of source.webhooks) store.queueDelivery(event.id, source.id, w.url, body);
}

/** Sends what is due. Returns how many were attempted. `fetchImpl` is for tests. */
export async function deliverDue(store, sources, { fetchImpl = fetch, now = Date.now(), log = () => {} } = {}) {
  const due = store.dueDeliveries(new Date(now).toISOString());
  await Promise.all(
    due.map(async (d) => {
      const source = sources.find((s) => s.id === d.source);
      const hook = source?.webhooks.find((w) => w.url === d.url);
      if (!hook) {
        store.markFailedAttempt(d.id, null, "El webhook ya no está en la configuración", null);
        return;
      }
      const nextAt = d.attempts < RETRY_DELAYS_MS.length ? new Date(now + RETRY_DELAYS_MS[d.attempts]).toISOString() : null;
      try {
        const res = await fetchImpl(d.url, {
          method: "POST",
          redirect: "manual",
          signal: AbortSignal.timeout(10_000),
          headers: {
            "Content-Type": "application/json",
            "User-Agent": "pagoradar/1",
            "Pagoradar-Event-Id": d.event_id,
            "Pagoradar-Signature": signatureHeader(hook.secret, d.body),
          },
          body: d.body,
        });
        if (res.status >= 200 && res.status < 300) {
          store.markDelivered(d.id, res.status);
          log(`webhook ${d.event_id} -> ${new URL(d.url).host}: ${res.status}`);
        } else {
          store.markFailedAttempt(d.id, res.status, `HTTP ${res.status}`, nextAt);
          log(`webhook ${d.event_id} -> ${new URL(d.url).host}: HTTP ${res.status}${nextAt ? `, reintento ${nextAt}` : ", sin más reintentos"}`);
        }
      } catch (e) {
        store.markFailedAttempt(d.id, null, e?.name === "TimeoutError" ? "Tiempo de espera agotado" : (e?.message ?? "Error de red"), nextAt);
        log(`webhook ${d.event_id} -> ${new URL(d.url).host}: ${e?.message ?? e}${nextAt ? `, reintento ${nextAt}` : ", sin más reintentos"}`);
      }
    }),
  );
  return due.length;
}
