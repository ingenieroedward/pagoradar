/**
 * pagoradar — Cloudflare Email Worker.
 *
 * Cloudflare Email Routing hands every email sent to your pagoradar address to this Worker, which
 * passes it untouched (raw bytes, so the bank's DKIM signature can still be checked) to the pagoradar
 * service, signed with INGEST_SECRET. It reads nothing and keeps nothing.
 *
 * Variables: PAGORADAR_URL (e.g. https://pagoradar.example.com), INGEST_SECRET (secret),
 * FALLBACK_FORWARD (optional: a verified address that gets the email if the service can't be reached).
 */
const MAX_BYTES = 5 * 1024 * 1024;

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

export async function signIngest(secret, timestamp, raw) {
  const digest = hex(await crypto.subtle.digest("SHA-256", raw));
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(`${timestamp}.${digest}`)));
}

/** Delivers one email to pagoradar; true when the service took it (accepted, duplicate or rejected on purpose). */
export async function deliver(raw, { to, from }, env, { fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  const url = `${String(env.PAGORADAR_URL).replace(/\/+$/, "")}/ingest`;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await sleep(1000 * 2 ** attempt);
    const timestamp = String(Math.floor(Date.now() / 1000));
    try {
      const res = await fetchImpl(url, {
        method: "POST",
        headers: {
          "Content-Type": "message/rfc822",
          "X-Pagoradar-Timestamp": timestamp,
          "X-Pagoradar-Signature": await signIngest(env.INGEST_SECRET, timestamp, raw),
          "X-Pagoradar-To": to,
          "X-Pagoradar-From": from,
        },
        body: raw,
      });
      if (res.ok) return true;
      // A wrong secret or an oversized email won't get better by retrying.
      if (res.status === 401 || res.status === 413) return false;
    } catch {
      // network error: retry
    }
  }
  return false;
}

export default {
  async email(message, env) {
    if (message.rawSize > MAX_BYTES) {
      if (env.FALLBACK_FORWARD) return message.forward(env.FALLBACK_FORWARD);
      return message.setReject("Mensaje demasiado grande");
    }
    const raw = new Uint8Array(await new Response(message.raw).arrayBuffer());
    const ok = await deliver(raw, { to: message.to, from: message.from }, env);
    if (ok) return;
    if (env.FALLBACK_FORWARD) return message.forward(env.FALLBACK_FORWARD);
    message.setReject("pagoradar no está disponible, inténtalo más tarde");
  },
};
