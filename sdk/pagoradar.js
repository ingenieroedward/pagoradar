// pagoradar SDK: one file, no dependencies (Node 18+). Copy it into your project, or install the repo
// (npm i github:ingenieroedward/pagoradar) and `import { Pagoradar } from "pagoradar/sdk"`.
//
//   const pr = new Pagoradar({ apiKey: process.env.PAGORADAR_API_KEY, baseUrl: "https://pagoradar.tudominio.com" });
//   const charge = await pr.charges.create({ account: "acc_…", amount: 25000, description: "Pedido 123", reference: "order-123" });
//   // send the customer to charge.checkoutUrl; then, in your webhook:
//   const event = constructEvent(rawBody, req.headers["pagoradar-signature"], process.env.PAGORADAR_WEBHOOK_SECRET);
//   if (event.type === "charge.paid") markOrderPaid(event.data.reference);
import { createHmac, timingSafeEqual } from "node:crypto";

export class PagoradarError extends Error {
  constructor(message, status = null, body = null) {
    super(message);
    this.name = "PagoradarError";
    this.status = status;
    this.body = body;
  }
}

const qs = (params = {}) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
};
const seg = (id) => encodeURIComponent(String(id));

export class Pagoradar {
  constructor({ apiKey, baseUrl, fetch: fetchImpl = globalThis.fetch, timeoutMs = 10_000 } = {}) {
    if (!apiKey) throw new PagoradarError("Falta apiKey");
    if (!baseUrl) throw new PagoradarError("Falta baseUrl");
    this.apiKey = apiKey;
    this.baseUrl = String(baseUrl).replace(/\/+$/, "");
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;

    this.accounts = {
      create: (fields) => this.request("POST", "/v1/accounts", fields),
      list: (filters) => this.request("GET", `/v1/accounts${qs(filters)}`).then((r) => r.accounts),
      get: (id) => this.request("GET", `/v1/accounts/${seg(id)}`),
      update: (id, fields) => this.request("PATCH", `/v1/accounts/${seg(id)}`, fields),
      remove: (id) => this.request("DELETE", `/v1/accounts/${seg(id)}`),
    };
    this.charges = {
      create: (fields) => this.request("POST", "/v1/charges", fields),
      list: (filters) => this.request("GET", `/v1/charges${qs(filters)}`),
      get: (id) => this.request("GET", `/v1/charges/${seg(id)}`),
      cancel: (id) => this.request("POST", `/v1/charges/${seg(id)}/cancel`),
      pay: (id, paymentId) => this.request("POST", `/v1/charges/${seg(id)}/pay`, { paymentId }),
    };
    this.payments = {
      list: (filters) => this.request("GET", `/v1/payments${qs(filters)}`),
    };
    this.webhooks = {
      test: () => this.request("POST", "/v1/webhooks/test"),
    };
  }

  async request(method, path, body) {
    let res;
    try {
      res = await this.fetch(this.baseUrl + path, {
        method,
        headers: { Authorization: `Bearer ${this.apiKey}`, Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      throw new PagoradarError(`No se pudo conectar con pagoradar: ${e?.message ?? e}`);
    }
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new PagoradarError(data?.error ?? `HTTP ${res.status}`, res.status, data);
    return data;
  }
}

/** True when `rawBody` (the exact bytes/string received) was signed by pagoradar with `secret` in the last `toleranceSec`. */
export function verifySignature(rawBody, header, secret, { toleranceSec = 300, now = Date.now() } = {}) {
  const parts = Object.fromEntries(String(header ?? "").split(",").map((p) => p.trim().split("=", 2)));
  const t = Number(parts.t);
  if (!secret || !Number.isFinite(t) || !parts.v1 || Math.abs(now / 1000 - t) > toleranceSec) return false;
  const body = typeof rawBody === "string" ? rawBody : Buffer.from(rawBody).toString("utf8");
  const expected = Buffer.from(createHmac("sha256", secret).update(`${t}.${body}`).digest("hex"));
  const given = Buffer.from(parts.v1);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

/** Verifies the `Pagoradar-Signature` header and returns the parsed event; throws PagoradarError if it isn't genuine. */
export function constructEvent(rawBody, header, secret, options) {
  if (!verifySignature(rawBody, header, secret, options)) throw new PagoradarError("Firma de webhook inválida", 400);
  return JSON.parse(typeof rawBody === "string" ? rawBody : Buffer.from(rawBody).toString("utf8"));
}
