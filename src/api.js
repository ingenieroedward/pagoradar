import { BANK_IDS, gmailFilterFor } from "./parsers/index.js";
import { rateLimiter, readBody, sendJson } from "./http.js";
import { chargeDTO, createCharge, expireCharges, payManually } from "./charges.js";
import { deliverDue, makeEvent, queueEvent } from "./webhooks.js";

const MAX_ACCOUNTS_PER_APP = 5000;
const createLimit = rateLimiter(60, 3600_000);
const chargeLimit = rateLimiter(2000, 3600_000);
const CHARGE_STATUSES = ["pending", "paid", "expired", "canceled"];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** An account as the API returns it: everything the app needs to guide its customer through the setup. */
export function accountDTO(a) {
  return {
    id: a.id,
    name: a.name,
    address: a.address,
    ownerEmails: a.ownerEmails,
    banks: a.banks,
    tenantRef: a.tenantRef,
    status: a.status,
    confirmationCode: a.confirmationCode,
    confirmationLink: a.confirmationLink,
    confirmationAt: a.confirmationAt,
    lastEmailAt: a.lastEmailAt,
    lastPaymentAt: a.lastPaymentAt,
    payKey: a.payKey,
    payHolder: a.payHolder,
    createdAt: a.createdAt,
    setup: { forwardTo: a.address, gmailFilterFrom: gmailFilterFor(a.banks) },
  };
}

async function readJson(req) {
  const body = await readBody(req, 16 * 1024);
  if (body === null) return { error: "Cuerpo demasiado grande" };
  if (!body.length) return { value: {} };
  try {
    const value = JSON.parse(body.toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? { value } : { error: "Se esperaba un objeto JSON" };
  } catch {
    return { error: "JSON inválido" };
  }
}

/** Validates the editable fields; `partial` for PATCH (only what was sent). */
function accountFields(input, { partial = false } = {}) {
  const out = {};
  if (!partial || input.name !== undefined) {
    const name = typeof input.name === "string" ? input.name.trim() : "";
    if (!name || name.length > 60) return { error: "name: texto de 1 a 60 caracteres" };
    out.name = name;
  }
  if (!partial || input.ownerEmails !== undefined) {
    const emails = Array.isArray(input.ownerEmails) ? [...new Set(input.ownerEmails.map((e) => String(e).trim().toLowerCase()))] : [];
    if (emails.length === 0 || emails.length > 10 || emails.some((e) => !EMAIL_RE.test(e) || e.length > 120)) {
      return { error: "ownerEmails: lista de 1 a 10 correos válidos (donde el banco avisa)" };
    }
    out.ownerEmails = emails;
  }
  if (input.banks !== undefined || !partial) {
    const banks = input.banks === undefined ? BANK_IDS : Array.isArray(input.banks) ? [...new Set(input.banks)] : null;
    if (!banks || banks.length === 0 || banks.some((b) => !BANK_IDS.includes(b))) return { error: `banks: lista con ${BANK_IDS.join(", ")}` };
    out.banks = banks;
  }
  for (const [field, max, label] of [["payKey", 80, "la llave Bre-B donde pagan los clientes"], ["payHolder", 80, "el titular que ven los clientes"]]) {
    if (input[field] === undefined) continue;
    if (input[field] !== null && (typeof input[field] !== "string" || input[field].trim().length > max)) return { error: `${field}: ${label}, texto de hasta ${max} caracteres o null` };
    out[field] = input[field]?.trim() || null;
  }
  if (input.tenantRef !== undefined) {
    if (input.tenantRef !== null && (typeof input.tenantRef !== "string" || input.tenantRef.length > 120)) return { error: "tenantRef: texto de hasta 120 caracteres o null" };
    out.tenantRef = input.tenantRef ? input.tenantRef.trim() : null;
  }
  return { value: out };
}

/**
 * The API for apps, authenticated with one of the app's keys (Authorization: Bearer prk_…):
 *   GET    /v1/payments?since=&limit=&account=&tenantRef=   the app's payments in arrival order
 *   POST   /v1/webhooks/test                                a payment.test event to the app's webhook
 *   POST   /v1/accounts                                     create a receiving account (for one of your customers)
 *   GET    /v1/accounts?tenantRef=                          the app's receiving accounts
 *   GET    /v1/accounts/:id                                 one account (status, Gmail confirmation code…)
 *   PATCH  /v1/accounts/:id                                 change name / ownerEmails / banks / tenantRef / active
 *   DELETE /v1/accounts/:id                                 delete it (or disable it, when it already has payments)
 *   POST   /v1/charges                                      ask a customer for an amount (unique amount + checkout page)
 *   GET    /v1/charges?status=&reference=&account=&tenantRef=
 *   GET    /v1/charges/:id
 *   POST   /v1/charges/:id/cancel                           frees its amount; only while pending
 *   POST   /v1/charges/:id/pay   { paymentId }              link a payment by hand
 * Returns false when the path isn't an API route.
 */
export async function handleApi(req, res, url, ctx) {
  const { store, log } = ctx;
  const publicUrl = ctx.config?.publicUrl ?? null;
  const path = url.pathname.replace(/\/+$/, "");
  if (!path.startsWith("/v1/")) return false;
  const done = (status, body) => (sendJson(res, status, body), true);

  const bearer = String(req.headers.authorization ?? "").match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  const app = store.keys.appFor(bearer);
  if (!app) return done(401, { error: "API key inválida" });
  const audit = (action, target, detail) => store.audit.add(`API · ${app.name}`, action, target, detail);

  if (path === "/v1/payments" && req.method === "GET") {
    const since = url.searchParams.get("since") ?? undefined;
    if (since && Number.isNaN(Date.parse(since))) return done(400, { error: "since debe ser una fecha ISO" });
    let payments = store.payments.listForApp(app.id, {
      since: since ? new Date(since).toISOString() : undefined,
      limit: Number(url.searchParams.get("limit") ?? 100) || 100,
    });
    const next = payments.at(-1)?.receivedAt ?? since ?? null;
    const account = url.searchParams.get("account");
    const tenantRef = url.searchParams.get("tenantRef");
    if (account) payments = payments.filter((p) => p.accountId === account);
    if (tenantRef) {
      const ids = new Set(store.accounts.byTenant(app.id, tenantRef).map((a) => a.id));
      payments = payments.filter((p) => ids.has(p.accountId));
    }
    payments = payments.map((p) => ({ ...p, chargeId: store.charges.byPayment(p.id)?.id ?? null }));
    return done(200, { payments, next });
  }

  if (path === "/v1/webhooks/test" && req.method === "POST") {
    const result = await sendTestEvent(store, app, log);
    return result ? done(200, result) : done(400, { error: "Esta app no tiene webhook" });
  }

  if (path === "/v1/accounts" && req.method === "POST") {
    const domain = store.settings.get("inbound_domain") ?? ctx.config?.inboundDomain;
    if (!domain) return done(503, { error: "pagoradar no tiene dominio de recepción configurado" });
    if (!createLimit(app.id)) return done(429, { error: "Demasiadas cuentas creadas en la última hora" });
    if (store.accounts.list(app.id).length >= MAX_ACCOUNTS_PER_APP) return done(409, { error: "Límite de cuentas de esta app" });
    const body = await readJson(req);
    if (body.error) return done(400, { error: body.error });
    const fields = accountFields(body.value);
    if (fields.error) return done(400, { error: fields.error });
    const created = store.accounts.create({ appId: app.id, domain, tenantRef: null, ...fields.value });
    const { payKey, payHolder } = fields.value;
    const a = payKey || payHolder ? store.accounts.update(created.id, { payKey, payHolder }) : created;
    audit("Creó la cuenta receptora", a.id, `${a.name} · ${a.address}${a.tenantRef ? ` · cliente ${a.tenantRef}` : ""}`);
    return done(201, accountDTO(a));
  }

  if (path === "/v1/accounts" && req.method === "GET") {
    const tenantRef = url.searchParams.get("tenantRef");
    const list = tenantRef ? store.accounts.byTenant(app.id, tenantRef) : store.accounts.list(app.id);
    return done(200, { accounts: list.map(accountDTO) });
  }

  const m = path.match(/^\/v1\/accounts\/([\w-]+)$/);
  if (m) {
    const a = store.accounts.get(m[1]);
    // Another app's account is answered exactly like a missing one.
    if (!a || a.appId !== app.id) return done(404, { error: "Cuenta no encontrada" });
    if (req.method === "GET") return done(200, accountDTO(a));
    if (req.method === "PATCH") {
      const body = await readJson(req);
      if (body.error) return done(400, { error: body.error });
      const fields = accountFields(body.value, { partial: true });
      if (fields.error) return done(400, { error: fields.error });
      if (body.value.active !== undefined && typeof body.value.active !== "boolean") return done(400, { error: "active: true o false" });
      store.accounts.update(a.id, fields.value);
      if (typeof body.value.active === "boolean") store.accounts.setDisabled(a.id, !body.value.active);
      audit("Editó la cuenta receptora", a.id, JSON.stringify({ ...fields.value, ...(typeof body.value.active === "boolean" ? { active: body.value.active } : {}) }));
      return done(200, accountDTO(store.accounts.get(a.id)));
    }
    if (req.method === "DELETE") {
      const hasPayments = store.payments.search({ accountId: a.id, limit: 1 }).total > 0;
      if (hasPayments) {
        store.accounts.setDisabled(a.id, true);
        audit("Desactivó la cuenta receptora (tiene pagos)", a.id, a.address);
        return done(200, { id: a.id, deleted: false, disabled: true });
      }
      store.accounts.remove(a.id);
      audit("Eliminó la cuenta receptora", a.id, a.address);
      return done(200, { id: a.id, deleted: true });
    }
  }

  if (path === "/v1/charges" || path.startsWith("/v1/charges/")) {
    if (expireCharges(store, { publicUrl })) void deliverDue(store, { log }).catch(() => {});
    const dto = (c) => chargeDTO(c, store.accounts.get(c.accountId), publicUrl);

    if (path === "/v1/charges" && req.method === "POST") {
      if (!chargeLimit(app.id)) return done(429, { error: "Demasiados cobros creados en la última hora" });
      const body = await readJson(req);
      if (body.error) return done(400, { error: body.error });
      const r = createCharge(store, app, body.value);
      if (r.error) return done(r.status, { error: r.error });
      if (r.created) audit("Creó un cobro", r.charge.id, `$${r.charge.amount.toLocaleString("es-CO")} · ${r.account.name}${r.charge.reference ? ` · ref. ${r.charge.reference}` : ""}`);
      return done(r.created ? 201 : 200, chargeDTO(r.charge, r.account, publicUrl));
    }
    if (path === "/v1/charges" && req.method === "GET") {
      const q = url.searchParams;
      const status = q.get("status") || undefined;
      if (status && !CHARGE_STATUSES.includes(status)) return done(400, { error: `status: ${CHARGE_STATUSES.join(", ")}` });
      const { total, rows } = store.charges.search({
        appId: app.id,
        status,
        reference: q.get("reference") || undefined,
        accountId: q.get("account") || undefined,
        tenantRef: q.get("tenantRef") || undefined,
        limit: Number(q.get("limit") ?? 50) || 50,
        offset: Number(q.get("offset") ?? 0) || 0,
      });
      return done(200, { charges: rows.map(dto), total });
    }
    const cm = path.match(/^\/v1\/charges\/(chg_[a-z0-9]+)(?:\/(cancel|pay))?$/);
    const charge = cm ? store.charges.get(cm[1]) : null;
    if (!charge || charge.appId !== app.id) return done(404, { error: "Cobro no encontrado" });
    if (!cm[2] && req.method === "GET") return done(200, dto(charge));
    if (cm[2] === "cancel" && req.method === "POST") {
      if (!store.charges.cancel(charge.id)) return done(409, { error: `No se puede cancelar un cobro ${charge.status}` });
      audit("Canceló un cobro", charge.id, charge.reference);
      return done(200, dto(store.charges.get(charge.id)));
    }
    if (cm[2] === "pay" && req.method === "POST") {
      const body = await readJson(req);
      if (body.error) return done(400, { error: body.error });
      const payment = typeof body.value.paymentId === "string" ? store.payments.get(body.value.paymentId) : null;
      if (!payment || payment.appId !== app.id) return done(404, { error: "Pago no encontrado" });
      if (payment.accountId !== charge.accountId) return done(409, { error: "El pago llegó a otra cuenta receptora" });
      if (store.charges.byPayment(payment.id)) return done(409, { error: "Ese pago ya está asociado a otro cobro" });
      const paid = payManually(store, app, charge, payment, { publicUrl });
      if (!paid) return done(409, { error: `No se puede marcar pagado un cobro ${charge.status}` });
      audit("Asoció un pago a un cobro", charge.id, payment.id);
      void deliverDue(store, { log }).catch(() => {});
      return done(200, dto(paid));
    }
  }

  return done(404, { error: "No encontrado" });
}

/** A payment.test event (fake data) to the app's webhook, delivered right away. Null when there's no webhook. */
export async function sendTestEvent(store, app, log = () => {}) {
  const at = new Date().toISOString();
  const event = makeEvent("payment.test", app.id, {
    id: `pay_test${Date.now().toString(36)}`, source: app.id, appId: app.id, accountId: null, bank: "nequi_negocios", method: "breb_qr",
    methodText: "QR Negocios Bre-B", amount: 1000, amountCents: 100000, currency: "COP", payerName: "Prueba Pagoradar",
    payerNameNormalized: "PRUEBA PAGORADAR", payerBank: "Nequi", reference: null, transactionId: null, accountHint: null,
    paidAt: at, receivedAt: at, account: null, charge: null,
  });
  if (!queueEvent(store, app, event)) return null;
  await deliverDue(store, { log });
  return { queued: 1, deliveries: store.deliveries.list({ appId: app.id, limit: 1 }) };
}
