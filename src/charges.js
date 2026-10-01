import { normalizeName } from "./text.js";
import { makeEvent, queueEvent } from "./webhooks.js";

/**
 * Charges: an app asks its customer to pay an amount into one of its receiving accounts. To recognize the
 * payment by the bank notice alone, each open charge of an account gets a unique amount: the asked amount
 * plus (or minus) a few pesos. The notice that brings exactly that amount pays the charge.
 */

export const UNIQUE_MODES = ["up", "down", "off"];
/** The most pesos added to (or taken from) the asked amount to make it unique. */
export const MAX_ADJUSTMENT_PESOS = 999;
/** An expired charge keeps its amount reserved this long: a notice can arrive a few minutes late. */
export const LATE_GRACE_MS = 30 * 60_000;
/** Bank notices carry the time to the minute (or second): a payment counts if made within this of the charge's window. */
export const MATCH_SLACK_MS = 5 * 60_000;

/** The charge as the API, the events and the SDK see it. */
export function chargeDTO(c, account, publicUrl) {
  return {
    id: c.id,
    status: c.status,
    amount: c.amount,
    amountCents: c.amountCents,
    baseAmount: c.baseAmount,
    adjustment: c.amount - c.baseAmount,
    currency: c.currency,
    description: c.description,
    reference: c.reference,
    payerName: c.payerName,
    metadata: c.metadata,
    account: account ? { id: account.id, name: account.name, tenantRef: account.tenantRef } : { id: c.accountId },
    payTo: account ? { key: account.payKey, holder: account.payHolder, banks: account.banks } : null,
    checkoutUrl: `${publicUrl ?? ""}/c/${c.id}`,
    returnUrl: c.returnUrl,
    paymentId: c.paymentId,
    /** How it got paid: "exact", "approximate" (the customer paid the asked amount, not the unique one) or "manual". */
    match: c.match,
    paidAmount: c.paidAmount,
    createdAt: c.createdAt,
    expiresAt: c.expiresAt,
    paidAt: c.paidAt,
    canceledAt: c.canceledAt,
  };
}

/** A free amount (cents) for a new charge of `baseCents` in this account, or null when none is left. */
export function pickAmount(store, accountId, baseCents, mode, at = new Date().toISOString()) {
  if (mode === "off") return baseCents;
  const taken = store.charges.takenAmounts(accountId, at, LATE_GRACE_MS);
  // Never the round amount itself: someone paying it without a charge must not settle one.
  for (let k = 1; k <= MAX_ADJUSTMENT_PESOS; k++) {
    const cents = mode === "down" ? baseCents - k * 100 : baseCents + k * 100;
    if (cents <= 0) return null;
    if (!taken.has(cents)) return cents;
  }
  return null;
}

/** Same rule as Ibirifas: at least two words in common (one if a name has a single word), and every word of the shorter name. */
export function namesMatch(a, b) {
  const words = (s) => new Set(normalizeName(String(s ?? "")).split(" ").filter((w) => w.length > 1));
  const x = words(a);
  const y = words(b);
  if (x.size === 0 || y.size === 0) return false;
  const shared = [...x].filter((w) => y.has(w)).length;
  return shared >= Math.min(2, x.size, y.size) && shared === Math.min(x.size, y.size);
}

function chargeEvent(type, app, charge, account, publicUrl, extra = {}) {
  return makeEvent(type, app.id, { ...chargeDTO(charge, account, publicUrl), ...extra }, `evt_${type.replace(".", "_")}_${charge.id.replace(/^chg_/, "")}`);
}

/** One charge out of several: the only one, or the only one whose expected payer is who paid. */
function pickOne(candidates, payment) {
  if (candidates.length === 1) return candidates[0];
  const byName = candidates.filter((c) => c.payerName && namesMatch(c.payerName, payment.payerName));
  return byName.length === 1 ? byName[0] : null;
}

/**
 * A payment just arrived in `account`: settles the charge it pays, if any.
 *  1. exact: open charges with that unique amount (several only with uniqueAmount "off": the expected payer decides);
 *  2. approximate: none, but the customer paid the round amount asked for (25.000 instead of 25.001) — taken only
 *     when a single open charge asked that amount (or a single one expects this payer). Otherwise it waits for a person.
 * Returns { charge, event } — the charge.paid event for the caller to queue after payment.received — or null.
 */
export function matchPayment(store, app, account, payment, { publicUrl } = {}) {
  const at = payment.paidAt ?? payment.receivedAt;
  let match = "exact";
  let pick = null;
  const exact = store.charges.candidates(account.id, payment.amountCents, at, MATCH_SLACK_MS);
  if (exact.length) pick = pickOne(exact, payment);
  else {
    // Charges with uniqueAmount "off" were already looked at above (their amount is the base).
    const byBase = store.charges.candidates(account.id, payment.amountCents, at, MATCH_SLACK_MS, "base_cents").filter((c) => c.amountCents !== c.baseAmount * 100);
    if (byBase.length) {
      pick = pickOne(byBase, payment);
      match = "approximate";
    }
  }
  if (!pick || !store.charges.markPaid(pick.id, payment, match)) return null;
  const charge = store.charges.get(pick.id);
  return { charge, event: chargeEvent("charge.paid", app, charge, account, publicUrl, { payment, late: pick.status === "expired" }) };
}

/** A person (the app by API, or an admin in the panel) links a payment to a charge the automatic match couldn't decide. */
export function payManually(store, app, charge, payment, { publicUrl } = {}) {
  if (!store.charges.markPaid(charge.id, payment, "manual")) return null;
  const paid = store.charges.get(charge.id);
  const account = store.accounts.get(charge.accountId);
  queueEvent(store, app, chargeEvent("charge.paid", app, paid, account, publicUrl, { payment, late: charge.status !== "pending", manual: true }));
  return paid;
}

/** Expires overdue open charges and queues charge.expired for each. Returns how many. */
export function expireCharges(store, { publicUrl, at } = {}) {
  const due = store.charges.expireDue(at);
  for (const c of due) {
    const app = store.apps.get(c.appId);
    if (app) queueEvent(store, app, chargeEvent("charge.expired", app, c, store.accounts.get(c.accountId), publicUrl));
  }
  return due.length;
}

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Validates and creates a charge for `app`. Returns { charge, account, created } or { status, error }.
 * A `reference` already used by the app returns that same charge (safe to retry) unless the request differs.
 */
export function createCharge(store, app, input, { at = new Date() } = {}) {
  const fail = (error, status = 400) => ({ status, error });

  let account = null;
  if (input.account !== undefined) {
    if (typeof input.account !== "string") return fail("account: id de la cuenta receptora");
    account = store.accounts.get(input.account);
  } else if (input.tenantRef !== undefined) {
    if (typeof input.tenantRef !== "string") return fail("tenantRef: texto");
    account = store.accounts.byTenant(app.id, input.tenantRef).find((a) => a.status !== "disabled") ?? null;
  } else {
    return fail("Falta account (o tenantRef): la cuenta donde el cliente va a pagar");
  }
  if (!account || account.appId !== app.id) return fail("Cuenta receptora no encontrada", 404);
  if (account.status === "disabled") return fail("La cuenta receptora está desactivada", 409);

  const amount = input.amount;
  if (typeof amount !== "number" || !Number.isInteger(amount) || amount < 1 || amount > 100_000_000) return fail("amount: valor en pesos, entero, de 1 a 100.000.000");
  if (input.currency !== undefined && input.currency !== "COP") return fail("currency: por ahora solo COP");
  const mode = input.uniqueAmount ?? "up";
  if (!UNIQUE_MODES.includes(mode)) return fail(`uniqueAmount: ${UNIQUE_MODES.join(", ")}`);
  const minutes = input.expiresInMinutes ?? 30;
  if (!Number.isInteger(minutes) || minutes < 5 || minutes > 10_080) return fail("expiresInMinutes: de 5 a 10080 (7 días)");
  const text = (name, max) => {
    const v = input[name];
    if (v === undefined || v === null || v === "") return { value: null };
    if (typeof v !== "string" || v.trim().length > max) return { error: `${name}: texto de hasta ${max} caracteres` };
    return { value: v.trim() };
  };
  const description = text("description", 140);
  const reference = text("reference", 120);
  const payerName = text("payerName", 120);
  for (const f of [description, reference, payerName]) if (f.error) return fail(f.error);
  let returnUrl = null;
  if (input.returnUrl !== undefined && input.returnUrl !== null && input.returnUrl !== "") {
    try {
      const u = new URL(String(input.returnUrl));
      if ((u.protocol !== "https:" && u.protocol !== "http:") || String(input.returnUrl).length > 500) throw new Error();
      returnUrl = u.toString();
    } catch {
      return fail("returnUrl: una URL http(s) de hasta 500 caracteres");
    }
  }
  if (input.metadata !== undefined && input.metadata !== null && (!isPlainObject(input.metadata) || JSON.stringify(input.metadata).length > 2000)) {
    return fail("metadata: un objeto JSON de hasta 2000 caracteres");
  }

  if (reference.value) {
    const existing = store.charges.byReference(app.id, reference.value);
    if (existing) {
      const same = existing.accountId === account.id && existing.baseAmount === amount;
      return same ? { charge: existing, account, created: false } : fail("Ya existe un cobro con esa reference y otros datos", 409);
    }
  }

  const nowIso = at.toISOString();
  const amountCents = pickAmount(store, account.id, amount * 100, mode, nowIso);
  if (amountCents === null) return fail("No quedan valores únicos libres para ese monto en esta cuenta: espera a que venzan los cobros abiertos", 409);
  const charge = store.charges.create({
    appId: app.id,
    accountId: account.id,
    baseCents: amount * 100,
    amountCents,
    description: description.value,
    reference: reference.value,
    payerName: payerName.value,
    metadata: input.metadata ?? null,
    returnUrl,
    createdAt: nowIso,
    expiresAt: new Date(at.getTime() + minutes * 60_000).toISOString(),
  });
  return { charge, account, created: true };
}
