import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  bank TEXT NOT NULL,
  method TEXT,
  method_text TEXT,
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL,
  payer_name TEXT,
  payer_name_normalized TEXT,
  payer_bank TEXT,
  reference TEXT,
  transaction_id TEXT,
  account_hint TEXT,
  paid_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  dkim_domain TEXT,
  dedupe_key TEXT NOT NULL,
  UNIQUE (source, dedupe_key)
);
CREATE INDEX IF NOT EXISTS payments_source_received ON payments (source, received_at);

CREATE TABLE IF NOT EXISTS deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL,
  source TEXT NOT NULL,
  url TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_status INTEGER,
  last_error TEXT,
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  UNIQUE (event_id, url)
);
CREATE INDEX IF NOT EXISTS deliveries_due ON deliveries (status, next_attempt_at);

-- Emails that were not accepted (unknown sender, failed DKIM, unrecognized format, Gmail's
-- forwarding confirmation…), kept a few days so the owner can see why. Payments are never here.
CREATE TABLE IF NOT EXISTS inbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT,
  received_at TEXT NOT NULL,
  reason TEXT NOT NULL,
  from_addr TEXT,
  subject TEXT,
  code TEXT,
  snippet TEXT
);
`;

export const newId = (prefix) => `${prefix}_${Date.now().toString(36)}${randomBytes(8).toString("hex")}`;

export function openStore(path) {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;");
  db.exec(SCHEMA);

  const insertPayment = db.prepare(`INSERT OR IGNORE INTO payments
    (id, source, bank, method, method_text, amount_cents, currency, payer_name, payer_name_normalized, payer_bank,
     reference, transaction_id, account_hint, paid_at, received_at, dkim_domain, dedupe_key)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const insertDelivery = db.prepare(`INSERT OR IGNORE INTO deliveries (event_id, source, url, body, next_attempt_at, created_at) VALUES (?,?,?,?,?,?)`);

  return {
    db,
    /** Stores a payment; returns it with its id, or null if this source already had it (a duplicate notice). */
    addPayment(source, p, receivedAt = new Date().toISOString()) {
      const id = newId("pay");
      const r = insertPayment.run(id, source, p.bank, p.method, p.methodText, p.amountCents, p.currency, p.payerName, p.payerNameNormalized,
        p.payerBank, p.reference, p.transactionId, p.accountHint, p.paidAt, receivedAt, p.dkimDomain, p.dedupeKey);
      return r.changes === 1 ? this.getPayment(id) : null;
    },
    getPayment(id) {
      const row = db.prepare("SELECT * FROM payments WHERE id = ?").get(id);
      return row ? toPayment(row) : null;
    },
    listPayments(source, { since, limit = 100 } = {}) {
      const rows = db
        .prepare("SELECT * FROM payments WHERE source = ? AND received_at > ? ORDER BY received_at ASC, id ASC LIMIT ?")
        .all(source, since ?? "", Math.min(Math.max(1, limit), 500));
      return rows.map(toPayment);
    },
    queueDelivery(eventId, source, url, body, at = new Date().toISOString()) {
      insertDelivery.run(eventId, source, url, body, at, at);
    },
    dueDeliveries(now = new Date().toISOString(), limit = 20) {
      return db.prepare("SELECT * FROM deliveries WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT ?").all(now, limit);
    },
    markDelivered(id, httpStatus, at = new Date().toISOString()) {
      db.prepare("UPDATE deliveries SET status = 'delivered', attempts = attempts + 1, last_status = ?, last_error = NULL, delivered_at = ? WHERE id = ?").run(httpStatus, at, id);
    },
    markFailedAttempt(id, httpStatus, error, nextAt) {
      db.prepare("UPDATE deliveries SET attempts = attempts + 1, last_status = ?, last_error = ?, next_attempt_at = COALESCE(?, next_attempt_at), status = CASE WHEN ? IS NULL THEN 'failed' ELSE 'pending' END WHERE id = ?")
        .run(httpStatus, String(error ?? "").slice(0, 300), nextAt, nextAt, id);
    },
    listDeliveries({ source, status, limit = 100 } = {}) {
      return db
        .prepare("SELECT id, event_id, source, url, status, attempts, next_attempt_at, last_status, last_error, created_at, delivered_at FROM deliveries WHERE (? IS NULL OR source = ?) AND (? IS NULL OR status = ?) ORDER BY id DESC LIMIT ?")
        .all(source ?? null, source ?? null, status ?? null, status ?? null, limit);
    },
    retryDelivery(id, at = new Date().toISOString()) {
      return db.prepare("UPDATE deliveries SET status = 'pending', next_attempt_at = ? WHERE id = ? AND status != 'delivered'").run(at, id).changes === 1;
    },
    addInbox(entry, at = new Date().toISOString()) {
      db.prepare("INSERT INTO inbox (source, received_at, reason, from_addr, subject, code, snippet) VALUES (?,?,?,?,?,?,?)")
        .run(entry.source ?? null, at, entry.reason, entry.from ?? null, (entry.subject ?? "").slice(0, 200), entry.code ?? null, entry.snippet ? entry.snippet.slice(0, 1500) : null);
    },
    listInbox(limit = 50) {
      return db.prepare("SELECT * FROM inbox ORDER BY id DESC LIMIT ?").all(limit);
    },
    /** Retention: rejected emails 7 days, finished deliveries 30 days, payments `paymentDays`. */
    cleanup(paymentDays, now = Date.now()) {
      const ago = (days) => new Date(now - days * 86400000).toISOString();
      db.prepare("DELETE FROM inbox WHERE received_at < ?").run(ago(7));
      db.prepare("DELETE FROM deliveries WHERE status != 'pending' AND created_at < ?").run(ago(30));
      db.prepare("DELETE FROM payments WHERE received_at < ?").run(ago(paymentDays));
    },
    close: () => db.close(),
  };
}

function toPayment(r) {
  return {
    id: r.id,
    source: r.source,
    bank: r.bank,
    method: r.method,
    methodText: r.method_text,
    amount: r.amount_cents / 100,
    amountCents: r.amount_cents,
    currency: r.currency,
    payerName: r.payer_name,
    payerNameNormalized: r.payer_name_normalized,
    payerBank: r.payer_bank,
    reference: r.reference,
    transactionId: r.transaction_id,
    accountHint: r.account_hint,
    paidAt: r.paid_at,
    receivedAt: r.received_at,
  };
}
