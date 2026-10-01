import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { decrypt, encrypt, randomCode, randomToken, sha256 } from "./security.js";

// v1: what the first version created (kept as is, so existing databases keep their payments).
const V1 = `
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

// v2: configuration lives in the database (apps, receiving accounts, keys) and the admin panel.
// `source` in payments / deliveries / inbox is the app id.
const V2 = `
ALTER TABLE payments ADD COLUMN account_id TEXT;
ALTER TABLE inbox ADD COLUMN account_id TEXT;
ALTER TABLE inbox ADD COLUMN link TEXT;
CREATE TABLE apps (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  webhook_url TEXT,
  webhook_secret_enc TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);
CREATE INDEX api_keys_app ON api_keys (app_id);
CREATE TABLE accounts (
  id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL,
  name TEXT NOT NULL,
  address TEXT NOT NULL UNIQUE,
  owner_emails TEXT NOT NULL,
  banks TEXT NOT NULL,
  tenant_ref TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  confirmation_code TEXT,
  confirmation_link TEXT,
  confirmation_at TEXT,
  last_email_at TEXT,
  last_payment_at TEXT,
  created_at TEXT NOT NULL,
  disabled_at TEXT
);
CREATE INDEX accounts_app ON accounts (app_id);
CREATE TABLE admins (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  password_hash TEXT NOT NULL,
  totp_secret_enc TEXT,
  totp_last_step INTEGER NOT NULL DEFAULT -1,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  created_at TEXT NOT NULL,
  last_login_at TEXT
);
CREATE TABLE sessions (
  id_hash TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL,
  csrf TEXT NOT NULL,
  stage TEXT NOT NULL,
  pending_totp_enc TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  ip TEXT
);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  admin_email TEXT,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT
);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`;

// v3: charges (an amount the app asks a customer to pay, matched to the bank notice) and how to pay an account.
const V3 = `
ALTER TABLE accounts ADD COLUMN pay_key TEXT;
ALTER TABLE accounts ADD COLUMN pay_holder TEXT;
CREATE TABLE charges (
  id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  base_cents INTEGER NOT NULL,
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'COP',
  description TEXT,
  reference TEXT,
  payer_name TEXT,
  metadata TEXT,
  return_url TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  payment_id TEXT UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  paid_at TEXT,
  canceled_at TEXT
);
CREATE INDEX charges_open ON charges (account_id, status, amount_cents);
CREATE INDEX charges_app ON charges (app_id, created_at);
CREATE INDEX charges_due ON charges (status, expires_at);
CREATE UNIQUE INDEX charges_app_reference ON charges (app_id, reference) WHERE reference IS NOT NULL;
`;

export const newId = (prefix) => `${prefix}_${Date.now().toString(36)}${randomBytes(8).toString("hex")}`;
const now = () => new Date().toISOString();
const json = (v, fallback) => {
  try {
    return JSON.parse(v);
  } catch {
    return fallback;
  }
};

export function openStore(path, { masterKey } = {}) {
  if (!masterKey) throw new Error("openStore necesita masterKey");
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;");
  db.exec(V1);
  const version = db.prepare("PRAGMA user_version").get().user_version;
  for (const [v, sql] of [[2, V2], [3, V3]]) {
    if (version >= v) continue;
    db.exec("BEGIN");
    try {
      db.exec(sql);
      db.exec(`PRAGMA user_version = ${v}`);
      db.exec("COMMIT");
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  }

  const one = (sql, ...args) => db.prepare(sql).get(...args);
  const all = (sql, ...args) => db.prepare(sql).all(...args);
  const run = (sql, ...args) => db.prepare(sql).run(...args);

  // ---------- settings
  const settings = {
    get: (key, fallback = null) => one("SELECT value FROM settings WHERE key = ?", key)?.value ?? fallback,
    set: (key, value) => run("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, String(value)),
  };

  // ---------- apps (the projects that receive payments: Ibirifas, another SaaS…)
  const toApp = (r) => r && { id: r.id, name: r.name, webhookUrl: r.webhook_url, active: r.active === 1, createdAt: r.created_at };
  const apps = {
    list: () => all("SELECT * FROM apps ORDER BY created_at").map(toApp),
    get: (id) => toApp(one("SELECT * FROM apps WHERE id = ?", id)),
    create({ id, name, webhookUrl = null, webhookSecret = null }) {
      const appId = id ?? `app_${randomCode(10)}`;
      run(
        "INSERT INTO apps (id, name, webhook_url, webhook_secret_enc, created_at) VALUES (?,?,?,?,?)",
        appId,
        name,
        webhookUrl,
        encrypt(masterKey, webhookSecret ?? `whsec_${randomToken(24)}`),
        now(),
      );
      return apps.get(appId);
    },
    update(id, { name, webhookUrl, active }) {
      const cur = one("SELECT * FROM apps WHERE id = ?", id);
      if (!cur) return null;
      run(
        "UPDATE apps SET name = ?, webhook_url = ?, active = ? WHERE id = ?",
        name ?? cur.name,
        webhookUrl === undefined ? cur.webhook_url : webhookUrl,
        active === undefined ? cur.active : active ? 1 : 0,
        id,
      );
      return apps.get(id);
    },
    secret: (id) => {
      const r = one("SELECT webhook_secret_enc FROM apps WHERE id = ?", id);
      return r ? decrypt(masterKey, r.webhook_secret_enc) : null;
    },
    rotateSecret(id) {
      const secret = `whsec_${randomToken(24)}`;
      run("UPDATE apps SET webhook_secret_enc = ? WHERE id = ?", encrypt(masterKey, secret), id);
      return secret;
    },
  };

  // ---------- API keys (shown once; only their hash is kept)
  const toKey = (r) =>
    r && { id: r.id, appId: r.app_id, name: r.name, prefix: r.prefix, createdAt: r.created_at, lastUsedAt: r.last_used_at, revokedAt: r.revoked_at };
  const keys = {
    listForApp: (appId) => all("SELECT * FROM api_keys WHERE app_id = ? ORDER BY created_at DESC", appId).map(toKey),
    /** Returns the full key once: `prk_<prefix>_<secret>`. A legacy key can be imported as it is. */
    create(appId, name, legacyKey = null) {
      const prefix = randomCode(8);
      const key = legacyKey ?? `prk_${prefix}_${randomToken(24)}`;
      const shown = legacyKey ? legacyKey.slice(0, 6) : `prk_${prefix}`;
      const id = newId("key");
      run("INSERT INTO api_keys (id, app_id, name, prefix, hash, created_at) VALUES (?,?,?,?,?,?)", id, appId, name, shown, sha256(key), now());
      return { ...toKey(one("SELECT * FROM api_keys WHERE id = ?", id)), key };
    },
    /** The app a bearer key belongs to (active key, active app), or null. Records its use. */
    appFor(key) {
      if (!key) return null;
      const r = one(
        "SELECT k.id AS key_id, a.* FROM api_keys k JOIN apps a ON a.id = k.app_id WHERE k.hash = ? AND k.revoked_at IS NULL AND a.active = 1",
        sha256(key),
      );
      if (!r) return null;
      run("UPDATE api_keys SET last_used_at = ? WHERE id = ?", now(), r.key_id);
      return toApp(r);
    },
    revoke: (id, appId) => run("UPDATE api_keys SET revoked_at = ? WHERE id = ? AND app_id = ? AND revoked_at IS NULL", now(), id, appId).changes === 1,
  };

  // ---------- receiving accounts (one per bank inbox that forwards here)
  const toAccount = (r) =>
    r && {
      id: r.id,
      appId: r.app_id,
      name: r.name,
      address: r.address,
      ownerEmails: json(r.owner_emails, []),
      banks: json(r.banks, []),
      tenantRef: r.tenant_ref,
      status: r.disabled_at ? "disabled" : r.status,
      confirmationCode: r.confirmation_code,
      confirmationLink: r.confirmation_link,
      confirmationAt: r.confirmation_at,
      lastEmailAt: r.last_email_at,
      lastPaymentAt: r.last_payment_at,
      payKey: r.pay_key,
      payHolder: r.pay_holder,
      createdAt: r.created_at,
    };
  const accounts = {
    list: (appId) =>
      (appId ? all("SELECT * FROM accounts WHERE app_id = ? ORDER BY created_at DESC", appId) : all("SELECT * FROM accounts ORDER BY created_at DESC")).map(toAccount),
    get: (id) => toAccount(one("SELECT * FROM accounts WHERE id = ?", id)),
    byAddress: (address) => toAccount(one("SELECT * FROM accounts WHERE address = ?", String(address).trim().toLowerCase())),
    byTenant: (appId, tenantRef) => all("SELECT * FROM accounts WHERE app_id = ? AND tenant_ref = ? ORDER BY created_at DESC", appId, tenantRef).map(toAccount),
    create({ appId, name, ownerEmails, banks, tenantRef = null, address = null, domain }) {
      const id = `acc_${randomCode(12)}`;
      const slug =
        String(name)
          .normalize("NFD")
          .replace(/[̀-ͯ]/g, "")
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-+|-+$/g, "")
          .slice(0, 20) || "cuenta";
      let addr = address?.trim().toLowerCase();
      for (let i = 0; !addr && i < 5; i++) {
        const candidate = `${slug}-${randomCode(6)}@${domain}`;
        if (!one("SELECT 1 FROM accounts WHERE address = ?", candidate)) addr = candidate;
      }
      run(
        "INSERT INTO accounts (id, app_id, name, address, owner_emails, banks, tenant_ref, created_at) VALUES (?,?,?,?,?,?,?,?)",
        id,
        appId,
        name,
        addr,
        JSON.stringify(ownerEmails.map((e) => e.trim().toLowerCase())),
        JSON.stringify(banks),
        tenantRef,
        now(),
      );
      return accounts.get(id);
    },
    update(id, { name, ownerEmails, banks, tenantRef, payKey, payHolder }) {
      const cur = one("SELECT * FROM accounts WHERE id = ?", id);
      if (!cur) return null;
      run(
        "UPDATE accounts SET name = ?, owner_emails = ?, banks = ?, tenant_ref = ?, pay_key = ?, pay_holder = ? WHERE id = ?",
        name ?? cur.name,
        ownerEmails ? JSON.stringify(ownerEmails.map((e) => e.trim().toLowerCase())) : cur.owner_emails,
        banks ? JSON.stringify(banks) : cur.banks,
        tenantRef === undefined ? cur.tenant_ref : tenantRef,
        payKey === undefined ? cur.pay_key : payKey,
        payHolder === undefined ? cur.pay_holder : payHolder,
        id,
      );
      return accounts.get(id);
    },
    setDisabled: (id, disabled) => run("UPDATE accounts SET disabled_at = ? WHERE id = ?", disabled ? now() : null, id).changes === 1,
    recordConfirmation: (id, code, link) =>
      run("UPDATE accounts SET confirmation_code = ?, confirmation_link = ?, confirmation_at = ? WHERE id = ?", code, link, now(), id),
    /** A genuine bank email arrived: the account works. Returns true the first time. */
    markActive(id) {
      run("UPDATE accounts SET last_email_at = ? WHERE id = ?", now(), id);
      return run("UPDATE accounts SET status = 'active' WHERE id = ? AND status = 'pending'", id).changes === 1;
    },
    touchPayment: (id) => run("UPDATE accounts SET last_payment_at = ? WHERE id = ?", now(), id),
    remove(id) {
      // Its open charges can't be paid anymore.
      run("UPDATE charges SET status = 'canceled', canceled_at = ? WHERE account_id = ? AND status = 'pending'", now(), id);
      return run("DELETE FROM accounts WHERE id = ?", id).changes === 1;
    },
  };

  // ---------- payments (`source` = app id)
  const insertPayment = db.prepare(`INSERT OR IGNORE INTO payments
    (id, source, account_id, bank, method, method_text, amount_cents, currency, payer_name, payer_name_normalized, payer_bank,
     reference, transaction_id, account_hint, paid_at, received_at, dkim_domain, dedupe_key)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const toPayment = (r) =>
    r && {
      id: r.id,
      source: r.source,
      appId: r.source,
      accountId: r.account_id,
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
  const payments = {
    /** Stores a payment; returns it, or null if this app already had it (a duplicate notice). */
    add(appId, accountId, p, receivedAt = now()) {
      const id = newId("pay");
      const r = insertPayment.run(id, appId, accountId, p.bank, p.method, p.methodText, p.amountCents, p.currency, p.payerName, p.payerNameNormalized,
        p.payerBank, p.reference, p.transactionId, p.accountHint, p.paidAt, receivedAt, p.dkimDomain, p.dedupeKey);
      return r.changes === 1 ? payments.get(id) : null;
    },
    get: (id) => toPayment(one("SELECT * FROM payments WHERE id = ?", id)),
    listForApp: (appId, { since, limit = 100 } = {}) =>
      all("SELECT * FROM payments WHERE source = ? AND received_at > ? ORDER BY received_at ASC, id ASC LIMIT ?", appId, since ?? "", Math.min(Math.max(1, limit), 500)).map(toPayment),
    search({ appId, accountId, bank, q, from, to, limit = 50, offset = 0 } = {}) {
      const where = [];
      const args = [];
      if (appId) where.push("source = ?"), args.push(appId);
      if (accountId) where.push("account_id = ?"), args.push(accountId);
      if (bank) where.push("bank = ?"), args.push(bank);
      if (q) where.push("(payer_name_normalized LIKE ? OR reference LIKE ?)"), args.push(`%${String(q).toUpperCase()}%`, `%${q}%`);
      if (from) where.push("paid_at >= ?"), args.push(from);
      if (to) where.push("paid_at < ?"), args.push(to);
      const sql = `FROM payments ${where.length ? `WHERE ${where.join(" AND ")}` : ""}`;
      return {
        total: one(`SELECT COUNT(*) AS n ${sql}`, ...args).n,
        rows: all(`SELECT * ${sql} ORDER BY paid_at DESC LIMIT ? OFFSET ?`, ...args, limit, offset).map(toPayment),
      };
    },
    stats: (sinceIso) => one("SELECT COUNT(*) AS n, COALESCE(SUM(amount_cents), 0) AS cents FROM payments WHERE received_at >= ?", sinceIso),
  };

  // ---------- charges: an amount an app asks its customer to pay into one of its accounts
  const toCharge = (r) =>
    r && {
      id: r.id,
      appId: r.app_id,
      accountId: r.account_id,
      baseAmount: r.base_cents / 100,
      amount: r.amount_cents / 100,
      amountCents: r.amount_cents,
      currency: r.currency,
      description: r.description,
      reference: r.reference,
      payerName: r.payer_name,
      metadata: r.metadata ? json(r.metadata, null) : null,
      returnUrl: r.return_url,
      status: r.status,
      paymentId: r.payment_id,
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      paidAt: r.paid_at,
      canceledAt: r.canceled_at,
    };
  const charges = {
    get: (id) => toCharge(one("SELECT * FROM charges WHERE id = ?", id)),
    byReference: (appId, reference) => toCharge(one("SELECT * FROM charges WHERE app_id = ? AND reference = ?", appId, reference)),
    byPayment: (paymentId) => toCharge(one("SELECT * FROM charges WHERE payment_id = ?", paymentId)),
    /** Amounts (cents) an account can't hand out now: open charges, and ones that expired in the last `graceMs` (a late notice may still come). */
    takenAmounts: (accountId, at, graceMs) =>
      new Set(
        all(
          "SELECT amount_cents FROM charges WHERE account_id = ? AND (status = 'pending' OR (status = 'expired' AND expires_at > ?))",
          accountId,
          new Date(new Date(at).getTime() - graceMs).toISOString(),
        ).map((r) => r.amount_cents),
      ),
    create(c) {
      // Unguessable: the id is also the public checkout link.
      const id = `chg_${randomCode(24)}`;
      run(
        `INSERT INTO charges (id, app_id, account_id, base_cents, amount_cents, currency, description, reference, payer_name, metadata, return_url, created_at, expires_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        id,
        c.appId,
        c.accountId,
        c.baseCents,
        c.amountCents,
        c.currency ?? "COP",
        c.description ?? null,
        c.reference ?? null,
        c.payerName ?? null,
        c.metadata ? JSON.stringify(c.metadata) : null,
        c.returnUrl ?? null,
        c.createdAt ?? now(),
        c.expiresAt,
      );
      return charges.get(id);
    },
    /** Charges of an account that a payment of `amountCents` made at `paidAt` could be paying (open, or expired just before it). */
    candidates: (accountId, amountCents, paidAt, slackMs) => {
      const t = new Date(paidAt).getTime();
      return all(
        "SELECT * FROM charges WHERE account_id = ? AND amount_cents = ? AND status IN ('pending','expired') AND created_at <= ? AND expires_at >= ? ORDER BY created_at",
        accountId,
        amountCents,
        new Date(t + slackMs).toISOString(),
        new Date(t - slackMs).toISOString(),
      ).map(toCharge);
    },
    /** Links the payment; false when the charge was already settled or the payment already pays another charge. */
    markPaid(id, paymentId, at = now()) {
      try {
        return run("UPDATE charges SET status = 'paid', payment_id = ?, paid_at = ? WHERE id = ? AND status IN ('pending','expired')", paymentId, at, id).changes === 1;
      } catch {
        return false; // payment_id is UNIQUE
      }
    },
    cancel: (id, at = now()) => run("UPDATE charges SET status = 'canceled', canceled_at = ? WHERE id = ? AND status = 'pending'", at, id).changes === 1,
    /** Marks overdue open charges expired and returns them. */
    expireDue(at = now()) {
      const due = all("SELECT * FROM charges WHERE status = 'pending' AND expires_at <= ?", at);
      for (const r of due) run("UPDATE charges SET status = 'expired' WHERE id = ? AND status = 'pending'", r.id);
      return due.map((r) => ({ ...toCharge(r), status: "expired" }));
    },
    search({ appId, accountId, status, reference, tenantRef, limit = 50, offset = 0 } = {}) {
      const where = [];
      const args = [];
      if (appId) where.push("c.app_id = ?"), args.push(appId);
      if (accountId) where.push("c.account_id = ?"), args.push(accountId);
      if (status) where.push("c.status = ?"), args.push(status);
      if (reference) where.push("c.reference = ?"), args.push(reference);
      if (tenantRef) where.push("a.tenant_ref = ?"), args.push(tenantRef);
      const sql = `FROM charges c LEFT JOIN accounts a ON a.id = c.account_id ${where.length ? `WHERE ${where.join(" AND ")}` : ""}`;
      return {
        total: one(`SELECT COUNT(*) AS n ${sql}`, ...args).n,
        rows: all(`SELECT c.* ${sql} ORDER BY c.created_at DESC LIMIT ? OFFSET ?`, ...args, Math.min(Math.max(1, limit), 500), offset).map(toCharge),
      };
    },
  };

  // ---------- webhook deliveries (`source` = app id)
  const deliveries = {
    queue: (eventId, appId, url, body, at = now()) =>
      run("INSERT OR IGNORE INTO deliveries (event_id, source, url, body, next_attempt_at, created_at) VALUES (?,?,?,?,?,?)", eventId, appId, url, body, at, at),
    due: (at = now(), limit = 20) => all("SELECT * FROM deliveries WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT ?", at, limit),
    markDelivered: (id, httpStatus, at = now()) =>
      run("UPDATE deliveries SET status = 'delivered', attempts = attempts + 1, last_status = ?, last_error = NULL, delivered_at = ? WHERE id = ?", httpStatus, at, id),
    markFailedAttempt: (id, httpStatus, error, nextAt) =>
      run(
        "UPDATE deliveries SET attempts = attempts + 1, last_status = ?, last_error = ?, next_attempt_at = COALESCE(?, next_attempt_at), status = CASE WHEN ? IS NULL THEN 'failed' ELSE 'pending' END WHERE id = ?",
        httpStatus,
        String(error ?? "").slice(0, 300),
        nextAt,
        nextAt,
        id,
      ),
    list: ({ appId, status, limit = 100 } = {}) =>
      all(
        "SELECT id, event_id, source, url, status, attempts, next_attempt_at, last_status, last_error, created_at, delivered_at, json_extract(body, '$.type') AS type FROM deliveries WHERE (? IS NULL OR source = ?) AND (? IS NULL OR status = ?) ORDER BY id DESC LIMIT ?",
        appId ?? null,
        appId ?? null,
        status ?? null,
        status ?? null,
        limit,
      ),
    retry: (id, at = now()) => run("UPDATE deliveries SET status = 'pending', next_attempt_at = ? WHERE id = ? AND status != 'delivered'", at, id).changes === 1,
    countFailed: () => one("SELECT COUNT(*) AS n FROM deliveries WHERE status = 'failed'").n,
  };

  // ---------- rejected emails (kept 7 days, so the owner can see why)
  const inbox = {
    add: (e, at = now()) =>
      run(
        "INSERT INTO inbox (source, account_id, received_at, reason, from_addr, subject, code, link, snippet) VALUES (?,?,?,?,?,?,?,?,?)",
        e.appId ?? null,
        e.accountId ?? null,
        at,
        e.reason,
        e.from ?? null,
        (e.subject ?? "").slice(0, 200),
        e.code ?? null,
        e.link ?? null,
        e.snippet ? e.snippet.slice(0, 1500) : null,
      ),
    list: ({ accountId, limit = 100 } = {}) =>
      all("SELECT * FROM inbox WHERE (? IS NULL OR account_id = ?) ORDER BY id DESC LIMIT ?", accountId ?? null, accountId ?? null, limit),
    countSince: (iso) => one("SELECT COUNT(*) AS n FROM inbox WHERE received_at >= ? AND reason != 'gmail_forwarding_confirmation'", iso).n,
  };

  // ---------- admins and their sessions
  const toAdmin = (r) =>
    r && {
      id: r.id,
      email: r.email,
      name: r.name,
      passwordHash: r.password_hash,
      totpEnabled: Boolean(r.totp_secret_enc),
      totpLastStep: r.totp_last_step,
      mustChangePassword: r.must_change_password === 1,
      lockedUntil: r.locked_until,
      createdAt: r.created_at,
      lastLoginAt: r.last_login_at,
    };
  const admins = {
    count: () => one("SELECT COUNT(*) AS n FROM admins").n,
    list: () => all("SELECT * FROM admins ORDER BY created_at").map(toAdmin),
    get: (id) => toAdmin(one("SELECT * FROM admins WHERE id = ?", id)),
    byEmail: (email) => toAdmin(one("SELECT * FROM admins WHERE email = ?", String(email).trim().toLowerCase())),
    create({ email, name = null, passwordHash, mustChangePassword = false }) {
      const id = newId("adm");
      run(
        "INSERT INTO admins (id, email, name, password_hash, must_change_password, created_at) VALUES (?,?,?,?,?,?)",
        id,
        String(email).trim().toLowerCase(),
        name,
        passwordHash,
        mustChangePassword ? 1 : 0,
        now(),
      );
      return admins.get(id);
    },
    remove(id) {
      run("DELETE FROM sessions WHERE admin_id = ?", id);
      return run("DELETE FROM admins WHERE id = ?", id).changes === 1;
    },
    setPassword: (id, passwordHash) => run("UPDATE admins SET password_hash = ?, must_change_password = 0 WHERE id = ?", passwordHash, id),
    totpSecret(id) {
      const r = one("SELECT totp_secret_enc FROM admins WHERE id = ?", id);
      return r?.totp_secret_enc ? decrypt(masterKey, r.totp_secret_enc) : null;
    },
    setTotp: (id, secret, step) =>
      run("UPDATE admins SET totp_secret_enc = ?, totp_last_step = ? WHERE id = ?", secret ? encrypt(masterKey, secret) : null, step ?? -1, id),
    /** Records the time step of a code just accepted; false if it (or a later one) was already used. */
    useTotpStep: (id, step) => run("UPDATE admins SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?", step, id, step).changes === 1,
    recordFailure(id, lockMinutes = 15, maxAttempts = 8) {
      run("UPDATE admins SET failed_attempts = failed_attempts + 1 WHERE id = ?", id);
      const r = one("SELECT failed_attempts FROM admins WHERE id = ?", id);
      if (r && r.failed_attempts >= maxAttempts) {
        run("UPDATE admins SET locked_until = ?, failed_attempts = 0 WHERE id = ?", new Date(Date.now() + lockMinutes * 60_000).toISOString(), id);
      }
    },
    recordLogin: (id) => run("UPDATE admins SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?", now(), id),
  };

  const SESSION_HOURS = 12;
  const sessions = {
    /** Returns the raw token (for the cookie). Only its hash is stored. */
    create(adminId, stage, ip) {
      const token = randomToken(32);
      run(
        "INSERT INTO sessions (id_hash, admin_id, csrf, stage, created_at, expires_at, ip) VALUES (?,?,?,?,?,?,?)",
        sha256(token),
        adminId,
        randomToken(24),
        stage,
        now(),
        new Date(Date.now() + SESSION_HOURS * 3600_000).toISOString(),
        ip ?? null,
      );
      return token;
    },
    get(token) {
      if (!token) return null;
      const r = one("SELECT * FROM sessions WHERE id_hash = ? AND expires_at > ?", sha256(token), now());
      if (!r) return null;
      // Sliding expiry, refreshed at most once a minute.
      const exp = new Date(Date.now() + SESSION_HOURS * 3600_000);
      if (new Date(r.expires_at).getTime() < exp.getTime() - 60_000) run("UPDATE sessions SET expires_at = ? WHERE id_hash = ?", exp.toISOString(), r.id_hash);
      return {
        adminId: r.admin_id,
        csrf: r.csrf,
        stage: r.stage,
        pendingTotp: r.pending_totp_enc ? decrypt(masterKey, r.pending_totp_enc) : null,
        createdAt: r.created_at,
      };
    },
    setStage: (token, stage) => run("UPDATE sessions SET stage = ? WHERE id_hash = ?", stage, sha256(token)),
    setPendingTotp: (token, secret) =>
      run("UPDATE sessions SET pending_totp_enc = ? WHERE id_hash = ?", secret ? encrypt(masterKey, secret) : null, sha256(token)),
    destroy: (token) => run("DELETE FROM sessions WHERE id_hash = ?", sha256(token)),
    destroyAllFor: (adminId, exceptToken) => run("DELETE FROM sessions WHERE admin_id = ? AND id_hash != ?", adminId, exceptToken ? sha256(exceptToken) : ""),
  };

  const audit = {
    add: (adminEmail, action, target = null, detail = null) =>
      run("INSERT INTO audit (at, admin_email, action, target, detail) VALUES (?,?,?,?,?)", now(), adminEmail, action, target, detail),
    list: (limit = 200) => all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", limit),
  };

  return {
    db,
    settings,
    apps,
    keys,
    accounts,
    payments,
    charges,
    deliveries,
    inbox,
    admins,
    sessions,
    audit,
    /** Retention: rejected emails 7 days, finished deliveries 30 days, audit a year, payments `paymentDays`. */
    cleanup(paymentDays, at = Date.now()) {
      const ago = (days) => new Date(at - days * 86400000).toISOString();
      run("DELETE FROM inbox WHERE received_at < ?", ago(7));
      run("DELETE FROM deliveries WHERE status != 'pending' AND created_at < ?", ago(30));
      run("DELETE FROM payments WHERE received_at < ?", ago(paymentDays));
      run("DELETE FROM charges WHERE status != 'pending' AND created_at < ?", ago(paymentDays));
      run("DELETE FROM sessions WHERE expires_at < ?", new Date(at).toISOString());
      run("DELETE FROM audit WHERE at < ?", ago(365));
    },
    close: () => db.close(),
  };
}
