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

// v4: how a charge got paid (exact amount, the round amount, or by hand) and what the payment brought.
const V4 = `
ALTER TABLE charges ADD COLUMN match_type TEXT;
ALTER TABLE charges ADD COLUMN paid_amount_cents INTEGER;
CREATE INDEX charges_open_base ON charges (account_id, status, base_cents);
`;

// v5: several receiving domains, and other people's Cloudflare accounts (one Worker each, with its own secret, for
// all the domains in that account; cf_account_id NULL = yours, whose Worker signs with INGEST_SECRET). Also people
// who only see some apps (role "client", with "view" or "manage" access per app).
const V5 = `
CREATE TABLE cf_accounts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  secret_enc TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE domains (
  name TEXT PRIMARY KEY,
  cf_account_id TEXT,
  app_ids TEXT,
  created_at TEXT NOT NULL,
  last_email_at TEXT
);
ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';
CREATE TABLE admin_apps (
  admin_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  access TEXT NOT NULL,
  PRIMARY KEY (admin_id, app_id)
);
`;

// v6: passkeys. `id` is the credential id; the public key isn't a secret, so it isn't encrypted.
const V6 = `
CREATE TABLE passkeys (
  id TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL,
  name TEXT NOT NULL,
  public_key TEXT NOT NULL,
  alg INTEGER NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX passkeys_admin ON passkeys (admin_id);
`;

// v7: warn when an account stops getting notices (0 hours = never), and invitations by link instead of temporary passwords.
const V7 = `
ALTER TABLE accounts ADD COLUMN silent_after_hours INTEGER NOT NULL DEFAULT 168;
ALTER TABLE accounts ADD COLUMN silent_alerted_at TEXT;
ALTER TABLE admins ADD COLUMN invite_hash TEXT;
ALTER TABLE admins ADD COLUMN invite_expires_at TEXT;
`;

const INVITE_DAYS = 7;

export const ROLES = ["admin", "client"];
export const ACCESS_LEVELS = ["view", "manage"];

/** `col IN (?,?,…)` for a list of ids; an empty list matches nothing. */
const inList = (col, ids) => (ids.length ? { sql: `${col} IN (${ids.map(() => "?").join(",")})`, args: ids } : { sql: "0", args: [] });

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
  for (const [v, sql] of [[2, V2], [3, V3], [4, V4], [5, V5], [6, V6], [7, V7]]) {
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

  // ---------- someone else's Cloudflare account: one Worker there, signing with this secret, serves all its domains
  const toCf = (r) => r && { id: r.id, name: r.name, createdAt: r.created_at };
  const newIngestSecret = () => `ing_${randomToken(32)}`;
  const cfAccounts = {
    list: () => all("SELECT * FROM cf_accounts ORDER BY created_at").map(toCf),
    get: (id) => toCf(one("SELECT * FROM cf_accounts WHERE id = ?", id)),
    create(name) {
      const id = `cf_${randomCode(10)}`;
      run("INSERT INTO cf_accounts (id, name, secret_enc, created_at) VALUES (?,?,?,?)", id, name, encrypt(masterKey, newIngestSecret()), now());
      return cfAccounts.get(id);
    },
    /** What the Worker in that account signs its emails with (INGEST_SECRET there). */
    secret(id) {
      const r = one("SELECT secret_enc FROM cf_accounts WHERE id = ?", id);
      return r ? decrypt(masterKey, r.secret_enc) : null;
    },
    rotateSecret(id) {
      const secret = newIngestSecret();
      run("UPDATE cf_accounts SET secret_enc = ? WHERE id = ?", encrypt(masterKey, secret), id);
      return secret;
    },
    /** Forgets the account once none of its domains is left. */
    removeIfUnused: (id) => run("DELETE FROM cf_accounts WHERE id = ? AND NOT EXISTS (SELECT 1 FROM domains WHERE cf_account_id = ?)", id, id).changes === 1,
  };

  // ---------- receiving domains. The default one is the "inbound_domain" setting (older versions only had that).
  const toDomain = (r) =>
    r && {
      name: r.name,
      cfAccountId: r.cf_account_id,
      appIds: r.app_ids ? json(r.app_ids, []) : null,
      createdAt: r.created_at,
      lastEmailAt: r.last_email_at,
      isDefault: r.name === settings.get("inbound_domain"),
    };
  const domains = {
    /** Every domain, the default first. The default (set by older versions, the env or the legacy import) gets its row here. */
    list() {
      const def = settings.get("inbound_domain");
      if (def && !one("SELECT 1 FROM domains WHERE name = ?", def)) domains.create(def);
      return all("SELECT * FROM domains ORDER BY name = ? DESC, created_at", def ?? "").map(toDomain);
    },
    get: (name) => toDomain(one("SELECT * FROM domains WHERE name = ?", String(name ?? "").trim().toLowerCase())),
    /** The domains an app may create accounts in (`appIds` null = every app), the default first. */
    forApp: (appId) => domains.list().filter((d) => !d.appIds || d.appIds.includes(appId)),
    /** `cfAccountId` null: the domain is in your Cloudflare account, served by your Worker. */
    create(name, { appIds = null, cfAccountId = null } = {}) {
      const n = String(name).trim().toLowerCase();
      run("INSERT INTO domains (name, cf_account_id, app_ids, created_at) VALUES (?,?,?,?)", n, cfAccountId, appIds ? JSON.stringify(appIds) : null, now());
      if (!settings.get("inbound_domain")) settings.set("inbound_domain", n);
      return domains.get(n);
    },
    setApps: (name, appIds) => run("UPDATE domains SET app_ids = ? WHERE name = ?", appIds ? JSON.stringify(appIds) : null, name).changes === 1,
    setCfAccount: (name, cfAccountId) => run("UPDATE domains SET cf_account_id = ? WHERE name = ?", cfAccountId, name).changes === 1,
    inCfAccount: (cfAccountId) => all("SELECT * FROM domains WHERE cf_account_id IS ? ORDER BY created_at", cfAccountId).map(toDomain),
    touch: (name) => run("UPDATE domains SET last_email_at = ? WHERE name = ?", now(), name),
    accountCount: (name) => one("SELECT COUNT(*) AS n FROM accounts WHERE address LIKE ?", `%@${name}`).n,
    remove: (name) => run("DELETE FROM domains WHERE name = ?", name).changes === 1,
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
      silentAfterHours: r.silent_after_hours,
      silentAlertedAt: r.silent_alerted_at,
      // Working, but no valid notice in too long: a filter broke, the bank changed its email, or nobody paid.
      silent:
        !r.disabled_at && r.status === "active" && r.silent_after_hours > 0 && Boolean(r.last_email_at) &&
        Date.now() - new Date(r.last_email_at).getTime() > r.silent_after_hours * 3600_000,
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
    update(id, { name, ownerEmails, banks, tenantRef, payKey, payHolder, silentAfterHours }) {
      const cur = one("SELECT * FROM accounts WHERE id = ?", id);
      if (!cur) return null;
      run(
        "UPDATE accounts SET name = ?, owner_emails = ?, banks = ?, tenant_ref = ?, pay_key = ?, pay_holder = ?, silent_after_hours = ? WHERE id = ?",
        name ?? cur.name,
        ownerEmails ? JSON.stringify(ownerEmails.map((e) => e.trim().toLowerCase())) : cur.owner_emails,
        banks ? JSON.stringify(banks) : cur.banks,
        tenantRef === undefined ? cur.tenant_ref : tenantRef,
        payKey === undefined ? cur.pay_key : payKey,
        payHolder === undefined ? cur.pay_holder : payHolder,
        silentAfterHours === undefined ? cur.silent_after_hours : silentAfterHours,
        id,
      );
      return accounts.get(id);
    },
    setDisabled: (id, disabled) => run("UPDATE accounts SET disabled_at = ? WHERE id = ?", disabled ? now() : null, id).changes === 1,
    recordConfirmation: (id, code, link) =>
      run("UPDATE accounts SET confirmation_code = ?, confirmation_link = ?, confirmation_at = ? WHERE id = ?", code, link, now(), id),
    /** A genuine bank email arrived: the account works. Returns true the first time. */
    markActive(id) {
      run("UPDATE accounts SET last_email_at = ?, silent_alerted_at = NULL WHERE id = ?", now(), id);
      return run("UPDATE accounts SET status = 'active' WHERE id = ? AND status = 'pending'", id).changes === 1;
    },
    /** Accounts that went silent and nobody has been told yet. */
    silentToAlert: () => accounts.list().filter((a) => a.silent && !a.silentAlertedAt),
    markSilentAlerted: (id) => run("UPDATE accounts SET silent_alerted_at = ? WHERE id = ?", now(), id),
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
    /** `appIds`: only these apps (what a client may see); undefined = all. */
    search({ appId, appIds, accountId, bank, q, from, to, limit = 50, offset = 0 } = {}) {
      const where = [];
      const args = [];
      if (appId) where.push("source = ?"), args.push(appId);
      if (appIds) {
        const f = inList("source", appIds);
        where.push(f.sql), args.push(...f.args);
      }
      if (accountId) where.push("account_id = ?"), args.push(accountId);
      if (bank) where.push("bank = ?"), args.push(bank);
      if (q) where.push("(payer_name_normalized LIKE ? OR reference LIKE ?)"), args.push(`%${String(q).toUpperCase()}%`, `%${q}%`);
      if (from) where.push("paid_at >= ?"), args.push(from);
      if (to) where.push("paid_at < ?"), args.push(to);
      const sql = `FROM payments ${where.length ? `WHERE ${where.join(" AND ")}` : ""}`;
      const sum = one(`SELECT COUNT(*) AS n, COALESCE(SUM(amount_cents), 0) AS cents ${sql}`, ...args);
      return {
        total: sum.n,
        cents: sum.cents,
        rows: all(`SELECT * ${sql} ORDER BY paid_at DESC LIMIT ? OFFSET ?`, ...args, limit, offset).map(toPayment),
      };
    },
    stats(sinceIso, appIds) {
      const f = appIds ? inList("source", appIds) : { sql: "1", args: [] };
      return one(`SELECT COUNT(*) AS n, COALESCE(SUM(amount_cents), 0) AS cents FROM payments WHERE received_at >= ? AND ${f.sql}`, sinceIso, ...f.args);
    },
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
      match: r.match_type,
      paidAmount: r.paid_amount_cents == null ? null : r.paid_amount_cents / 100,
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      paidAt: r.paid_at,
      canceledAt: r.canceled_at,
    };
  const chargeWhere = ({ appId, appIds, accountId, status, reference, tenantRef, q }) => {
    const where = [];
    const args = [];
    if (appId) where.push("c.app_id = ?"), args.push(appId);
    if (appIds) {
      const f = inList("c.app_id", appIds);
      where.push(f.sql), args.push(...f.args);
    }
    if (accountId) where.push("c.account_id = ?"), args.push(accountId);
    if (status) where.push("c.status = ?"), args.push(status);
    if (reference) where.push("c.reference = ?"), args.push(reference);
    if (tenantRef) where.push("a.tenant_ref = ?"), args.push(tenantRef);
    if (q) where.push("(c.description LIKE ? OR c.reference LIKE ? OR c.payer_name LIKE ?)"), args.push(`%${q}%`, `%${q}%`, `%${q}%`);
    return { sql: `FROM charges c LEFT JOIN accounts a ON a.id = c.account_id ${where.length ? `WHERE ${where.join(" AND ")}` : ""}`, args };
  };
  const charges = {
    /** How many charges in each status, with the other filters applied. */
    countByStatus(filters = {}) {
      const { sql, args } = chargeWhere({ ...filters, status: undefined });
      const out = { pending: 0, paid: 0, expired: 0, canceled: 0 };
      for (const r of all(`SELECT c.status AS status, COUNT(*) AS n ${sql} GROUP BY c.status`, ...args)) out[r.status] = r.n;
      return out;
    },
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
    candidates: (accountId, amountCents, paidAt, slackMs, column = "amount_cents") => {
      const t = new Date(paidAt).getTime();
      return all(
        `SELECT * FROM charges WHERE account_id = ? AND ${column === "base_cents" ? "base_cents" : "amount_cents"} = ? AND status IN ('pending','expired') AND created_at <= ? AND expires_at >= ? ORDER BY created_at`,
        accountId,
        amountCents,
        new Date(t + slackMs).toISOString(),
        new Date(t - slackMs).toISOString(),
      ).map(toCharge);
    },
    /** Charges of an account a payment could be linked to by hand: open, or expired/canceled in the last `days`, closest amount first. */
    linkable: (accountId, amountCents, days = 7, limit = 20) =>
      all(
        "SELECT * FROM charges WHERE account_id = ? AND (status = 'pending' OR (status IN ('expired','canceled') AND created_at > ?)) ORDER BY ABS(amount_cents - ?), created_at DESC LIMIT ?",
        accountId,
        new Date(Date.now() - days * 86400_000).toISOString(),
        amountCents,
        limit,
      ).map(toCharge),
    /**
     * Links the payment; false when the charge was already settled or the payment already pays another charge.
     * `match`: "exact", "approximate" (paid the round amount) or "manual". A canceled charge only by hand.
     */
    markPaid(id, payment, match = "exact", at = now()) {
      const states = match === "manual" ? "('pending','expired','canceled')" : "('pending','expired')";
      try {
        return (
          run(
            `UPDATE charges SET status = 'paid', payment_id = ?, paid_at = ?, match_type = ?, paid_amount_cents = ?, canceled_at = NULL WHERE id = ? AND status IN ${states}`,
            payment.id,
            at,
            match,
            payment.amountCents,
            id,
          ).changes === 1
        );
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
    search({ appId, accountId, status, reference, tenantRef, q, limit = 50, offset = 0 } = {}) {
      const { sql, args } = chargeWhere({ appId, accountId, status, reference, tenantRef, q });
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
    /**
     * The deliveries due at `at`, pushed `leaseMs` into the future so a concurrent deliverDue (the 15 s loop and the
     * one each ingested email starts) doesn't pick them up too. A send that never finishes (crash) is retried after it.
     */
    claimDue(at = now(), limit = 20, leaseMs = 120_000) {
      const due = all("SELECT * FROM deliveries WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT ?", at, limit);
      const until = new Date(Date.parse(at) + leaseMs).toISOString();
      for (const d of due) run("UPDATE deliveries SET next_attempt_at = ? WHERE id = ?", until, d.id);
      return due;
    },
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
    get: (id) => one("SELECT * FROM deliveries WHERE id = ?", id),
    retry: (id, at = now()) => run("UPDATE deliveries SET status = 'pending', next_attempt_at = ? WHERE id = ? AND status != 'delivered'", at, id).changes === 1,
    countFailed(appIds) {
      const f = appIds ? inList("source", appIds) : { sql: "1", args: [] };
      return one(`SELECT COUNT(*) AS n FROM deliveries WHERE status = 'failed' AND ${f.sql}`, ...f.args).n;
    },
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
    /** `appIds`: only emails of these apps' accounts (what a client may see); undefined = all. */
    list({ accountId, appIds, limit = 100 } = {}) {
      const f = appIds ? inList("source", appIds) : { sql: "1", args: [] };
      return all(`SELECT * FROM inbox WHERE (? IS NULL OR account_id = ?) AND ${f.sql} ORDER BY id DESC LIMIT ?`, accountId ?? null, accountId ?? null, ...f.args, limit);
    },
    /** Genuine bank notices we couldn't read: most likely the bank changed its email. */
    countUnrecognizedSince(iso, appIds) {
      const f = appIds ? inList("source", appIds) : { sql: "1", args: [] };
      return one(`SELECT COUNT(*) AS n FROM inbox WHERE received_at >= ? AND reason = 'unrecognized' AND ${f.sql}`, iso, ...f.args).n;
    },
    countSince(iso, appIds) {
      const f = appIds ? inList("source", appIds) : { sql: "1", args: [] };
      return one(`SELECT COUNT(*) AS n FROM inbox WHERE received_at >= ? AND reason != 'gmail_forwarding_confirmation' AND ${f.sql}`, iso, ...f.args).n;
    },
  };

  // ---------- admins and their sessions
  const toAdmin = (r) =>
    r && {
      id: r.id,
      email: r.email,
      name: r.name,
      role: r.role ?? "admin",
      invitePending: Boolean(r.invite_hash),
      inviteExpiresAt: r.invite_expires_at,
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
    create({ email, name = null, passwordHash, mustChangePassword = false, role = "admin" }) {
      const id = newId("adm");
      run(
        "INSERT INTO admins (id, email, name, password_hash, must_change_password, role, created_at) VALUES (?,?,?,?,?,?,?)",
        id,
        String(email).trim().toLowerCase(),
        name,
        passwordHash,
        mustChangePassword ? 1 : 0,
        ROLES.includes(role) ? role : "client",
        now(),
      );
      return admins.get(id);
    },
    /** A new one-time link for this person to choose their password; replaces any earlier one. Returns its token. */
    newInvite(id) {
      const token = randomToken(32);
      run("UPDATE admins SET invite_hash = ?, invite_expires_at = ? WHERE id = ?", sha256(token), new Date(Date.now() + INVITE_DAYS * 86400_000).toISOString(), id);
      return token;
    },
    /** Whose invitation this is, if it's still good. */
    byInvite: (token) => toAdmin(one("SELECT * FROM admins WHERE invite_hash = ? AND invite_expires_at > ?", sha256(String(token ?? "")), now())),
    acceptInvite: (id, name, passwordHash) =>
      run("UPDATE admins SET name = COALESCE(?, name), password_hash = ?, must_change_password = 0, invite_hash = NULL, invite_expires_at = NULL WHERE id = ?", name, passwordHash, id),
    /** An admin sees everything; a client only the apps in `access` (an admin's own grants are dropped). */
    setRole(id, role) {
      if (!ROLES.includes(role)) return false;
      if (role === "admin") run("DELETE FROM admin_apps WHERE admin_id = ?", id);
      return run("UPDATE admins SET role = ? WHERE id = ?", role, id).changes === 1;
    },
    remove(id) {
      run("DELETE FROM sessions WHERE admin_id = ?", id);
      run("DELETE FROM admin_apps WHERE admin_id = ?", id);
      run("DELETE FROM passkeys WHERE admin_id = ?", id);
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

  // ---------- what each client may do with each app: "view" or "manage"
  const access = {
    /** { appId: "view" | "manage" } for one person. */
    forAdmin: (adminId) => Object.fromEntries(all("SELECT app_id, access FROM admin_apps WHERE admin_id = ?", adminId).map((r) => [r.app_id, r.access])),
    /** `level` null removes the access. */
    set(adminId, appId, level) {
      if (!level) return run("DELETE FROM admin_apps WHERE admin_id = ? AND app_id = ?", adminId, appId);
      if (!ACCESS_LEVELS.includes(level)) throw new Error(`acceso desconocido: ${level}`);
      return run("INSERT INTO admin_apps (admin_id, app_id, access) VALUES (?,?,?) ON CONFLICT(admin_id, app_id) DO UPDATE SET access = excluded.access", adminId, appId, level);
    },
  };

  // ---------- passkeys: another way in, instead of password + 2-step code
  const toPasskey = (r) =>
    r && {
      id: r.id,
      adminId: r.admin_id,
      name: r.name,
      publicKey: r.public_key,
      alg: r.alg,
      signCount: r.sign_count,
      transports: json(r.transports, []),
      createdAt: r.created_at,
      lastUsedAt: r.last_used_at,
    };
  const passkeys = {
    listFor: (adminId) => all("SELECT * FROM passkeys WHERE admin_id = ? ORDER BY created_at", adminId).map(toPasskey),
    get: (id) => toPasskey(one("SELECT * FROM passkeys WHERE id = ?", id)),
    /** False when that credential is already registered. */
    add({ id, adminId, name, publicKey, alg, signCount, transports }) {
      return run("INSERT OR IGNORE INTO passkeys (id, admin_id, name, public_key, alg, sign_count, transports, created_at) VALUES (?,?,?,?,?,?,?,?)", id, adminId, name, publicKey, alg, signCount, JSON.stringify(transports ?? []), now()).changes === 1;
    },
    recordUse: (id, signCount) => run("UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?", signCount, now(), id),
    remove: (id, adminId) => run("DELETE FROM passkeys WHERE id = ? AND admin_id = ?", id, adminId).changes === 1,
    removeAllFor: (adminId) => run("DELETE FROM passkeys WHERE admin_id = ?", adminId).changes,
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
    cfAccounts,
    domains,
    apps,
    keys,
    accounts,
    payments,
    charges,
    deliveries,
    inbox,
    admins,
    access,
    passkeys,
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
