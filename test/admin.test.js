import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openStore } from "../src/store.js";
import { createApp } from "../src/app.js";
import { importLegacySources } from "../src/importLegacy.js";
import { validateSources } from "../src/config.js";
import { masterKeyFrom, totpAt, totpStep, decrypt } from "../src/security.js";
import { deliver } from "../worker/src/index.js";
import { OWNER, buildEmail, gmailConfirmationEmail, nequiNegociosEmail, resolverFor } from "./fixtures.js";

const INGEST_SECRET = "i".repeat(40);
const masterKey = masterKeyFrom("cd".repeat(32));
let server, base, store;
const ctx = { setupToken: "setup-token-1234567890" };
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${srv.address().port}`)));

before(async () => {
  store = openStore(":memory:", { masterKey });
  const config = { ingestSecret: INGEST_SECRET, masterKey, publicUrl: null, legacySources: [], retentionDays: 180 };
  server = createServer(createApp({ store, config, resolver: resolverFor(), log: () => {}, get setupToken() { return ctx.setupToken; } }));
  base = await listen(server);
});
after(() => {
  server.close();
  store.close();
});

/** A tiny browser: keeps cookies, doesn't follow redirects, reads the CSRF token from the page. */
function browser() {
  const jar = new Map();
  const b = {
    async req(path, { method = "GET", form, headers = {}, body } = {}) {
      const h = { ...headers, cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") };
      let payload = body;
      if (form) {
        h["content-type"] = "application/x-www-form-urlencoded";
        payload = new URLSearchParams(form).toString();
      }
      const res = await fetch(base + path, { method, headers: h, body: payload, redirect: "manual" });
      for (const c of res.headers.getSetCookie()) {
        const [pair] = c.split(";");
        const i = pair.indexOf("=");
        const v = decodeURIComponent(pair.slice(i + 1));
        if (/Max-Age=0/.test(c)) jar.delete(pair.slice(0, i));
        else jar.set(pair.slice(0, i), v);
      }
      const text = await res.text();
      b.last = text;
      const token = text.match(/name="_csrf" value="([^"]+)"/)?.[1];
      if (token) b.token = token;
      return { status: res.status, location: res.headers.get("location"), text, headers: res.headers };
    },
    // The session's CSRF token, as last seen in a page (it doesn't change during a session).
    csrf: () => b.token,
    jar,
  };
  return b;
}

const code = (secret, offset = 0) => totpAt(secret, totpStep() + offset);
let adminSecret;

test("first start: no admin yet → setup needs the token", async () => {
  const b = browser();
  assert.match((await b.req("/")).text, /enlace de configuración/);
  assert.equal((await b.req("/setup?token=wrong")).status, 403);
  assert.equal((await b.req("/login")).status, 200, "login page renders but there's nobody to log in");
});

test("setup creates the first admin and forces 2-step setup", async () => {
  const b = browser();
  await b.req(`/setup?token=${ctx.setupToken}`);
  let r = await b.req(`/setup?token=${ctx.setupToken}`, { method: "POST", form: { _csrf: b.csrf(), email: "Admin@Example.com", password: "corta", password2: "corta" } });
  assert.equal(r.status, 400);
  assert.match(r.text, /al menos 10/);
  r = await b.req(`/setup?token=${ctx.setupToken}`, { method: "POST", form: { _csrf: "otro", email: "admin@example.com", password: "una-clave-larga", password2: "una-clave-larga" } });
  assert.match(r.text, /venció/, "CSRF on setup");
  r = await b.req(`/setup?token=${ctx.setupToken}`, { method: "POST", form: { _csrf: b.csrf(), email: "Admin@Example.com", password: "una-clave-larga", password2: "una-clave-larga" } });
  assert.equal(r.location, "/login/2fa/setup");
  assert.equal((await b.req("/")).location, "/login/2fa/setup", "no access before 2-step setup");
  r = await b.req("/login/2fa/setup");
  assert.match(r.text, /<svg/, "QR shown");
  const secret = r.text.match(/data-copy="([A-Z2-7]{32})"/)[1];
  r = await b.req("/login/2fa/setup", { method: "POST", form: { _csrf: b.csrf(), code: "000000" } });
  assert.equal(r.status, 400);
  r = await b.req("/login/2fa/setup", { method: "POST", form: { _csrf: b.csrf(), code: code(secret) } });
  assert.equal(r.location, "/");
  adminSecret = secret;
  assert.equal((await b.req("/")).status, 200);
  assert.equal((await b.req(`/setup?token=${ctx.setupToken}`)).location, "/login", "setup closes once an admin exists");
  assert.equal(store.admins.byEmail("admin@example.com").totpEnabled, true);
});

let adminBrowser = null;
/** One signed-in admin browser for the whole file: every login needs a fresh 2-step code (codes can't be reused). */
async function loggedIn() {
  if (adminBrowser) return adminBrowser;
  const b = browser();
  await b.req("/login");
  let r = await b.req("/login", { method: "POST", form: { _csrf: b.csrf(), email: "admin@example.com", password: "una-clave-larga" } });
  assert.equal(r.location, "/login/2fa");
  await b.req("/login/2fa");
  // The current step was used by the setup; the next one is accepted (clock drift window).
  r = await b.req("/login/2fa", { method: "POST", form: { _csrf: b.csrf(), code: code(adminSecret, 1) } });
  assert.equal(r.location, "/", "logged in with the next code");
  adminBrowser = b;
  return b;
}

test("login: wrong password, password only isn't enough, code can't be reused", async () => {
  const b = browser();
  await b.req("/login");
  let r = await b.req("/login", { method: "POST", form: { _csrf: b.csrf(), email: "admin@example.com", password: "mala-clave-123" } });
  assert.equal(r.status, 400);
  assert.match(r.text, /incorrectos/);
  r = await b.req("/login", { method: "POST", form: { _csrf: b.csrf(), email: "admin@example.com", password: "una-clave-larga" } });
  assert.equal(r.location, "/login/2fa");
  assert.equal((await b.req("/apps")).location, "/login/2fa", "password alone gives no access");
  await b.req("/login/2fa");
  r = await b.req("/login/2fa", { method: "POST", form: { _csrf: b.csrf(), code: "123456" } });
  assert.equal(r.status, 400);
  const used = store.admins.byEmail("admin@example.com").totpLastStep;
  r = await b.req("/login/2fa", { method: "POST", form: { _csrf: b.csrf(), code: totpAt(adminSecret, used) } });
  assert.equal(r.status, 400, "an already used code is refused");
  const b2 = await loggedIn();
  assert.equal((await b2.req("/apps")).status, 200);
});

let appId, accountId, apiKey;

test("apps: create, CSRF required, webhook secret encrypted, API key shown once and only hashed", async () => {
  const b = await loggedIn();
  await b.req("/apps");
  let r = await b.req("/apps", { method: "POST", form: { _csrf: "nope", name: "Tienda" } });
  assert.equal(r.status, 403, "no CSRF token → refused");
  r = await b.req("/apps", { method: "POST", form: { _csrf: b.csrf(), name: "Tienda", webhookUrl: "javascript:alert(1)" } });
  assert.equal(r.status, 400);
  r = await b.req("/apps", { method: "POST", form: { _csrf: b.csrf(), name: "Tienda <b>x</b>", webhookUrl: "https://tienda.example.com/hook" } });
  appId = r.location.match(/\/apps\/([\w-]+)/)[1];
  r = await b.req(`/apps/${appId}`);
  assert.match(r.text, /Tienda &lt;b&gt;x&lt;\/b&gt;/, "names are escaped");
  const row = store.db.prepare("SELECT webhook_secret_enc FROM apps WHERE id = ?").get(appId);
  assert.ok(row.webhook_secret_enc.startsWith("v1."), "secret stored encrypted");
  assert.match(decrypt(masterKey, row.webhook_secret_enc), /^whsec_/);
  r = await b.req(`/apps/${appId}/keys`, { method: "POST", form: { _csrf: b.csrf(), name: "producción" } });
  apiKey = r.text.match(/data-copy="(prk_[^"]+)"/)[1];
  assert.match(r.text, /no se volverá a mostrar/);
  assert.equal(store.db.prepare("SELECT COUNT(*) AS n FROM api_keys WHERE hash LIKE ?").get(`%${apiKey}%`).n, 0, "key not stored in clear");
  assert.equal((await fetch(`${base}/v1/payments`, { headers: { Authorization: `Bearer ${apiKey}` } })).status, 200);
  r = await b.req(`/apps/${appId}`);
  assert.doesNotMatch(r.text, new RegExp(apiKey), "not shown again");
});

test("receiving accounts: generated address, setup guide, Gmail code and first notice", async () => {
  const b = await loggedIn();
  await b.req("/accounts/new");
  let r = await b.req("/accounts", { method: "POST", form: { _csrf: b.csrf(), appId, name: "Nequi de Ana", ownerEmails: OWNER, banks: "nequi_negocios" } });
  assert.equal(r.status, 400, "no inbound domain yet");
  assert.match(r.text, /dominio de recepción/);
  await b.req("/settings");
  r = await b.req("/settings", { method: "POST", form: { _csrf: b.csrf(), inboundDomain: "pagos.example.com", retentionDays: "180" } });
  assert.equal(r.location, "/settings?ok=saved");
  await b.req("/accounts/new");
  r = await b.req("/accounts", { method: "POST", form: { _csrf: b.csrf(), appId, name: "Nequi de Ana", ownerEmails: "no-es-correo", banks: "nequi_negocios" } });
  assert.equal(r.status, 400);
  r = await b.req("/accounts", { method: "POST", form: { _csrf: b.csrf(), appId, name: "Nequi de Ána", ownerEmails: OWNER, banks: "nequi_negocios", tenantRef: "org-42" } });
  accountId = r.location.match(/\/accounts\/([\w-]+)/)[1];
  const account = store.accounts.get(accountId);
  assert.match(account.address, /^nequi-de-ana-[a-z2-9]{6}@pagos\.example\.com$/);
  r = await b.req(`/accounts/${accountId}`);
  assert.match(r.text, /Esperando el correo de Gmail/);
  assert.match(r.text, /notificaciones@nequi\.com\.co/, "filter senders for the chosen banks");
  assert.match(r.text, /data-autorefresh/);

  const send = (raw) => deliver(new Uint8Array(raw), { to: account.address, from: "x@gmail.com" }, { PAGORADAR_URL: base, INGEST_SECRET }, { sleep: async () => {} });
  await send(Buffer.from(buildEmail({ from: "forwarding-noreply@google.com", subject: "(#999000111) Confirmación de reenvío de Gmail", text: "falso" })));
  assert.doesNotMatch((await b.req(`/accounts/${accountId}`)).text, /big">999000111/, "an unsigned 'Gmail' email can't put a code on screen");
  await send(await gmailConfirmationEmail({ subject: "(#112233445) Confirmación de reenvío de Gmail", text: "Para confirmar...", to: account.address }));
  r = await b.req(`/accounts/${accountId}`);
  assert.match(r.text, /112233445/, "the Gmail code appears on the account page");
  await send(await nequiNegociosEmail({ tx: "panel-1" }));
  assert.equal(store.accounts.get(accountId).status, "active");
  r = await b.req(`/accounts/${accountId}`);
  assert.match(r.text, /Recibiendo avisos/);
  assert.match(r.text, /Ana Maria Prueba Lopez/);
  r = await b.req("/payments?q=prueba");
  assert.match(r.text, /Ana Maria Prueba Lopez/);
  const csv = await b.req(`/payments.csv?account=${accountId}`);
  assert.match(csv.headers.get("content-type"), /text\/csv/);
  assert.match(csv.text, /Ana Maria Prueba Lopez/);
  const payments = await (await fetch(`${base}/v1/payments`, { headers: { Authorization: `Bearer ${apiKey}` } })).json();
  assert.equal(payments.payments.length, 1);
  assert.equal(payments.payments[0].accountId, accountId);

  // disable → its notices are refused; can't delete while it has payments
  await b.req(`/accounts/${accountId}`);
  r = await b.req(`/accounts/${accountId}/toggle`, { method: "POST", form: { _csrf: b.csrf() } });
  assert.equal(store.accounts.get(accountId).status, "disabled");
  assert.equal(await send(await nequiNegociosEmail({ tx: "panel-2" })), true);
  assert.equal(store.inbox.list({ limit: 1 })[0].reason, "account_disabled");
  await b.req(`/accounts/${accountId}`);
  r = await b.req(`/accounts/${accountId}/delete`, { method: "POST", form: { _csrf: b.csrf() } });
  assert.match(r.text, /Tiene pagos/);
  await b.req(`/accounts/${accountId}`);
  await b.req(`/accounts/${accountId}/toggle`, { method: "POST", form: { _csrf: b.csrf() } });
  assert.equal(store.accounts.get(accountId).status, "active");
});

test(".eml checker: CSRF header required, reports what would be read", async () => {
  const b = await loggedIn();
  const r0 = await b.req(`/accounts/${accountId}`);
  const csrf = r0.text.match(/data-csrf="([^"]+)"/)[1];
  const raw = await nequiNegociosEmail({ tx: "check-1" });
  let r = await b.req(`/accounts/${accountId}/check`, { method: "POST", body: raw, headers: { "content-type": "message/rfc822" } });
  assert.equal(r.status, 403);
  r = await b.req(`/accounts/${accountId}/check`, { method: "POST", body: raw, headers: { "content-type": "message/rfc822", "x-csrf": csrf } });
  const out = JSON.parse(r.text);
  assert.equal(out.ok, true);
  assert.equal(out.payment.amountCents, 2500000);
  assert.equal(store.payments.search({ accountId }).total, 1, "nothing stored by the checker");
});

test("API key revoke, app deactivation, rotating the webhook secret", async () => {
  const b = await loggedIn();
  const r0 = await b.req(`/apps/${appId}`);
  const keyId = store.keys.listForApp(appId)[0].id;
  await b.req(`/apps/${appId}/keys/${keyId}/revoke`, { method: "POST", form: { _csrf: b.csrf() } });
  assert.equal((await fetch(`${base}/v1/payments`, { headers: { Authorization: `Bearer ${apiKey}` } })).status, 401);
  const before = store.apps.secret(appId);
  await b.req(`/apps/${appId}`);
  const r = await b.req(`/apps/${appId}/rotate`, { method: "POST", form: { _csrf: b.csrf() } });
  const after = store.apps.secret(appId);
  assert.notEqual(before, after);
  assert.match(r.text, new RegExp(after));
  assert.ok(r0.status === 200);
});

test("other admins: temporary password, must change it and set up 2-step; audit log", async () => {
  const b = await loggedIn();
  await b.req("/settings");
  let r = await b.req("/settings/admins", { method: "POST", form: { _csrf: b.csrf(), email: "socio@example.com" } });
  const temp = r.text.match(/data-copy="([\w-]+)"/)[1];
  const s = browser();
  await s.req("/login");
  r = await s.req("/login", { method: "POST", form: { _csrf: s.csrf(), email: "socio@example.com", password: temp } });
  assert.equal(r.location, "/login/2fa/setup", "new admin must set up 2-step first");
  r = await s.req("/login/2fa/setup");
  const secret = r.text.match(/data-copy="([A-Z2-7]{32})"/)[1];
  r = await s.req("/login/2fa/setup", { method: "POST", form: { _csrf: s.csrf(), code: code(secret) } });
  assert.equal((await s.req("/apps")).location, "/me?first=1", "then change the temporary password");
  await s.req("/me");
  r = await s.req("/me/password", { method: "POST", form: { _csrf: s.csrf(), current: temp, password: "nueva-clave-larga", password2: "nueva-clave-larga" } });
  assert.equal(r.location, "/me?ok=password");
  assert.equal((await s.req("/apps")).status, 200);
  r = await b.req("/audit");
  for (const action of ["Creó la app", "Creó una API key", "Creó la cuenta receptora", "Revocó una API key", "Cambió el secreto del webhook", "Agregó un administrador"]) {
    assert.match(r.text, new RegExp(action));
  }
});

test("charges: pay key on the account, list, cancel", async () => {
  const b = await loggedIn();
  const app = store.apps.create({ name: "Cobros SaaS" });
  const acc = store.accounts.create({ appId: app.id, name: "Caja", ownerEmails: [OWNER], banks: ["nequi"], domain: "pagos.example.com" });
  await b.req(`/accounts/${acc.id}`);
  let r = await b.req(`/accounts/${acc.id}`, { method: "POST", form: { _csrf: b.csrf(), name: "Caja", ownerEmails: OWNER, banks: "nequi", tenantRef: "", payKey: "3001234567", payHolder: "Caja Prueba" } });
  assert.equal(r.location, `/accounts/${acc.id}?ok=saved`);
  assert.equal(store.accounts.get(acc.id).payKey, "3001234567");
  const c = store.charges.create({ appId: app.id, accountId: acc.id, baseCents: 1_000_000, amountCents: 1_000_100, description: "Mensualidad", expiresAt: new Date(Date.now() + 600_000).toISOString() });
  r = await b.req("/charges");
  assert.match(r.text, /Mensualidad/);
  assert.match(r.text, /Esperando pago/);
  assert.match(r.text, new RegExp(`/c/${c.id}`));
  r = await b.req(`/charges/${c.id}/cancel`, { method: "POST", form: { _csrf: b.csrf() } });
  assert.equal(r.location, "/charges?ok=canceled");
  assert.equal(store.charges.get(c.id).status, "canceled");
  assert.match((await b.req("/charges?status=canceled")).text, /Cancelado/);

  // A payment that came with another amount: "Asociar a un cobro" from Pagos.
  const open = store.charges.create({ appId: app.id, accountId: acc.id, baseCents: 2_000_000, amountCents: 2_000_300, description: "Pedido 9", expiresAt: new Date(Date.now() + 600_000).toISOString() });
  const p = store.payments.add(app.id, acc.id, { bank: "nequi", method: "breb", methodText: null, amountCents: 1_999_000, currency: "COP", payerName: "Luis Prueba", payerNameNormalized: "LUIS PRUEBA", payerBank: null, reference: null, transactionId: null, accountHint: null, paidAt: new Date().toISOString(), dkimDomain: "nequi.com.co", dedupeKey: "link-1" });
  r = await b.req("/payments");
  assert.match(r.text, new RegExp(`/payments/${p.id}/link`));
  r = await b.req(`/payments/${p.id}/link`);
  assert.match(r.text, /Pedido 9/);
  r = await b.req(`/payments/${p.id}/link`, { method: "POST", form: { _csrf: b.csrf(), chargeId: open.id } });
  assert.equal(r.location, "/payments?ok=linked");
  const done = store.charges.get(open.id);
  assert.equal(done.status, "paid");
  assert.equal(done.match, "manual");
  assert.equal(done.paidAmount, 19990);
  r = await b.req("/payments?ok=linked");
  assert.match(r.text, /Pagó un cobro/);
  assert.match(r.text, /asociado a mano/);
});

test("logout ends the session; security headers on pages; foreign origin refused", async () => {
  const b = await loggedIn();
  const r = await b.req("/");
  assert.match(r.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.equal(r.headers.get("x-frame-options"), "DENY");
  const evil = await b.req("/apps", { method: "POST", form: { _csrf: b.csrf(), name: "x" }, headers: { origin: "https://evil.example" } });
  assert.equal(evil.status, 403);
  await b.req("/logout", { method: "POST", form: { _csrf: b.csrf() } });
  assert.equal((await b.req("/apps")).location, "/login");
});

test("legacy import: a v1 database and PAGORADAR_SOURCES become an app + account, payments kept", () => {
  const dir = mkdtempSync(join(tmpdir(), "pr-"));
  const path = join(dir, "old.db");
  const old = new DatabaseSync(path);
  old.exec(`CREATE TABLE payments (id TEXT PRIMARY KEY, source TEXT NOT NULL, bank TEXT NOT NULL, method TEXT, method_text TEXT, amount_cents INTEGER NOT NULL, currency TEXT NOT NULL, payer_name TEXT, payer_name_normalized TEXT, payer_bank TEXT, reference TEXT, transaction_id TEXT, account_hint TEXT, paid_at TEXT NOT NULL, received_at TEXT NOT NULL, dkim_domain TEXT, dedupe_key TEXT NOT NULL, UNIQUE (source, dedupe_key));
    INSERT INTO payments VALUES ('pay_old1','ibirifas','nequi_negocios',NULL,NULL,10000,'COP','Ana',NULL,NULL,NULL,NULL,NULL,'2026-10-01T15:00:00.000Z','2026-10-01T15:00:01.000Z',NULL,'k1');`);
  old.close();
  const s2 = openStore(path, { masterKey });
  const sources = validateSources([{ id: "ibirifas", addresses: ["pagos-ibirifas-6eabb7@pagos.edwsystem.com"], ownerEmails: [OWNER], apiKey: "9".repeat(48), webhooks: [{ url: "https://rifas.example.com/api/pagoradar/webhook", secret: "s".repeat(48) }] }]);
  assert.equal(importLegacySources(s2, sources), 1);
  assert.equal(importLegacySources(s2, sources), 0, "only once");
  const app = s2.apps.get("ibirifas");
  assert.equal(app.webhookUrl, "https://rifas.example.com/api/pagoradar/webhook");
  assert.equal(s2.apps.secret("ibirifas"), "s".repeat(48), "same webhook secret");
  assert.equal(s2.keys.appFor("9".repeat(48)).id, "ibirifas", "same API key");
  const acc = s2.accounts.byAddress("pagos-ibirifas-6eabb7@pagos.edwsystem.com");
  assert.ok(acc);
  assert.equal(s2.payments.get("pay_old1").accountId, acc.id, "old payments attached to the account");
  assert.equal(s2.settings.get("inbound_domain"), "pagos.edwsystem.com");
  s2.close();
});
