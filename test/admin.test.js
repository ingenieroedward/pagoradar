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
  const empty = await b.req("/");
  assert.match(empty.text, /Primeros pasos/);
  assert.match(empty.text, /href="\/domains">Agregar dominio/, "the next thing to do");
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
  await b.req("/domains");
  r = await b.req("/domains", { method: "POST", form: { _csrf: b.csrf(), name: "no es dominio" } });
  assert.equal(r.status, 400);
  r = await b.req("/domains", { method: "POST", form: { _csrf: b.csrf(), name: "Pagos.Example.com" } });
  assert.equal(r.location, "/domains/pagos.example.com?ok=created");
  assert.equal(store.settings.get("inbound_domain"), "pagos.example.com", "the first domain is the default");
  r = await b.req("/settings", { method: "POST", form: { _csrf: b.csrf(), retentionDays: "180" } });
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
  assert.match(r.text, /data-copy="112233445"/, "with a button to copy it");
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

test("other admins: invitation by link, then a password and 2-step; audit log", async () => {
  const b = await loggedIn();
  await b.req("/settings");
  let r = await b.req("/settings/admins", { method: "POST", form: { _csrf: b.csrf(), email: "socio@example.com", role: "admin" } });
  const link = new URL(r.text.match(/data-copy="(http[^"]+\/invite\/[^"]+)"/)[1]).pathname;
  assert.match(r.text, /wa\.me/);
  assert.match((await b.req("/settings")).text, /Invitación pendiente/);
  assert.doesNotMatch((await b.req("/settings")).text, new RegExp(link), "the link isn't shown again");
  const s = browser();
  r = await s.req(link);
  assert.match(r.text, /socio@example\.com/);
  r = await s.req(link, { method: "POST", form: { _csrf: "otro", password: "nueva-clave-larga", password2: "nueva-clave-larga" } });
  assert.match(r.text, /venció/, "CSRF");
  r = await s.req(link, { method: "POST", form: { _csrf: s.csrf(), password: "corta", password2: "corta" } });
  assert.equal(r.status, 400);
  r = await s.req(link, { method: "POST", form: { _csrf: s.csrf(), name: "Socia", password: "nueva-clave-larga", password2: "nueva-clave-larga" } });
  assert.equal(r.location, "/login/2fa/setup", "then the 2-step code, like anyone");
  assert.equal((await browser().req(link)).status, 404, "one use");
  assert.equal(store.admins.byEmail("socio@example.com").name, "Socia");
  r = await s.req("/login/2fa/setup");
  const secret = r.text.match(/data-copy="([A-Z2-7]{32})"/)[1];
  r = await s.req("/login/2fa/setup", { method: "POST", form: { _csrf: s.csrf(), code: code(secret) } });
  assert.equal((await s.req("/apps")).status, 200);
  r = await b.req("/audit");
  for (const action of ["Creó la app", "Creó una API key", "Creó la cuenta receptora", "Revocó una API key", "Cambió el secreto del webhook", "Agregó un administrador"]) {
    assert.match(r.text, new RegExp(action));
  }
});

test("Inicio warns about silent accounts and notices it couldn't read; first steps go away once done", async () => {
  const b = await loggedIn();
  const app = store.apps.create({ name: "Alertas" });
  const acc = store.accounts.create({ appId: app.id, name: "Cuenta Callada", ownerEmails: [OWNER], banks: ["nequi"], domain: "pagos.example.com" });
  store.accounts.markActive(acc.id);
  assert.equal(store.accounts.get(acc.id).silent, false);
  let r = await b.req("/");
  assert.doesNotMatch(r.text, /Primeros pasos/);
  assert.doesNotMatch(r.text, /Cuenta Callada<\/a>\./);
  store.db.prepare("UPDATE accounts SET last_email_at = ? WHERE id = ?").run(new Date(Date.now() - 8 * 86400_000).toISOString(), acc.id);
  r = await b.req("/");
  assert.match(r.text, /Una cuenta no recibe avisos/);
  assert.match(r.text, /Cuenta Callada<\/a>/);
  r = await b.req(`/accounts/${acc.id}`);
  assert.match(r.text, /Sin avisos/);
  assert.match(r.text, /Último aviso válido/);
  assert.doesNotMatch(r.text, /Recibiendo avisos/, "not both at once");
  // Choosing "never" in the account's settings silences it.
  r = await b.req(`/accounts/${acc.id}`, { method: "POST", form: { _csrf: b.csrf(), name: "Cuenta Callada", ownerEmails: OWNER, banks: "nequi", silentAfterHours: "0" } });
  assert.equal(store.accounts.get(acc.id).silent, false);
  assert.doesNotMatch((await b.req("/")).text, /Una cuenta no recibe avisos/);
  assert.match((await b.req(`/accounts/${acc.id}?ok=saved`)).text, /<details class="config" open>/, "stays open after saving");
  store.accounts.remove(acc.id);

  store.inbox.add({ appId: app.id, reason: "unrecognized", from: "notificaciones@nequi.com.co", subject: "Formato nuevo" });
  r = await b.req("/");
  assert.match(r.text, /Llegó 1 aviso real del banco que no pudimos leer/);
  store.db.prepare("DELETE FROM inbox WHERE subject = 'Formato nuevo'").run();
});

test("invitations: expire, and a new link cancels the old one", async () => {
  const b = await loggedIn();
  await b.req("/settings");
  let r = await b.req("/settings/admins", { method: "POST", form: { _csrf: b.csrf(), email: "invitada@example.com", role: "client" } });
  const first = new URL(r.text.match(/data-copy="(http[^"]+\/invite\/[^"]+)"/)[1]).pathname;
  const person = store.admins.byEmail("invitada@example.com");
  assert.equal(person.invitePending, true);
  const row = store.db.prepare("SELECT invite_hash FROM admins WHERE id = ?").get(person.id);
  assert.ok(!first.includes(row.invite_hash), "only its hash is stored");
  const anon = browser();
  await anon.req("/login");
  r = await anon.req("/login", { method: "POST", form: { _csrf: anon.csrf(), email: "invitada@example.com", password: "lo-que-sea-1234" } });
  assert.match(r.text, /incorrectos/, "no way in before accepting");
  r = await b.req(`/settings/admins/${person.id}`);
  assert.match(r.text, /Invitación pendiente/);
  r = await b.req(`/settings/admins/${person.id}/invite`, { method: "POST", form: { _csrf: b.csrf() } });
  const second = new URL(r.text.match(/data-copy="(http[^"]+\/invite\/[^"]+)"/)[1]).pathname;
  assert.notEqual(first, second);
  assert.equal((await browser().req(first)).status, 404, "the old one no longer works");
  assert.equal((await browser().req(second)).status, 200);
  store.db.prepare("UPDATE admins SET invite_expires_at = ? WHERE id = ?").run(new Date(Date.now() - 1000).toISOString(), person.id);
  assert.equal((await browser().req(second)).status, 404, "expired");
  assert.equal((await browser().req("/invite/inventado")).status, 404);
  store.admins.remove(person.id);

  // Someone who already got in doesn't need one.
  const socio = store.admins.byEmail("socio@example.com");
  r = await b.req(`/settings/admins/${socio.id}/invite`, { method: "POST", form: { _csrf: b.csrf() } });
  assert.equal(r.status, 400);
  assert.equal(store.admins.get(socio.id).invitePending, false);
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

test("domains: in your Cloudflare or a customer's, one Worker per account, who may use it, default, delete", async () => {
  const b = await loggedIn();
  let r = await b.req("/domains", { method: "POST", form: { _csrf: b.csrf(), name: "pagos.cliente.com.co", cf: "new", cfName: "" } });
  assert.equal(r.status, 400, "another account needs a name");
  r = await b.req("/domains", { method: "POST", form: { _csrf: b.csrf(), name: "pagos.cliente.com.co", cf: "new", cfName: "Cloudflare de Ana" } });
  assert.equal(r.location, "/domains/pagos.cliente.com.co?ok=created");
  const cf = store.cfAccounts.list().find((a) => a.name === "Cloudflare de Ana");
  assert.equal(store.domains.get("pagos.cliente.com.co").cfAccountId, cf.id);
  r = await b.req("/domains/pagos.cliente.com.co");
  assert.match(r.text, /Catch-all/);
  assert.match(r.text, /Solo la primera vez en Cloudflare de Ana/);
  assert.match(r.text, new RegExp(store.cfAccounts.secret(cf.id)), "the account's Worker secret, behind 'Mostrar'");
  const worker = await fetch(`${base}/static/pagoradar-email-worker.js`);
  assert.equal(worker.status, 200);
  assert.match(await worker.text(), /X-Pagoradar-Signature/);
  assert.equal((await b.req("/domains", { method: "POST", form: { _csrf: b.csrf(), name: "pagos.cliente.com.co", cf: "mine" } })).status, 400, "already there");

  // A second domain in the same Cloudflare account: same Worker, nothing new to set up once it works.
  await b.req("/domains", { method: "POST", form: { _csrf: b.csrf(), name: "cobros.cliente.com.co", cf: cf.id } });
  store.domains.touch("pagos.cliente.com.co");
  r = await b.req("/domains/cobros.cliente.com.co");
  assert.match(r.text, /Ya está/);
  assert.match(r.text, /ya recibe correos \(de pagos\.cliente\.com\.co\)/);

  // A domain in your own Cloudflare: your Worker, no secret of its own.
  await b.req("/domains", { method: "POST", form: { _csrf: b.csrf(), name: "pagos2.example.com", cf: "mine" } });
  r = await b.req("/domains/pagos2.example.com");
  assert.match(r.text, /que ya tienes en tu cuenta/);
  assert.doesNotMatch(r.text, /ing_/);
  assert.equal((await b.req("/domains/pagos2.example.com/rotate", { method: "POST", form: { _csrf: b.csrf() } })).status, 400);

  r = await b.req("/domains/pagos.cliente.com.co", { method: "POST", form: { _csrf: b.csrf(), cf: cf.id, scope: "some" } });
  assert.equal(r.status, 400, "'only these' needs an app");
  r = await b.req("/domains/pagos.cliente.com.co", { method: "POST", form: { _csrf: b.csrf(), cf: cf.id, scope: "some", apps: appId } });
  assert.deepEqual(store.domains.get("pagos.cliente.com.co").appIds, [appId]);
  assert.equal(store.domains.get("pagos.cliente.com.co").cfAccountId, cf.id, "still in the same account");
  r = await b.req(`/accounts/new?app=${appId}`);
  assert.match(r.text, /name="domain"/, "several domains → choose one");
  r = await b.req("/accounts", { method: "POST", form: { _csrf: b.csrf(), appId, domain: "pagos.cliente.com.co", name: "Caja Cliente", ownerEmails: OWNER, banks: "nequi" } });
  const acc = store.accounts.get(r.location.match(/\/accounts\/([\w-]+)/)[1]);
  assert.match(acc.address, /@pagos\.cliente\.com\.co$/);

  const before = store.cfAccounts.secret(cf.id);
  r = await b.req("/domains/cobros.cliente.com.co/rotate", { method: "POST", form: { _csrf: b.csrf() } });
  assert.notEqual(store.cfAccounts.secret(cf.id), before, "one secret for the whole account");
  assert.match(r.text, new RegExp(store.cfAccounts.secret(cf.id)));
  await b.req("/domains/pagos.cliente.com.co/default", { method: "POST", form: { _csrf: b.csrf() } });
  assert.equal(store.settings.get("inbound_domain"), "pagos.cliente.com.co");
  assert.equal((await b.req("/domains/pagos.cliente.com.co/delete", { method: "POST", form: { _csrf: b.csrf() } })).status, 400, "the default can't go");
  await b.req("/domains/pagos.example.com/default", { method: "POST", form: { _csrf: b.csrf() } });
  assert.equal((await b.req("/domains/pagos.cliente.com.co/delete", { method: "POST", form: { _csrf: b.csrf() } })).status, 400, "it has an account");
  store.accounts.remove(acc.id);
  for (const d of ["pagos.cliente.com.co", "cobros.cliente.com.co", "pagos2.example.com"]) {
    r = await b.req(`/domains/${d}/delete`, { method: "POST", form: { _csrf: b.csrf() } });
    assert.equal(r.location, "/settings?ok=deleted");
  }
  assert.equal(store.domains.get("pagos.cliente.com.co"), undefined);
  assert.equal(store.cfAccounts.get(cf.id), undefined, "the Cloudflare account goes with its last domain");
  assert.match((await b.req("/settings")).text, /pagos\.example\.com/);
});

test("new charge from the panel: link to send, and only for those who manage an app with a working account", async () => {
  const b = await loggedIn();
  const app = store.apps.create({ name: "Cobros a mano" });
  const off = store.accounts.create({ appId: app.id, name: "Sin llave", ownerEmails: [OWNER], banks: ["nequi"], domain: "pagos.example.com" });
  const acc = store.accounts.create({ appId: app.id, name: "Con llave", ownerEmails: [OWNER], banks: ["nequi"], domain: "pagos.example.com" });
  store.accounts.update(acc.id, { payKey: "@conllave", payHolder: "Ana Pérez" });
  let r = await b.req("/charges");
  assert.match(r.text, /href="\/charges\/new"/);
  r = await b.req(`/charges/new?account=${acc.id}`);
  assert.match(r.text, /Sin llave \(sin llave Bre-B\)|Sin llave · Cobros a mano \(sin llave Bre-B\)/, "says which accounts lack a key");
  const form = (o) => ({ _csrf: b.csrf(), account: acc.id, amount: "25.000", expiresInMinutes: "60", description: "Pedido <9>", payerName: "", ...o });
  r = await b.req("/charges", { method: "POST", form: form({ account: off.id }) });
  assert.equal(r.status, 400);
  assert.match(r.text, /no tiene llave Bre-B/);
  for (const amount of ["", "gratis", "25.000,50", "0", "100.000.001"]) {
    assert.equal((await b.req("/charges", { method: "POST", form: form({ amount }) })).status, 400, `amount "${amount}"`);
  }
  assert.equal((await b.req("/charges", { method: "POST", form: form({ expiresInMinutes: "1" }) })).status, 400);

  r = await b.req("/charges", { method: "POST", form: form() });
  const id = r.location.match(/^\/charges\/(chg_[a-z0-9]+)\?ok=charged$/)[1];
  const c = store.charges.get(id);
  assert.equal(c.baseAmount, 25000);
  assert.equal(c.amount, 25001, "a unique amount, like any charge");
  assert.equal(c.accountId, acc.id);
  assert.ok(new Date(c.expiresAt) - Date.now() > 50 * 60_000);
  r = await b.req(`/charges/${id}?ok=charged`);
  assert.match(r.text, /Pedido &lt;9&gt;/, "escaped");
  assert.match(r.text, new RegExp(`data-copy="http://[^"]+/c/${id}"`), "the link to copy");
  assert.match(r.text, /https:\/\/wa\.me\/\?text=/);
  assert.match(r.text, /todavía no ha recibido ningún aviso/, "warns while the account isn't working yet");
  assert.match((await b.req("/audit")).text, /Creó un cobro/);
  assert.match((await b.req("/charges")).text, new RegExp(`href="/charges/${id}"`));

  // How the amount is made unique: up by default, down, or exact (and then it warns about twins).
  const made = async (o) => store.charges.get((await b.req("/charges", { method: "POST", form: form({ amount: "40.000", ...o }) })).location.match(/(chg_[a-z0-9]+)/)[1]);
  assert.match((await b.req("/charges/new")).text, /name="uniqueAmount"/);
  const down = await made({ uniqueAmount: "down" });
  assert.equal(down.amount, 39999);
  const exact = await made({ uniqueAmount: "off" });
  assert.equal(exact.amount, 40000);
  assert.doesNotMatch((await b.req(`/charges/${exact.id}`)).text, /por el mismo valor/);
  const twin = await made({ uniqueAmount: "off" });
  assert.equal(twin.amount, 40000);
  assert.match((await b.req(`/charges/${twin.id}`)).text, /por el mismo valor/);
  const named = await made({ uniqueAmount: "off", payerName: "Ana Pérez" });
  assert.doesNotMatch((await b.req(`/charges/${named.id}`)).text, /por el mismo valor/, "an expected payer tells them apart");
  assert.equal((await b.req("/charges", { method: "POST", form: form({ uniqueAmount: "otro" }) })).status, 400);
  for (const c2 of [down, exact, twin, named]) store.charges.cancel(c2.id);

  // A suspended app can't charge (its notices are refused too).
  store.apps.update(app.id, { active: false });
  assert.equal((await b.req("/charges", { method: "POST", form: form() })).status, 400);
  store.apps.update(app.id, { active: true });

  // Clients: view sees it but can't create; nobody else sees it.
  const { hashPassword } = await import("../src/security.js");
  const viewer = store.admins.create({ email: "ve-cobros@example.com", passwordHash: await hashPassword("clave-larga-123"), role: "client" });
  store.admins.setTotp(viewer.id, "JBSWY3DPEHPK3PXP", 1);
  const token = store.sessions.create(viewer.id, "full", "127.0.0.1");
  const v = browser();
  v.jar.set("pr_s", token);
  assert.equal((await v.req(`/charges/${id}`)).status, 404, "no access yet");
  store.access.set(viewer.id, app.id, "view");
  r = await v.req(`/charges/${id}`);
  assert.equal(r.status, 200);
  assert.doesNotMatch(r.text, /\/cancel"/, "view can't cancel");
  assert.doesNotMatch((await v.req("/charges")).text, /href="\/charges\/new"/);
  assert.equal((await v.req("/charges/new")).status, 404);
  assert.equal((await v.req("/charges", { method: "POST", form: { _csrf: v.csrf(), account: acc.id, amount: "1000" } })).status, 404);
  store.access.set(viewer.id, app.id, "manage");
  const other = store.apps.create({ name: "De otro" });
  const otherAcc = store.accounts.create({ appId: other.id, name: "Ajena", ownerEmails: [OWNER], banks: ["nequi"], domain: "pagos.example.com" });
  store.accounts.update(otherAcc.id, { payKey: "@ajena" });
  r = await v.req("/charges/new");
  assert.doesNotMatch(r.text, /Ajena/);
  assert.equal((await v.req("/charges", { method: "POST", form: { _csrf: v.csrf(), account: otherAcc.id, amount: "1000" } })).status, 400, "not someone else's account");
  store.admins.remove(viewer.id);
  store.charges.cancel(id);
});

test("clients: only their apps, with view or manage access", async () => {
  const b = await loggedIn();
  // Another app, with an account and a payment the client must never see.
  const other = store.apps.create({ name: "App Ajena" });
  const otherAcc = store.accounts.create({ appId: other.id, name: "Cuenta Ajena", ownerEmails: [OWNER], banks: ["nequi"], domain: "pagos.example.com" });
  store.payments.add(other.id, otherAcc.id, { bank: "nequi", method: "breb", methodText: null, amountCents: 777_700, currency: "COP", payerName: "Pagador Ajeno", payerNameNormalized: "PAGADOR AJENO", payerBank: null, reference: null, transactionId: null, accountHint: null, paidAt: new Date().toISOString(), dkimDomain: "nequi.com.co", dedupeKey: "ajeno-1" });

  await b.req("/settings");
  let r = await b.req("/settings/admins", { method: "POST", form: { _csrf: b.csrf(), email: "cliente@example.com", role: "client" } });
  const link = new URL(r.text.match(/data-copy="(http[^"]+\/invite\/[^"]+)"/)[1]).pathname;
  const person = store.admins.byEmail("cliente@example.com");
  assert.equal(person.role, "client");
  r = await b.req(`/settings/admins/${person.id}`, { method: "POST", form: { _csrf: b.csrf(), role: "client", [`access_${appId}`]: "manage", [`access_${other.id}`]: "" } });
  assert.equal(r.location, `/settings/admins/${person.id}?ok=saved`);
  assert.deepEqual(store.access.forAdmin(person.id), { [appId]: "manage" });

  // The client signs in like anyone: the link, a password, the 2-step setup.
  const c = browser();
  await c.req(link);
  await c.req(link, { method: "POST", form: { _csrf: c.csrf(), password: "clave-del-cliente", password2: "clave-del-cliente" } });
  r = await c.req("/login/2fa/setup");
  const secret = r.text.match(/data-copy="([A-Z2-7]{32})"/)[1];
  await c.req("/login/2fa/setup", { method: "POST", form: { _csrf: c.csrf(), code: code(secret) } });

  r = await c.req("/");
  assert.equal(r.status, 200);
  assert.doesNotMatch(r.text, /href="\/settings"/, "no Ajustes in the menu");
  for (const path of ["/settings", "/audit", "/domains", "/domains/pagos.example.com", `/settings/admins/${person.id}`, `/apps/${other.id}`, `/accounts/${otherAcc.id}`]) {
    assert.equal((await c.req(path)).status, 404, path);
  }
  assert.equal((await c.req("/apps", { method: "POST", form: { _csrf: c.csrf(), name: "Mía" } })).status, 404, "only admins create apps");
  r = await c.req("/apps");
  assert.match(r.text, /Tienda/);
  assert.doesNotMatch(r.text, /App Ajena/);
  for (const path of ["/payments", "/payments.csv", "/charges", "/accounts", "/"]) {
    assert.doesNotMatch((await c.req(path)).text, /Pagador Ajeno|Cuenta Ajena|App Ajena/, path);
  }

  // Manage: accounts in its app (not in another one), the webhook, but not switching the app off.
  r = await c.req("/accounts", { method: "POST", form: { _csrf: c.csrf(), appId: other.id, name: "Intruso", ownerEmails: OWNER, banks: "nequi" } });
  assert.equal(r.status, 400);
  r = await c.req("/accounts", { method: "POST", form: { _csrf: c.csrf(), appId, name: "Caja del cliente", ownerEmails: OWNER, banks: "nequi" } });
  assert.match(r.location, /^\/accounts\/acc_/);
  r = await c.req(`/apps/${appId}`, { method: "POST", form: { _csrf: c.csrf(), name: "Tienda", webhookUrl: "https://cliente.example.com/hook" } });
  assert.equal(r.location, `/apps/${appId}?ok=saved`);
  assert.equal(store.apps.get(appId).webhookUrl, "https://cliente.example.com/hook");
  assert.equal(store.apps.get(appId).active, true, "a client can't switch its app off (or back on)");

  // View only: pages yes, changes no.
  await b.req(`/settings/admins/${person.id}`);
  await b.req(`/settings/admins/${person.id}`, { method: "POST", form: { _csrf: b.csrf(), role: "client", [`access_${appId}`]: "view" } });
  r = await c.req(`/apps/${appId}`);
  assert.equal(r.status, 200);
  assert.match(r.text, /solo lectura/);
  assert.doesNotMatch(r.text, /whsec_|Crear API key/, "no webhook secret nor keys");
  assert.equal((await c.req(`/apps/${appId}/rotate`, { method: "POST", form: { _csrf: c.csrf() } })).status, 404);
  assert.equal((await c.req(`/accounts/${accountId}`, { method: "POST", form: { _csrf: c.csrf(), name: "x", ownerEmails: OWNER, banks: "nequi" } })).status, 404);
  assert.equal((await c.req(`/accounts/${accountId}`)).status, 200);

  // Made an admin, the grants go; removed, the session ends.
  await b.req(`/settings/admins/${person.id}`, { method: "POST", form: { _csrf: b.csrf(), role: "admin" } });
  assert.deepEqual(store.access.forAdmin(person.id), {});
  assert.equal((await c.req("/settings")).status, 200);
  await b.req(`/settings/admins/${person.id}/delete`, { method: "POST", form: { _csrf: b.csrf() } });
  assert.equal((await c.req("/")).location, "/login");
  r = await b.req("/audit");
  for (const action of ["Agregó un cliente", "Cambió los permisos", "Quitó un administrador"]) assert.match(r.text, new RegExp(action));
});

test("login: a locked account only says so to whoever knows the password", async () => {
  const { hashPassword } = await import("../src/security.js");
  const locked = store.admins.create({ email: "bloqueado@example.com", passwordHash: await hashPassword("clave-correcta-123") });
  store.db.prepare("UPDATE admins SET locked_until = ? WHERE id = ?").run(new Date(Date.now() + 600_000).toISOString(), locked.id);
  const b = browser();
  await b.req("/login");
  let r = await b.req("/login", { method: "POST", form: { _csrf: b.csrf(), email: "bloqueado@example.com", password: "otra-clave-xyz" } });
  assert.match(r.text, /Correo o contraseña incorrectos/);
  assert.doesNotMatch(r.text, /bloqueada/);
  r = await b.req("/login", { method: "POST", form: { _csrf: b.csrf(), email: "nadie-existe@example.com", password: "otra-clave-xyz" } });
  assert.match(r.text, /Correo o contraseña incorrectos/);
  r = await b.req("/login", { method: "POST", form: { _csrf: b.csrf(), email: "bloqueado@example.com", password: "clave-correcta-123" } });
  assert.match(r.text, /bloqueada/);
  store.admins.remove(locked.id);
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
