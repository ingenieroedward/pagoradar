import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { openStore } from "../src/store.js";
import { createApp } from "../src/app.js";
import { masterKeyFrom } from "../src/security.js";
import { deliver } from "../worker/src/index.js";
import { OWNER, gmailConfirmationEmail, nequiNegociosEmail, resolverFor } from "./fixtures.js";

const INGEST_SECRET = "i".repeat(40);
const masterKey = masterKeyFrom("aa".repeat(32));
let server, base, store, appA, appB, keyA, keyB, cfB, cfC;
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${srv.address().port}`)));

before(async () => {
  store = openStore(":memory:", { masterKey });
  // Older versions only had this setting: it becomes the default domain, in your Cloudflare, open to every app.
  store.settings.set("inbound_domain", "pagos.example.com");
  appA = store.apps.create({ name: "SaaS A" });
  appB = store.apps.create({ name: "SaaS B" });
  keyA = store.keys.create(appA.id, "test").key;
  keyB = store.keys.create(appB.id, "test").key;
  // Customer B's own Cloudflare account, with two domains (one Worker serves both), only for app B.
  cfB = store.cfAccounts.create("Cloudflare de B");
  store.domains.create("pagos.cliente-b.co", { appIds: [appB.id], cfAccountId: cfB.id });
  store.domains.create("cobros.cliente-b.co", { appIds: [appB.id], cfAccountId: cfB.id });
  // Another customer's Cloudflare account.
  cfC = store.cfAccounts.create("Cloudflare de C");
  store.domains.create("pagos.cliente-c.co", { cfAccountId: cfC.id });
  server = createServer(createApp({ store, config: { ingestSecret: INGEST_SECRET, masterKey, publicUrl: null }, resolver: resolverFor(), log: () => {} }));
  base = await listen(server);
});
after(() => {
  server.close();
  store.close();
});

const api = (key, path, { method = "GET", body } = {}) =>
  fetch(base + path, { method, headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then(async (r) => ({ status: r.status, body: await r.json() }));
const send = (raw, to, secret) =>
  deliver(new Uint8Array(raw), { to, from: "reenvio@gmail.com" }, { PAGORADAR_URL: base, INGEST_SECRET: secret }, { sleep: async () => {} });

test("the legacy setting becomes the default domain; each other Cloudflare account has its own encrypted Worker secret", () => {
  const list = store.domains.list();
  assert.deepEqual(list.map((d) => [d.name, d.isDefault, d.cfAccountId]), [
    ["pagos.example.com", true, null],
    ["pagos.cliente-b.co", false, cfB.id],
    ["cobros.cliente-b.co", false, cfB.id],
    ["pagos.cliente-c.co", false, cfC.id],
  ]);
  const secret = store.cfAccounts.secret(cfB.id);
  assert.match(secret, /^ing_/);
  assert.notEqual(secret, store.cfAccounts.secret(cfC.id));
  const row = store.db.prepare("SELECT secret_enc FROM cf_accounts WHERE id = ?").get(cfB.id);
  assert.ok(!row.secret_enc.includes(secret), "stored encrypted");
  assert.deepEqual(store.domains.inCfAccount(cfB.id).map((d) => d.name), ["pagos.cliente-b.co", "cobros.cliente-b.co"]);
  assert.deepEqual(store.domains.inCfAccount(null).map((d) => d.name), ["pagos.example.com"]);
});

test("API: each app sees the domains it may use, and creates accounts only in those", async () => {
  assert.deepEqual((await api(keyA, "/v1/domains")).body.domains.map((d) => d.name), ["pagos.example.com", "pagos.cliente-c.co"]);
  assert.deepEqual((await api(keyB, "/v1/domains")).body.domains.map((d) => d.name), ["pagos.example.com", "pagos.cliente-b.co", "cobros.cliente-b.co", "pagos.cliente-c.co"]);
  assert.equal((await api(keyB, "/v1/domains")).body.domains[0].default, true);

  let r = await api(keyA, "/v1/accounts", { method: "POST", body: { name: "Ana", ownerEmails: [OWNER], domain: "pagos.cliente-b.co" } });
  assert.equal(r.status, 400, "app A can't use B's domain");
  assert.match(r.body.error, /domain/);
  r = await api(keyA, "/v1/accounts", { method: "POST", body: { name: "Ana", ownerEmails: [OWNER] } });
  assert.equal(r.status, 201);
  assert.match(r.body.address, /@pagos\.example\.com$/, "no domain → the default");
  for (const domain of ["Pagos.Cliente-B.co", "cobros.cliente-b.co"]) {
    r = await api(keyB, "/v1/accounts", { method: "POST", body: { name: "Beto", ownerEmails: [OWNER], domain } });
    assert.equal(r.status, 201);
    assert.ok(r.body.address.endsWith(`@${domain.toLowerCase()}`));
  }
  assert.equal(store.domains.accountCount("pagos.cliente-b.co"), 1);
});

test("one Worker per Cloudflare account: its secret delivers to all of that account's domains, and only those", async () => {
  const inDomain = (d) => store.accounts.list(appB.id).find((x) => x.address.endsWith(`@${d}`));
  const inPagos = inDomain("pagos.cliente-b.co");
  const inCobros = inDomain("cobros.cliente-b.co");
  const [a] = store.accounts.list(appA.id);
  const own = store.cfAccounts.secret(cfB.id);

  assert.equal(await send(await gmailConfirmationEmail({ to: inPagos.address }), inPagos.address, own), true);
  assert.ok(store.domains.get("pagos.cliente-b.co").lastEmailAt, "the domain's first email is recorded");
  assert.equal(await send(await nequiNegociosEmail({ tx: "dom-b-1" }), inPagos.address, own), true);
  assert.equal(await send(await nequiNegociosEmail({ tx: "dom-b-2" }), inCobros.address, own), true, "the same Worker serves the account's second domain");
  assert.equal(store.payments.search({ appId: appB.id }).total, 2);

  assert.equal(await send(await nequiNegociosEmail({ tx: "dom-a-1" }), a.address, own), false, "B's Worker can't deliver to your domain");
  assert.equal(await send(await nequiNegociosEmail({ tx: "dom-a-1" }), a.address, store.cfAccounts.secret(cfC.id)), false, "nor C's");
  assert.equal(await send(await nequiNegociosEmail({ tx: "dom-a-1" }), a.address, "x".repeat(40)), false, "unknown secret");
  assert.equal(await send(await nequiNegociosEmail({ tx: "dom-a-1" }), a.address, INGEST_SECRET), true);
  assert.equal(await send(await nequiNegociosEmail({ tx: "dom-b-3" }), inPagos.address, INGEST_SECRET), true, "the server's secret still works everywhere");

  store.cfAccounts.rotateSecret(cfB.id);
  assert.equal(await send(await nequiNegociosEmail({ tx: "dom-b-4" }), inCobros.address, own), false, "the old secret stops working");
});

test("restricting a domain later keeps its existing accounts working", async () => {
  store.domains.setApps("pagos.example.com", [appB.id]);
  store.domains.setApps("pagos.cliente-c.co", [appB.id]);
  const r = await api(keyA, "/v1/accounts", { method: "POST", body: { name: "Otra", ownerEmails: [OWNER] } });
  assert.equal(r.status, 503, "app A has no domain left");
  const [a] = store.accounts.list(appA.id);
  assert.equal(await send(await nequiNegociosEmail({ tx: "dom-a-2" }), a.address, INGEST_SECRET), true);
  assert.equal(store.payments.search({ accountId: a.id }).total, 2);
  store.domains.setApps("pagos.example.com", null);
});

test("a Cloudflare account is forgotten with its last domain", () => {
  assert.equal(store.cfAccounts.removeIfUnused(cfC.id), false, "still has a domain");
  store.domains.remove("pagos.cliente-c.co");
  assert.equal(store.cfAccounts.removeIfUnused(cfC.id), true);
  assert.equal(store.cfAccounts.get(cfC.id), undefined);
});
