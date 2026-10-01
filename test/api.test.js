import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { openStore } from "../src/store.js";
import { createApp } from "../src/app.js";
import { masterKeyFrom } from "../src/security.js";
import { deliver } from "../worker/src/index.js";
import { OWNER, gmailConfirmationEmail, nequiNegociosEmail, resolverFor } from "./fixtures.js";

const INGEST_SECRET = "i".repeat(40);
const masterKey = masterKeyFrom("ef".repeat(32));
let server, base, store, hookServer, received = [], keyA, keyB, appA;
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${srv.address().port}`)));

before(async () => {
  hookServer = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push(JSON.parse(body));
      res.writeHead(200).end();
    });
  });
  const hookBase = await listen(hookServer);
  store = openStore(":memory:", { masterKey });
  store.settings.set("inbound_domain", "pagos.example.com");
  appA = store.apps.create({ name: "SaaS A", webhookUrl: `${hookBase}/a` });
  const appB = store.apps.create({ name: "SaaS B" });
  keyA = store.keys.create(appA.id, "test").key;
  keyB = store.keys.create(appB.id, "test").key;
  server = createServer(createApp({ store, config: { ingestSecret: INGEST_SECRET, masterKey, publicUrl: null }, resolver: resolverFor(), log: () => {} }));
  base = await listen(server);
});
after(() => {
  server.close();
  hookServer.close();
  store.close();
});

const api = (key, path, { method = "GET", body } = {}) =>
  fetch(base + path, { method, headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
const waitFor = async (pred, ms = 3000) => {
  const t = Date.now();
  while (Date.now() - t < ms) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 20));
  }
  return false;
};

let account;

test("create an account for one of your customers", async () => {
  let r = await api(keyA, "/v1/accounts", { method: "POST", body: { name: "", ownerEmails: [OWNER] } });
  assert.equal(r.status, 400);
  r = await api(keyA, "/v1/accounts", { method: "POST", body: { name: "Tienda de Ana", ownerEmails: ["no-es-correo"] } });
  assert.equal(r.status, 400);
  r = await api(keyA, "/v1/accounts", { method: "POST", body: { name: "Tienda de Ana", ownerEmails: [OWNER], banks: ["daviplata"] } });
  assert.equal(r.status, 400);
  r = await fetch(base + "/v1/accounts", { method: "POST", headers: { Authorization: `Bearer ${keyA}` }, body: "{nope" });
  assert.equal(r.status, 400);
  r = await api(keyA, "/v1/accounts", { method: "POST", body: { name: "Tienda de Ana", ownerEmails: [OWNER.toUpperCase()], banks: ["nequi_negocios"], tenantRef: "org_42" } });
  assert.equal(r.status, 201);
  account = await r.json();
  assert.match(account.address, /^tienda-de-ana-[a-z2-9]{6}@pagos\.example\.com$/);
  assert.deepEqual(account.ownerEmails, [OWNER]);
  assert.equal(account.status, "pending");
  assert.equal(account.tenantRef, "org_42");
  assert.equal(account.setup.forwardTo, account.address);
  assert.equal(account.setup.gmailFilterFrom, "notificaciones@nequi.com.co");
});

test("list and read, scoped to the app; another app's account is a 404", async () => {
  assert.equal((await (await api(keyA, "/v1/accounts")).json()).accounts.length, 1);
  assert.equal((await (await api(keyA, "/v1/accounts?tenantRef=org_42")).json()).accounts[0].id, account.id);
  assert.equal((await (await api(keyA, "/v1/accounts?tenantRef=otro")).json()).accounts.length, 0);
  assert.equal((await api(keyB, `/v1/accounts/${account.id}`)).status, 404);
  assert.equal((await api(keyB, `/v1/accounts/${account.id}`, { method: "PATCH", body: { name: "x" } })).status, 404);
  assert.equal((await api(keyB, `/v1/accounts/${account.id}`, { method: "DELETE" })).status, 404);
  assert.equal((await (await api(keyB, "/v1/accounts")).json()).accounts.length, 0);
  assert.equal((await fetch(`${base}/v1/accounts`)).status, 401);
});

test("Gmail code and first notice: visible through the API and sent as events", async () => {
  const send = (raw) => deliver(new Uint8Array(raw), { to: account.address, from: "x@gmail.com" }, { PAGORADAR_URL: base, INGEST_SECRET }, { sleep: async () => {} });
  await send(await gmailConfirmationEmail({ subject: "(#246813579) Confirmación de reenvío de Gmail", to: account.address }));
  const read = await (await api(keyA, `/v1/accounts/${account.id}`)).json();
  assert.equal(read.confirmationCode, "246813579");
  assert.ok(await waitFor(() => received.some((e) => e.type === "account.confirmation_code")));
  const ev = received.find((e) => e.type === "account.confirmation_code");
  assert.equal(ev.data.code, "246813579");
  assert.equal(ev.data.account.tenantRef, "org_42");

  await send(await nequiNegociosEmail({ tx: "api-1" }));
  assert.ok(await waitFor(() => received.some((e) => e.type === "payment.received")));
  assert.ok(received.some((e) => e.type === "account.activated" && e.data.account.id === account.id));
  const pay = received.find((e) => e.type === "payment.received");
  assert.equal(pay.data.account.tenantRef, "org_42");
  assert.equal((await (await api(keyA, `/v1/accounts/${account.id}`)).json()).status, "active");
  const byTenant = await (await api(keyA, "/v1/payments?tenantRef=org_42")).json();
  assert.equal(byTenant.payments.length, 1);
  assert.equal((await (await api(keyA, "/v1/payments?tenantRef=otro")).json()).payments.length, 0);
});

test("update, disable, delete (disables when it has payments)", async () => {
  let r = await api(keyA, `/v1/accounts/${account.id}`, { method: "PATCH", body: { ownerEmails: ["nueva@gmail.com"], banks: ["nequi", "bancolombia"] } });
  const upd = await r.json();
  assert.deepEqual(upd.ownerEmails, ["nueva@gmail.com"]);
  assert.match(upd.setup.gmailFilterFrom, /notificaciones@nequi\.com\.co OR alertasynotificaciones/);
  assert.equal(upd.name, "Tienda de Ana", "untouched fields stay");
  r = await api(keyA, `/v1/accounts/${account.id}`, { method: "PATCH", body: { active: "no" } });
  assert.equal(r.status, 400);
  r = await api(keyA, `/v1/accounts/${account.id}`, { method: "PATCH", body: { active: false } });
  assert.equal((await r.json()).status, "disabled");
  r = await api(keyA, `/v1/accounts/${account.id}`, { method: "DELETE" });
  assert.deepEqual(await r.json(), { id: account.id, deleted: false, disabled: true });
  const fresh = await (await api(keyA, "/v1/accounts", { method: "POST", body: { name: "Sin pagos", ownerEmails: [OWNER] } })).json();
  r = await api(keyA, `/v1/accounts/${fresh.id}`, { method: "DELETE" });
  assert.deepEqual(await r.json(), { id: fresh.id, deleted: true });
  assert.equal((await api(keyA, `/v1/accounts/${fresh.id}`)).status, 404);
  const actions = store.audit.list().map((a) => a.action);
  assert.ok(actions.includes("Creó la cuenta receptora") && actions.includes("Eliminó la cuenta receptora"));
});
