import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { openStore } from "../src/store.js";
import { createApp } from "../src/app.js";
import { masterKeyFrom } from "../src/security.js";
import { namesMatch } from "../src/charges.js";
import { deliver } from "../worker/src/index.js";
import { Pagoradar, PagoradarError, constructEvent, verifySignature } from "../sdk/pagoradar.js";
import { OWNER, nequiNegociosEmail, resolverFor } from "./fixtures.js";

const INGEST_SECRET = "i".repeat(40);
const masterKey = masterKeyFrom("cd".repeat(32));
const PUBLIC_URL = "https://pagoradar.example.com";
let server, base, store, hookServer, received = [], app, pr, other, account, account2;
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${srv.address().port}`)));

before(async () => {
  hookServer = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ headers: req.headers, body, event: JSON.parse(body) });
      res.writeHead(200).end();
    });
  });
  const hookBase = await listen(hookServer);
  store = openStore(":memory:", { masterKey });
  store.settings.set("inbound_domain", "pagos.example.com");
  app = store.apps.create({ name: "Tienda", webhookUrl: `${hookBase}/hook` });
  const appB = store.apps.create({ name: "Otra" });
  server = createServer(createApp({ store, config: { ingestSecret: INGEST_SECRET, masterKey, publicUrl: PUBLIC_URL }, resolver: resolverFor(), log: () => {} }));
  base = await listen(server);
  pr = new Pagoradar({ apiKey: store.keys.create(app.id, "test").key, baseUrl: base });
  other = new Pagoradar({ apiKey: store.keys.create(appB.id, "test").key, baseUrl: base });
  account = await pr.accounts.create({ name: "Tienda de Ana", ownerEmails: [OWNER], banks: ["nequi_negocios"], tenantRef: "org_1", payKey: "@tiendaana", payHolder: "Ana Prueba" });
  account2 = await pr.accounts.create({ name: "Segunda", ownerEmails: [OWNER], banks: ["nequi_negocios"] });
});
after(() => {
  server.close();
  hookServer.close();
  store.close();
});

const waitFor = async (pred, ms = 3000) => {
  const t = Date.now();
  while (Date.now() - t < ms) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 20));
  }
  return false;
};
const pad = (n) => String(n).padStart(2, "0");
/** "01/10/2026 17:05:09" in Bogotá, as Nequi writes it. */
const bogota = (d = new Date()) => {
  const b = new Date(d.getTime() - 5 * 3600_000);
  return `${pad(b.getUTCDate())}/${pad(b.getUTCMonth() + 1)}/${b.getUTCFullYear()} ${pad(b.getUTCHours())}:${pad(b.getUTCMinutes())}:${pad(b.getUTCSeconds())}`;
};
let tx = 0;
const pay = async (amount, { to = account.address, payer, when } = {}) => {
  const raw = await nequiNegociosEmail({ amount: `$ ${amount.toLocaleString("es-CO")}`, tx: `chg-${++tx}`, fecha: bogota(when), ...(payer ? { payer } : {}) });
  await deliver(new Uint8Array(raw), { to, from: "x@gmail.com" }, { PAGORADAR_URL: base, INGEST_SECRET }, { sleep: async () => {} });
};
const events = (type) => received.filter((r) => r.event.type === type).map((r) => r.event);
const rejects = async (promise, status) => {
  const err = await promise.then(() => null, (e) => e);
  assert.ok(err instanceof PagoradarError, `expected a PagoradarError, got ${err}`);
  assert.equal(err.status, status, err.message);
  return err;
};

let c1, c2, c3;

test("validation and scoping", async () => {
  await rejects(pr.charges.create({ amount: 25000 }), 400);
  await rejects(other.charges.create({ account: account.id, amount: 25000 }), 404);
  await rejects(pr.charges.create({ account: account.id, amount: 25000.5 }), 400);
  await rejects(pr.charges.create({ account: account.id, amount: "25000" }), 400);
  await rejects(pr.charges.create({ account: account.id, amount: 25000, uniqueAmount: "sideways" }), 400);
  await rejects(pr.charges.create({ account: account.id, amount: 25000, expiresInMinutes: 1 }), 400);
  await rejects(pr.charges.create({ account: account.id, amount: 25000, returnUrl: "javascript:alert(1)" }), 400);
  await rejects(pr.charges.create({ account: account.id, amount: 25000, metadata: { x: "y".repeat(3000) } }), 400);
  await rejects(pr.charges.create({ account: account.id, amount: 25000, currency: "USD" }), 400);
  assert.equal((await fetch(`${base}/v1/charges`)).status, 401);
});

test("each open charge of an account gets its own amount", async () => {
  c1 = await pr.charges.create({ account: account.id, amount: 25000, description: "Pedido 1", reference: "order-1", returnUrl: "https://tienda.example/gracias", metadata: { cart: 7 } });
  c2 = await pr.charges.create({ tenantRef: "org_1", amount: 25000, description: "Pedido 2", reference: "order-2" });
  c3 = await pr.charges.create({ account: account.id, amount: 25000, uniqueAmount: "down" });
  const exact = await pr.charges.create({ account: account2.id, amount: 25000, uniqueAmount: "off" });
  assert.deepEqual([c1.amount, c2.amount, c3.amount, exact.amount], [25001, 25002, 24999, 25000]);
  assert.equal(c1.adjustment, 1);
  assert.equal(c3.adjustment, -1);
  assert.equal(c1.status, "pending");
  assert.equal(c2.account.id, account.id, "tenantRef picks that customer's account");
  assert.match(c1.id, /^chg_[a-z0-9]{24}$/);
  assert.equal(c1.checkoutUrl, `${PUBLIC_URL}/c/${c1.id}`);
  assert.deepEqual(c1.payTo, { key: "@tiendaana", holder: "Ana Prueba", banks: ["nequi_negocios"] });
  assert.deepEqual(c1.metadata, { cart: 7 });
  assert.ok(Math.abs(new Date(c1.expiresAt) - Date.now() - 30 * 60_000) < 5000, "30 minutes by default");

  // Same reference = the same charge (safe retries); different data with it = conflict.
  const again = await pr.charges.create({ account: account.id, amount: 25000, reference: "order-1" });
  assert.equal(again.id, c1.id);
  await rejects(pr.charges.create({ account: account.id, amount: 26000, reference: "order-1" }), 409);
  await rejects(other.charges.get(c1.id), 404);
  const list = await pr.charges.list({ status: "pending", tenantRef: "org_1" });
  assert.equal(list.total, 3);
  assert.equal((await pr.charges.list({ reference: "order-2" })).charges[0].id, c2.id);
});

test("checkout page: what to pay, how, and its status", async () => {
  const res = await fetch(`${base}/c/${c1.id}`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-security-policy"), /script-src 'self'/);
  const page = await res.text();
  assert.match(page, /25\.001/);
  assert.match(page, /@tiendaana/);
  assert.match(page, /Ana Prueba/);
  assert.match(page, /Pedido 1/);
  assert.match(page, /Esperando tu pago/);
  assert.match(page, /incluye/);
  assert.doesNotMatch(page, /order-1|cart/, "reference and metadata stay private");
  assert.deepEqual(await (await fetch(`${base}/c/${c1.id}/status`)).json(), { status: "pending", paidAt: null, expiresAt: c1.expiresAt, returnUrl: null });
  assert.equal((await fetch(`${base}/c/chg_nonexistent00000000000000`)).status, 404);
  assert.equal((await fetch(`${base}/c/../admin`)).status !== 500, true);
  assert.equal((await fetch(`${base}/static/checkout.js`)).status, 200);
  assert.equal((await fetch(`${base}/static/checkout.css`)).status, 200);
});

test("the bank notice with exactly that amount pays the charge", async () => {
  await pay(25002);
  assert.ok(await waitFor(() => events("charge.paid").length === 1));
  const paid = events("charge.paid")[0];
  assert.equal(paid.data.id, c2.id);
  assert.equal(paid.data.reference, "order-2");
  assert.equal(paid.data.status, "paid");
  assert.equal(paid.data.payment.amount, 25002);
  assert.equal(paid.data.late, false);
  const pr2 = events("payment.received").find((e) => e.data.amount === 25002);
  assert.deepEqual(pr2.data.charge, { id: c2.id, reference: "order-2" });
  const order = received.map((r) => r.event.type).filter((t) => t !== "account.activated");
  assert.deepEqual(order.slice(-2), ["payment.received", "charge.paid"], "payment first, then the charge");

  const got = await pr.charges.get(c2.id);
  assert.equal(got.status, "paid");
  assert.equal(got.paymentId, pr2.data.id);
  assert.equal((await (await fetch(`${base}/c/${c2.id}/status`)).json()).status, "paid");
  assert.match(await (await fetch(`${base}/c/${c2.id}`)).text(), /Pago recibido/);
  const { payments } = await pr.payments.list();
  assert.equal(payments.find((p) => p.id === pr2.data.id).chargeId, c2.id);

  // A round amount (nobody's charge) is just a payment.
  await pay(30000);
  assert.ok(await waitFor(() => events("payment.received").some((e) => e.data.amount === 30000)));
  assert.equal(events("payment.received").find((e) => e.data.amount === 30000).data.charge, null);
  assert.equal(events("charge.paid").length, 1);
});

test("signed webhooks verify with the SDK", () => {
  const secret = store.apps.secret(app.id);
  const hit = received.find((r) => r.event.type === "charge.paid");
  assert.equal(verifySignature(hit.body, hit.headers["pagoradar-signature"], secret), true);
  assert.equal(constructEvent(hit.body, hit.headers["pagoradar-signature"], secret).data.id, c2.id);
  assert.equal(verifySignature(hit.body.replace("order-2", "order-9"), hit.headers["pagoradar-signature"], secret), false);
  assert.equal(verifySignature(hit.body, hit.headers["pagoradar-signature"], "otro-secreto"), false);
  assert.throws(() => constructEvent(hit.body, "t=1,v1=00", secret), PagoradarError);
});

test("same amount on purpose (uniqueAmount off): the expected payer decides", async () => {
  const a = await pr.charges.create({ account: account2.id, amount: 40000, uniqueAmount: "off", payerName: "Carlos Ruiz" });
  const b = await pr.charges.create({ account: account2.id, amount: 40000, uniqueAmount: "off", payerName: "Ana Prueba" });
  await pay(40000, { to: account2.address, payer: "ANA MARIA PRUEBA LOPEZ" });
  assert.ok(await waitFor(() => events("charge.paid").some((e) => e.data.id === b.id)));
  assert.equal((await pr.charges.get(a.id)).status, "pending");
  assert.equal(namesMatch("Ana Prueba", "ANA MARIA PRUEBA LOPEZ"), true);
  assert.equal(namesMatch("Ana Gomez", "ANA MARIA PRUEBA LOPEZ"), false);
});

test("cancel frees the amount; a notice for it no longer pays anything", async () => {
  const canceled = await pr.charges.cancel(c1.id);
  assert.equal(canceled.status, "canceled");
  await rejects(pr.charges.cancel(c1.id), 409);
  assert.match(await (await fetch(`${base}/c/${c1.id}`)).text(), /cancelado/);
  const before = events("charge.paid").length;
  await pay(25001);
  assert.ok(await waitFor(() => events("payment.received").some((e) => e.data.amount === 25001)));
  assert.equal(events("charge.paid").length, before);
  const reused = await pr.charges.create({ account: account.id, amount: 25000 });
  assert.equal(reused.amount, 25001, "the canceled charge's amount is free again");
  await pr.charges.cancel(reused.id);
});

test("expiry: charge.expired, the amount stays reserved a while, and a late notice still pays it", async () => {
  const c = await pr.charges.create({ account: account.id, amount: 50000, expiresInMinutes: 5, reference: "order-late" });
  store.db.prepare("UPDATE charges SET expires_at = ? WHERE id = ?").run(new Date(Date.now() - 60_000).toISOString(), c.id);
  assert.equal((await pr.charges.get(c.id)).status, "expired");
  assert.ok(await waitFor(() => events("charge.expired").some((e) => e.data.id === c.id)));
  assert.match(await (await fetch(`${base}/c/${c.id}`)).text(), /venció/);
  const next = await pr.charges.create({ account: account.id, amount: 50000 });
  assert.notEqual(next.amount, c.amount, "an expired charge's amount isn't reused right away");

  await pay(c.amount, { when: new Date(Date.now() - 90_000) });
  assert.ok(await waitFor(() => events("charge.paid").some((e) => e.data.id === c.id)));
  assert.equal(events("charge.paid").find((e) => e.data.id === c.id).data.late, true);
  assert.equal((await pr.charges.get(c.id)).status, "paid");
});

test("a payment can be linked by hand", async () => {
  const c = await pr.charges.create({ account: account.id, amount: 30000, reference: "order-manual" });
  const round = events("payment.received").find((e) => e.data.amount === 30000).data;
  const linked = await pr.charges.pay(c.id, round.id);
  assert.equal(linked.status, "paid");
  assert.equal(linked.paymentId, round.id);
  assert.ok(await waitFor(() => events("charge.paid").some((e) => e.data.id === c.id && e.data.manual === true)));
  const again = await pr.charges.create({ account: account.id, amount: 30000 });
  await rejects(pr.charges.pay(again.id, round.id), 409);
  await rejects(pr.charges.pay(again.id, "pay_nope"), 404);
  const foreign = events("payment.received").find((e) => e.data.accountId === account2.id).data;
  await rejects(pr.charges.pay(again.id, foreign.id), 409);
});

test("deleting an account cancels its open charges", async () => {
  const temp = await pr.accounts.create({ name: "Temporal", ownerEmails: [OWNER] });
  const c = await pr.charges.create({ account: temp.id, amount: 7000 });
  assert.deepEqual(await pr.accounts.remove(temp.id), { id: temp.id, deleted: true });
  assert.equal((await pr.charges.get(c.id)).status, "canceled");
});

test("a disabled account can't take charges", async () => {
  await pr.accounts.update(account2.id, { active: false });
  await rejects(pr.charges.create({ account: account2.id, amount: 1000 }), 409);
});
