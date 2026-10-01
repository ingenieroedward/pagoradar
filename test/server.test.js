import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { validateSources } from "../src/config.js";
import { openStore } from "../src/store.js";
import { createApp } from "../src/app.js";
import { deliverDue, RETRY_DELAYS_MS, verifySignature } from "../src/webhooks.js";
import { importLegacySources } from "../src/importLegacy.js";
import { masterKeyFrom } from "../src/security.js";
import { deliver } from "../worker/src/index.js";
import { OWNER, bancolombiaEmail, buildEmail, gmailConfirmationEmail, nequiNegociosEmail, resolverFor } from "./fixtures.js";

const INGEST_SECRET = "i".repeat(40);
const API_KEY = "k".repeat(32);
const HOOK_SECRET = "s".repeat(32);
const ADDRESS = "pagos-test@pagos.example.com";

let server, base, hookServer, received = [], hookStatus = 200, store, config;
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${srv.address().port}`)));

before(async () => {
  hookServer = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ headers: req.headers, body });
      res.writeHead(hookStatus).end();
    });
  });
  const hookBase = await listen(hookServer);
  config = { ingestSecret: INGEST_SECRET, masterKey: masterKeyFrom("ab".repeat(32)), publicUrl: null, legacySources: [] };
  store = openStore(":memory:", { masterKey: config.masterKey });
  // The old JSON configuration, imported into the database: app "rifas" with its key, secret and address.
  importLegacySources(store, validateSources([{ id: "rifas", addresses: [ADDRESS], ownerEmails: [OWNER], apiKey: API_KEY, webhooks: [{ url: `${hookBase}/hook`, secret: HOOK_SECRET }] }]));
  server = createServer(createApp({ config, store, resolver: resolverFor(), log: () => {} }));
  base = await listen(server);
});
after(() => {
  server.close();
  hookServer.close();
  store.close();
});

const env = () => ({ PAGORADAR_URL: base, INGEST_SECRET });
const ingest = (raw, to = ADDRESS, e = env()) => deliver(new Uint8Array(raw), { to, from: "reenvio@gmail.com" }, e, { sleep: async () => {} });
const waitFor = async (pred, ms = 3000) => {
  const t = Date.now();
  while (Date.now() - t < ms) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 20));
  }
  return false;
};

test("worker -> ingest -> payment stored -> signed webhook", async () => {
  assert.equal(await ingest(await nequiNegociosEmail({ tx: "e2e-1" })), true);
  assert.ok(await waitFor(() => received.length === 2), "webhooks arrived");
  const types = received.map((r) => JSON.parse(r.body).type).sort();
  assert.deepEqual(types, ["account.activated", "payment.received"], "first genuine notice also activates the account");
  assert.equal(store.accounts.byAddress(ADDRESS).status, "active");
  const hook = received.find((r) => JSON.parse(r.body).type === "payment.received");
  assert.ok(verifySignature(HOOK_SECRET, hook.headers["pagoradar-signature"], hook.body), "valid signature");
  assert.equal(verifySignature("otro-secreto-xxxxxxxxxxxxxxxx", hook.headers["pagoradar-signature"], hook.body), false);
  const event = JSON.parse(hook.body);
  assert.equal(event.type, "payment.received");
  assert.equal(hook.headers["pagoradar-event-id"], event.id);
  assert.equal(event.data.amount, 25000);
  assert.equal(event.data.payerName, "Ana Maria Prueba Lopez");
  assert.equal(event.data.source, "rifas");
  assert.equal(event.data.account.id, store.accounts.byAddress(ADDRESS).id);
  received = received.filter((r) => r === hook);
});

test("the same notice again is a duplicate: no second payment or webhook", async () => {
  const res = await rawIngest(await nequiNegociosEmail({ tx: "e2e-1" }));
  assert.deepEqual(await res.json(), { result: "duplicate" });
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(received.length, 1);
});

test("bad or old signature on /ingest -> 401; worker gives up without retrying", async () => {
  let calls = 0;
  const ok = await deliver(new Uint8Array(await bancolombiaEmail()), { to: ADDRESS, from: "x" }, { PAGORADAR_URL: base, INGEST_SECRET: "x".repeat(40) }, {
    sleep: async () => {},
    fetchImpl: async (...a) => (calls++, fetch(...a)),
  });
  assert.equal(ok, false);
  assert.equal(calls, 1);
  const raw = await bancolombiaEmail();
  const res = await fetch(`${base}/ingest`, { method: "POST", headers: { "X-Pagoradar-Timestamp": "1000", "X-Pagoradar-Signature": "00", "X-Pagoradar-To": ADDRESS }, body: raw });
  assert.equal(res.status, 401);
});

test("worker retries when the service is down", async () => {
  let calls = 0;
  const ok = await deliver(new Uint8Array([1]), { to: ADDRESS, from: "x" }, env(), {
    sleep: async () => {},
    fetchImpl: async () => {
      calls++;
      throw new Error("ECONNREFUSED");
    },
  });
  assert.equal(ok, false);
  assert.equal(calls, 3);
});

test("forged, foreign and unknown-address emails are rejected and kept in the inbox", async () => {
  const forged = Buffer.from(buildEmail({ from: "notificaciones@nequi.com.co", subject: "Detalle de tu venta por Bre-B", html: "<p>Venta exitosa por $ 999.999 Pagador: YO MISMO</p>" }));
  assert.deepEqual(await (await rawIngest(forged)).json(), { result: "rejected", reason: "dkim_failed" });
  assert.deepEqual(await (await rawIngest(await nequiNegociosEmail({ tx: "z" }, { to: "otro@gmail.com" }))).json(), { result: "rejected", reason: "not_owner" });
  assert.deepEqual(await (await rawIngest(await bancolombiaEmail(), "nadie@pagos.example.com")).json(), { result: "rejected", reason: "unknown_address" });
  const gmail = await gmailConfirmationEmail({ subject: "Confirmación de reenvío", text: "Código de confirmación: 987654321", to: ADDRESS });
  await rawIngest(gmail);
  const inbox = store.inbox.list();
  assert.deepEqual(inbox.map((i) => i.reason), ["gmail_forwarding_confirmation", "unknown_address", "not_owner", "dkim_failed"]);
  assert.equal(inbox[0].code, "987654321");
  assert.equal(inbox[3].snippet, null, "text of forged emails is not kept");
  const account = store.accounts.byAddress(ADDRESS);
  assert.equal(account.confirmationCode, "987654321", "the Gmail code is shown on the account");
});

test("GET /v1/payments with the app's API key (the imported legacy key works)", async () => {
  assert.equal((await fetch(`${base}/v1/payments`)).status, 401);
  assert.equal((await fetch(`${base}/v1/payments`, { headers: { Authorization: "Bearer nope" } })).status, 401);
  await ingest(await bancolombiaEmail());
  const auth = { headers: { Authorization: `Bearer ${API_KEY}` } };
  const all = await (await fetch(`${base}/v1/payments`, auth)).json();
  assert.deepEqual(all.payments.map((p) => p.bank), ["nequi_negocios", "bancolombia"]);
  const later = await (await fetch(`${base}/v1/payments?since=${encodeURIComponent(all.payments[0].receivedAt)}`, auth)).json();
  assert.deepEqual(later.payments.map((p) => p.bank), ["bancolombia"]);
  assert.equal((await fetch(`${base}/v1/payments?since=ayer`, auth)).status, 400);
});

test("webhook retries with backoff, then delivered; admin retry", async () => {
  received = [];
  hookStatus = 500;
  await ingest(await nequiNegociosEmail({ tx: "retry-1" }));
  assert.ok(await waitFor(() => received.length === 1));
  await new Promise((r) => setTimeout(r, 50));
  let d = store.deliveries.list({ status: "pending" })[0];
  assert.equal(d.attempts, 1);
  assert.equal(d.last_status, 500);
  // Not due yet: nothing is sent.
  assert.equal(await deliverDue(store), 0);
  hookStatus = 200;
  await deliverDue(store, { now: Date.now() + RETRY_DELAYS_MS[0] + 1000 });
  assert.equal(received.length, 2);
  assert.equal(store.deliveries.list({ status: "pending" }).length, 0);
  // gives up after the last delay
  hookStatus = 503;
  await ingest(await nequiNegociosEmail({ tx: "retry-2" }));
  await waitFor(() => received.length === 3);
  let now = Date.now();
  for (const delay of RETRY_DELAYS_MS) {
    now += delay + 1000;
    await deliverDue(store, { now });
  }
  d = store.deliveries.list({ status: "failed" })[0];
  assert.equal(d.attempts, RETRY_DELAYS_MS.length + 1);
  hookStatus = 200;
  assert.ok(store.deliveries.retry(d.id));
  await deliverDue(store);
  assert.equal(store.deliveries.list({ status: "failed" }).length, 0);
});

test("test webhook", async () => {
  received = [];
  const res = await fetch(`${base}/v1/webhooks/test`, { method: "POST", headers: { Authorization: `Bearer ${API_KEY}` } });
  assert.equal(res.status, 200);
  assert.ok(await waitFor(() => received.length === 1));
  assert.equal(JSON.parse(received[0].body).type, "payment.test");
});

test("health", async () => {
  assert.deepEqual(await (await fetch(`${base}/health`)).json(), { ok: true });
});

test("config validation", () => {
  assert.throws(() => validateSources([{ id: "A B" }]), /id/);
  assert.throws(() => validateSources([{ id: "a", addresses: ["x@y"], apiKey: API_KEY }]), /ownerEmails/);
  assert.throws(() => validateSources([{ id: "a", addresses: ["x@y"], ownerEmails: ["o@g"], apiKey: API_KEY, banks: ["daviplata"] }]), /banco desconocido/);
  assert.throws(() => validateSources([{ id: "a", addresses: ["x@y"], ownerEmails: ["o@g"], apiKey: "short" }]), /apiKey/);
  assert.throws(
    () => validateSources([
      { id: "a", addresses: ["x@y"], ownerEmails: ["o@g"], apiKey: API_KEY },
      { id: "b", addresses: ["X@y"], ownerEmails: ["o@g"], apiKey: API_KEY },
    ]),
    /ya es de otra fuente/,
  );
});

async function rawIngest(raw, to = ADDRESS) {
  const { signIngest } = await import("../worker/src/index.js");
  const ts = String(Math.floor(Date.now() / 1000));
  return fetch(`${base}/ingest`, { method: "POST", headers: { "X-Pagoradar-Timestamp": ts, "X-Pagoradar-Signature": await signIngest(INGEST_SECRET, ts, new Uint8Array(raw)), "X-Pagoradar-To": to }, body: raw });
}
