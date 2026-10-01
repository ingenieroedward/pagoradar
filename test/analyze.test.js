import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeEmail } from "../src/analyze.js";
import { OWNER, bancolombiaEmail, buildEmail, gmailConfirmationEmail, nequiNegociosEmail, nequiNegociosHtml, nequiPersonalEmail, resolverFor, sign } from "./fixtures.js";

const opts = { ownerEmails: [OWNER], resolver: resolverFor() };

test("a genuine Nequi Negocios notice becomes a payment", async () => {
  const r = await analyzeEmail(await nequiNegociosEmail(), opts);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.payment.bank, "nequi_negocios");
  assert.equal(r.payment.amountCents, 2500000);
  assert.equal(r.payment.payerName, "Ana Maria Prueba Lopez");
  assert.equal(r.payment.payerNameNormalized, "ANA MARIA PRUEBA LOPEZ");
  assert.equal(r.payment.dkimDomain, "notificaciones.nequi.com.co");
  assert.match(r.payment.dedupeKey, /^[0-9a-f]{32}$/);
});

test("Nequi personal and Bancolombia notices", async () => {
  const n = await analyzeEmail(await nequiPersonalEmail(), opts);
  assert.equal(n.ok, true, n.reason);
  assert.equal(n.payment.bank, "nequi");
  assert.equal(n.payment.amountCents, 10000000);
  const b = await analyzeEmail(await bancolombiaEmail(), opts);
  assert.equal(b.ok, true, b.reason);
  assert.equal(b.payment.bank, "bancolombia");
  assert.equal(b.payment.amountCents, 400000);
});

test("same transaction twice -> same dedupe key", async () => {
  const a = await analyzeEmail(await nequiNegociosEmail({ tx: "tx-1" }), opts);
  const b = await analyzeEmail(await nequiNegociosEmail({ tx: "tx-1" }), opts);
  const c = await analyzeEmail(await nequiNegociosEmail({ tx: "tx-2" }), opts);
  assert.equal(a.payment.dedupeKey, b.payment.dedupeKey);
  assert.notEqual(a.payment.dedupeKey, c.payment.dedupeKey);
});

test("unsigned email claiming to be Nequi is refused", async () => {
  const raw = Buffer.from(buildEmail({ from: "notificaciones@nequi.com.co", subject: "Detalle de tu venta por Bre-B", html: nequiNegociosHtml() }));
  const r = await analyzeEmail(raw, opts);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "dkim_failed");
});

test("a signed email whose body was changed afterwards is refused", async () => {
  const raw = (await nequiNegociosEmail()).toString().replace("$ 25.000", "$ 2.500.000");
  const r = await analyzeEmail(Buffer.from(raw), opts);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "dkim_failed");
});

test("validly signed, but by someone who is not the bank", async () => {
  const raw = await sign(buildEmail({ from: "notificaciones@nequi.com.co", subject: "Venta", html: nequiNegociosHtml() }), "evil.example");
  assert.equal((await analyzeEmail(raw, opts)).reason, "not_a_bank");
  const own = await sign(buildEmail({ from: "pagos@evil.example", subject: "Venta", html: nequiNegociosHtml() }), "evil.example");
  assert.equal((await analyzeEmail(own, opts)).reason, "not_a_bank");
});

test("bank-signed but From is another domain -> refused", async () => {
  const raw = await sign(buildEmail({ from: "alertas@evil.example", subject: "Venta", html: nequiNegociosHtml() }), "notificaciones.nequi.com.co");
  assert.equal((await analyzeEmail(raw, opts)).reason, "not_a_bank");
});

test("a genuine notice for SOMEONE ELSE's account (forwarded here) is refused", async () => {
  const raw = await nequiNegociosEmail({}, { to: "otra.persona@gmail.com" });
  assert.equal((await analyzeEmail(raw, opts)).reason, "not_owner");
});

test("signature that doesn't cover To, or only part of the body (l=), doesn't count", async () => {
  const noTo = await sign(buildEmail({ from: "notificaciones@nequi.com.co", subject: "Venta", html: nequiNegociosHtml() }), "notificaciones.nequi.com.co", { headerList: "From:Subject:Date" });
  assert.equal((await analyzeEmail(noTo, opts)).reason, "weak_signature");
  const partial = await sign(buildEmail({ from: "notificaciones@nequi.com.co", subject: "Venta", html: nequiNegociosHtml() }), "notificaciones.nequi.com.co", { bodyLength: 50 });
  assert.equal((await analyzeEmail(partial, opts)).reason, "weak_signature");
});

test("rejected sale and unknown format", async () => {
  assert.equal((await analyzeEmail(await nequiNegociosEmail({ status: "Rechazada" }), opts)).reason, "not_approved");
  const promo = await sign(buildEmail({ from: "notificaciones@nequi.com.co", subject: "Novedades", html: "<p>Conoce lo nuevo de Nequi</p>" }), "notificaciones.nequi.com.co");
  assert.equal((await analyzeEmail(promo, opts)).reason, "unrecognized");
});

test("bank not enabled for the source", async () => {
  assert.equal((await analyzeEmail(await bancolombiaEmail(), { ...opts, banks: ["nequi_negocios"] })).reason, "not_a_bank");
});

test("duplicate From headers are refused", async () => {
  const raw = await nequiNegociosEmail({}, { extraHeaders: "From: otro@evil.example\r\n" });
  assert.equal((await analyzeEmail(raw, opts)).reason, "ambiguous_headers");
});

test("Gmail forwarding confirmation: the code is read", async () => {
  const raw = await gmailConfirmationEmail();
  const r = await analyzeEmail(raw, opts);
  assert.equal(r.reason, "gmail_forwarding_confirmation");
  assert.equal(r.code, "123456789");
  // Code only in the subject, body worded differently.
  const other = await gmailConfirmationEmail({ subject: "(#555666777) Confirmación de reenvío de Gmail: recibir correo de x@gmail.com", text: "Para confirmar esta solicitud, haz clic en el siguiente vínculo." });
  assert.equal((await analyzeEmail(other, opts)).code, "555666777");
  const linkOnly = await gmailConfirmationEmail({ subject: "Confirmación de reenvío de Gmail", text: null, html: '<p><a href="https://mail-settings.google.com/mail/vf-%5BABC%5D-xyz?a=1&amp;b=2">Confirmar</a></p>' });
  assert.equal((await analyzeEmail(linkOnly, opts)).link, "https://mail-settings.google.com/mail/vf-%5BABC%5D-xyz?a=1&b=2");
  // A fake one (not signed by Google) doesn't put a code on screen.
  const fake = Buffer.from(buildEmail({ from: "forwarding-noreply@google.com", subject: "(#999999999) Confirmación de reenvío de Gmail", text: "Código de confirmación: 999999999" }));
  const r2 = await analyzeEmail(fake, opts);
  assert.equal(r2.reason, "dkim_failed");
  assert.equal(r2.code, undefined);
});

test("garbage doesn't throw", async () => {
  const r = await analyzeEmail(Buffer.from("not an email at all"), opts);
  assert.equal(r.ok, false);
});
