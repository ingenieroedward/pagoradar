import { test } from "node:test";
import assert from "node:assert/strict";
import { htmlToText, normalizeName, titleCase } from "../src/text.js";
import { nequiNegocios } from "../src/parsers/nequiNegocios.js";
import { nequi } from "../src/parsers/nequi.js";
import { bancolombia } from "../src/parsers/bancolombia.js";
import { bancolombiaText, nequiNegociosHtml, nequiPersonalHtml } from "./fixtures.js";

test("Nequi Negocios: every field of the sale", () => {
  const text = htmlToText(nequiNegociosHtml());
  assert.ok(nequiNegocios.matches(text));
  assert.deepEqual(nequiNegocios.parse(text), {
    approved: true,
    amountCents: 2500000,
    payerName: "ANA MARIA PRUEBA LOPEZ",
    payerBank: "Banco de Pruebas",
    reference: "M00000001",
    transactionId: "abc123def456",
    method: "breb_qr",
    methodText: "QR Negocios Bre-B",
    accountHint: null,
    paidAt: "2026-10-01T15:22:53.000Z",
  });
  assert.equal(nequiNegocios.parse(htmlToText(nequiNegociosHtml({ status: "Rechazada" }))).approved, false);
});

test("Nequi personal: amount, payer, bank and date from one sentence", () => {
  const text = htmlToText(nequiPersonalHtml());
  assert.ok(nequi.matches(text));
  const p = nequi.parse(text);
  assert.equal(p.amountCents, 10000000);
  assert.equal(p.payerName, "Carlos Andres Prueba Ruiz");
  assert.equal(p.payerBank, "Banco Uno");
  assert.equal(p.paidAt, "2026-09-17T00:09:00.000Z");
  assert.equal(p.method, "breb");
  assert.equal(nequi.matches("Enviaste 50.000 a Pedro el 1 de octubre de 2026"), false);
});

test("Bancolombia: US-style amount, account and llave", () => {
  const p = bancolombia.parse(bancolombiaText().replace(/\s+/g, " "));
  assert.equal(p.amountCents, 400000);
  assert.equal(p.payerName, "LUISA FERNANDA PRUEBA");
  assert.equal(p.accountHint, "*0000");
  assert.equal(p.methodText, "llave tienda@ejemplo.com");
  assert.equal(p.paidAt, "2026-09-30T23:16:00.000Z");
  const alt = bancolombia.parse("Bancolombia: Recibiste una transferencia por $50,000.00 de PEDRO PRUEBA en tu cuenta **1234, el 01/10/2026 a las 09:05.");
  assert.equal(alt.amountCents, 5000000);
  assert.equal(alt.payerName, "PEDRO PRUEBA");
  assert.equal(alt.method, "transfer");
});

test("names", () => {
  assert.equal(normalizeName("  José  Díaz-Pérez Muñoz "), "JOSE DIAZ PEREZ MUNOZ");
  assert.equal(titleCase("ANA MARÍA DE LA PEÑA"), "Ana María De La Peña");
});
