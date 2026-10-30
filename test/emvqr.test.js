import { test } from "node:test";
import assert from "node:assert/strict";
import { crc16, isEmvQr, parseTlv, withAmount } from "../src/emvqr.js";

const tlv = (id, v) => `${id}${String(v.length).padStart(2, "0")}${v}`;
/** A made-up static QR, like a bank's: no amount, no real account. */
const staticQr = (() => {
  const body = tlv("00", "01") + tlv("01", "11") + tlv("26", tlv("00", "CO.EJEMPLO") + tlv("01", "@tienda")) + tlv("52", "0000") + tlv("53", "170") + tlv("58", "CO") + tlv("59", "TIENDA PRUEBA") + tlv("60", "BOGOTA");
  return `${body}6304${crc16(`${body}6304`)}`;
})();

test("CRC-16/CCITT-FALSE, against its published check value", () => {
  assert.equal(crc16("123456789"), "29B1");
});

test("recognizes a whole payment QR and nothing else", () => {
  assert.equal(isEmvQr(staticQr), true);
  assert.equal(isEmvQr(staticQr.slice(0, -1)), false, "cut short");
  assert.equal(isEmvQr(staticQr.replace("TIENDA", "TIENDO")), false, "CRC doesn't match");
  assert.equal(isEmvQr(`${staticQr.slice(0, -4)}${staticQr.slice(-4).toLowerCase()}`), true, "CRC in lower case");
  for (const bad of ["", "hola", "https://example.com/pagar", null, undefined, 12345, "0002016304ZZZZ"]) assert.equal(isEmvQr(bad), false, String(bad));
});

test("adding the amount changes only that, and the result is still a valid QR", () => {
  const before = Object.fromEntries(parseTlv(staticQr).map((t) => [t.id, t.value]));
  const out = withAmount(staticQr, 101);
  assert.equal(isEmvQr(out), true);
  const tags = parseTlv(out);
  const after = Object.fromEntries(tags.map((t) => [t.id, t.value]));
  assert.equal(after["54"], "101");
  assert.equal(after["01"], "12", "marked as one-time");
  for (const id of ["00", "26", "52", "53", "58", "59", "60"]) assert.equal(after[id], before[id], `tag ${id} untouched`);
  assert.deepEqual(tags.map((t) => t.id), ["00", "01", "26", "52", "53", "54", "58", "59", "60", "63"], "in order, the CRC last");
  assert.equal(parseTlv(withAmount(staticQr, 101, "decimal")).find((t) => t.id === "54").value, "101.00");
  assert.equal(parseTlv(withAmount(staticQr, 1)).find((t) => t.id === "54").value, "1");
  const twice = withAmount(withAmount(staticQr, 500), 101);
  assert.equal(parseTlv(twice).filter((t) => t.id === "54").length, 1, "replaces an amount already there");
  assert.equal(parseTlv(twice).find((t) => t.id === "54").value, "101");
});

test("can add the amount and leave the QR's type as it was", () => {
  const out = withAmount(staticQr, 101, "keep");
  assert.equal(isEmvQr(out), true);
  const tags = parseTlv(out);
  assert.equal(tags.find((t) => t.id === "01").value, "11", "not marked as one-time");
  assert.equal(tags.find((t) => t.id === "54").value, "101");
  assert.deepEqual(tags.map((t) => t.id), ["00", "01", "26", "52", "53", "54", "58", "59", "60", "63"]);
  const noType = parseTlv(withAmount(`${tlv("00", "01")}${tlv("52", "0000")}6304ABCD`, 101, "keep"));
  assert.equal(noType.some((t) => t.id === "01"), false, "doesn't add one that wasn't there");
});
