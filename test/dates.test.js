import { test } from "node:test";
import assert from "node:assert/strict";
import { parseLongDate, parseNumericDate } from "../src/dates.js";

test("Colombian wall-clock time becomes UTC (UTC-5)", () => {
  assert.equal(parseNumericDate("01/10/2026 10:22:53"), "2026-10-01T15:22:53.000Z");
  assert.equal(parseNumericDate("30/09/26", "18:16"), "2026-09-30T23:16:00.000Z");
  assert.equal(parseNumericDate("30/09/2026", "6:16 p.m."), "2026-09-30T23:16:00.000Z");
  assert.equal(parseLongDate("16 de septiembre de 2026 a las 7:09 p.m"), "2026-09-17T00:09:00.000Z");
  assert.equal(parseLongDate("3 de enero de 2027 a las 12:05 a. m."), "2027-01-03T05:05:00.000Z");
});

test("impossible dates are rejected", () => {
  assert.equal(parseNumericDate("31/02/2026 10:00"), null);
  assert.equal(parseLongDate("5 de brumario de 2026"), null);
});
