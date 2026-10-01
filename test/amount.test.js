import { test } from "node:test";
import assert from "node:assert/strict";
import { parseAmountCents } from "../src/amount.js";

test("amounts as each bank writes them", () => {
  const cases = {
    "$ 100": 10000,
    "100.000": 10000000,
    "$ 1.250.000": 125000000,
    "$ 1.250.000,50": 125000050,
    "$4,000.00": 400000,
    "$1,250,000.5": 125000050,
    "25000": 2500000,
    "COP 3.500": 350000,
  };
  for (const [raw, cents] of Object.entries(cases)) assert.equal(parseAmountCents(raw), cents, raw);
});

test("things that are not amounts", () => {
  for (const raw of ["", "abc", "$", "1.000.50", "1,000.000,00", "12.34.5", null, "1.2345"]) assert.equal(parseAmountCents(raw), null, String(raw));
});
