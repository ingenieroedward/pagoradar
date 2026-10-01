import { test } from "node:test";
import assert from "node:assert/strict";
import { decrypt, encrypt, hashPassword, masterKeyFrom, totpAt, verifyPassword, verifyTotp } from "../src/security.js";

test("TOTP matches RFC 6238 (SHA-1 test vector, 6 digits)", () => {
  // Secret "12345678901234567890" in base32; at T=59 s (step 1) the 8-digit code is 94287082.
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(totpAt(secret, 1), "287082");
  assert.equal(totpAt(secret, Math.floor(1111111109 / 30)), "081804");
  assert.equal(verifyTotp(secret, "287082", { now: 59_000 }), 1);
  assert.equal(verifyTotp(secret, "287 082", { now: 59_000 }), 1, "spaces are fine");
  assert.equal(verifyTotp(secret, "287082", { now: 59_000, lastStep: 1 }), null, "a used code is refused");
  assert.equal(verifyTotp(secret, "287082", { now: 59_000 + 120_000 }), null, "too old");
  assert.equal(verifyTotp(secret, "abc", { now: 59_000 }), null);
});

test("secrets at rest: AES-GCM round trip, tampering detected, key format enforced", () => {
  const key = masterKeyFrom("11".repeat(32));
  const box = encrypt(key, "whsec_hola");
  assert.notEqual(box, "whsec_hola");
  assert.equal(decrypt(key, box), "whsec_hola");
  const parts = box.split(".");
  parts[3] = Buffer.from("otra cosa").toString("base64url");
  assert.throws(() => decrypt(key, parts.join(".")));
  assert.throws(() => decrypt(masterKeyFrom("22".repeat(32)), box), "another key can't read it");
  assert.throws(() => masterKeyFrom("corta"), /MASTER_KEY/);
});

test("passwords: scrypt, verify, wrong password", async () => {
  const h = await hashPassword("una-clave-larga");
  assert.match(h, /^scrypt\$/);
  assert.equal(await verifyPassword("una-clave-larga", h), true);
  assert.equal(await verifyPassword("otra-clave", h), false);
  assert.equal(await verifyPassword("x", "basura"), false);
});
