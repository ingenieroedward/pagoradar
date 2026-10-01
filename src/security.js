import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, scrypt, timingSafeEqual } from "node:crypto";

/**
 * Small crypto helpers: secrets encrypted at rest with MASTER_KEY (AES-256-GCM), passwords (scrypt),
 * random tokens and TOTP (RFC 6238, what Google Authenticator & co. use).
 */

// ---------- encryption at rest

export function masterKeyFrom(hex) {
  if (!/^[0-9a-f]{64}$/i.test(String(hex ?? ""))) throw new Error("MASTER_KEY debe ser 64 caracteres hexadecimales (openssl rand -hex 32).");
  return Buffer.from(hex, "hex");
}

/** "v1.<iv>.<tag>.<ciphertext>" (base64url). */
export function encrypt(key, plain) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), data.toString("base64url")].join(".");
}

export function decrypt(key, boxed) {
  const [v, iv, tag, data] = String(boxed).split(".");
  if (v !== "v1" || !iv || !tag || data === undefined) throw new Error("Valor cifrado inválido");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
}

// ---------- tokens

export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const sha256 = (value) => createHash("sha256").update(String(value)).digest("hex");

export function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Lowercase letters and digits only, for addresses and ids people read. */
export function randomCode(length = 6) {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const bytes = randomBytes(length);
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

// ---------- passwords

const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function hashPassword(password) {
  const salt = randomBytes(16);
  return new Promise((resolve, reject) =>
    scrypt(String(password), salt, 32, SCRYPT, (err, key) =>
      err ? reject(err) : resolve(`scrypt$${SCRYPT.N}$${salt.toString("base64url")}$${key.toString("base64url")}`),
    ),
  );
}

export function verifyPassword(password, stored) {
  const [kind, n, salt, hash] = String(stored ?? "").split("$");
  if (kind !== "scrypt" || !salt || !hash) return Promise.resolve(false);
  return new Promise((resolve) =>
    scrypt(String(password), Buffer.from(salt, "base64url"), 32, { ...SCRYPT, N: Number(n) }, (err, key) =>
      resolve(!err && safeEqual(key.toString("base64url"), hash)),
    ),
  );
}

// ---------- TOTP (RFC 6238: SHA-1, 30 s, 6 digits)

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function newTotpSecret() {
  const bytes = randomBytes(20);
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

function base32Decode(s) {
  let bits = "";
  for (const ch of String(s).replace(/=+$/, "").toUpperCase()) {
    const v = B32.indexOf(ch);
    if (v === -1) continue;
    bits += v.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

export function totpAt(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, "0");
}

export const totpStep = (now = Date.now()) => Math.floor(now / 1000 / 30);

/**
 * The time step the code belongs to (accepting the previous and next one, for clock drift), or null.
 * Callers store the last accepted step so the same code can't be used twice.
 */
export function verifyTotp(secret, code, { now = Date.now(), lastStep = -1 } = {}) {
  const clean = String(code ?? "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(clean)) return null;
  const current = totpStep(now);
  for (const step of [current - 1, current, current + 1]) {
    if (step > lastStep && safeEqual(totpAt(secret, step), clean)) return step;
  }
  return null;
}

export function totpUri(secret, account, issuer = "pagoradar") {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
