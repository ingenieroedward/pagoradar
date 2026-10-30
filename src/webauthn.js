import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";

/**
 * Passkeys (WebAuthn), with node:crypto alone. Attestation is "none": a passkey is only added from a signed-in
 * session that also gave a 2-step code, so who made the key doesn't matter, and the browser hands over the public
 * key as SPKI (getPublicKey) — no CBOR to parse. A sign-in requires user verification (fingerprint, face or PIN), so
 * the passkey counts as both factors.
 */

const ES256 = -7;
const RS256 = -257;
export const PASSKEY_ALGS = [ES256, RS256];
const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_ATTESTED = 0x40;
const CHALLENGE_TTL_MS = 5 * 60_000;
const MAX_CHALLENGES = 5000;

const fromB64 = (s) => Buffer.from(String(s ?? ""), "base64url");
const sha256 = (b) => createHash("sha256").update(b).digest();

// Challenges live in memory: this is one process, and a restart only makes someone try again.
const challenges = new Map();

/** A new one-time challenge for `owner` (who may answer it: this browser's login form, or this signed-in person). */
export function newChallenge(owner, now = Date.now()) {
  for (const [c, v] of challenges) if (v.expires <= now) challenges.delete(c);
  while (challenges.size >= MAX_CHALLENGES) challenges.delete(challenges.keys().next().value);
  const challenge = randomBytes(32).toString("base64url");
  challenges.set(challenge, { owner, expires: now + CHALLENGE_TTL_MS });
  return challenge;
}

/** Is this challenge one we gave `owner`, still valid? It can only be asked once, whatever the answer. */
function takeChallenge(challenge, owner, now) {
  const found = challenges.get(challenge);
  challenges.delete(challenge);
  return Boolean(found) && found.owner === owner && found.expires > now;
}

function checkClientData(clientDataJSON, type, origin, owner, now) {
  let data;
  try {
    data = JSON.parse(fromB64(clientDataJSON).toString("utf8"));
  } catch {
    return false;
  }
  return data?.type === type && data.origin === origin && data.crossOrigin !== true && takeChallenge(String(data.challenge), owner, now);
}

/** The fixed part of the authenticator data, already checked: right site, the user was there and verified. */
function readAuthData(raw, rpId, requiredFlags) {
  if (raw.length < 37 || !raw.subarray(0, 32).equals(sha256(rpId))) return null;
  const flags = raw[32];
  if ((flags & requiredFlags) !== requiredFlags) return null;
  return { signCount: raw.readUInt32BE(33) };
}

/** Only keys we can trust to verify: P-256 for ES256, RSA of at least 2048 bits for RS256. */
function usableKey(spki, alg) {
  try {
    const key = createPublicKey({ key: spki, format: "der", type: "spki" });
    const d = key.asymmetricKeyDetails;
    if (alg === ES256) return key.asymmetricKeyType === "ec" && d?.namedCurve === "prime256v1";
    if (alg === RS256) return key.asymmetricKeyType === "rsa" && d?.modulusLength >= 2048;
  } catch {}
  return false;
}

/**
 * The browser's answer to navigator.credentials.create(). Returns what to store
 * ({ id, publicKey, alg, signCount, transports }) or null.
 */
export function verifyRegistration(body, { rpId, origin, owner, now = Date.now() }) {
  if (!checkClientData(body?.clientDataJSON, "webauthn.create", origin, owner, now)) return null;
  const raw = fromB64(body.authenticatorData);
  const auth = readAuthData(raw, rpId, FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED);
  if (!auth || raw.length < 55) return null;
  const idLength = raw.readUInt16BE(53);
  const id = raw.subarray(55, 55 + idLength);
  if (idLength === 0 || idLength > 1023 || id.length !== idLength || id.toString("base64url") !== body.id) return null;
  const alg = Number(body.alg);
  const spki = fromB64(body.publicKey);
  if (!PASSKEY_ALGS.includes(alg) || !usableKey(spki, alg)) return null;
  const transports = Array.isArray(body.transports) ? body.transports.filter((t) => typeof t === "string" && t.length <= 20).slice(0, 8) : [];
  return { id: body.id, publicKey: spki.toString("base64url"), alg, signCount: auth.signCount, transports };
}

/** The browser's answer to navigator.credentials.get(), for the stored `passkey`. Returns the new sign count or null. */
export function verifyAssertion(body, passkey, { rpId, origin, owner, now = Date.now() }) {
  if (!checkClientData(body?.clientDataJSON, "webauthn.get", origin, owner, now)) return null;
  const raw = fromB64(body.authenticatorData);
  const auth = readAuthData(raw, rpId, FLAG_USER_PRESENT | FLAG_USER_VERIFIED);
  if (!auth) return null;
  // A counter that doesn't go up means a cloned key. Synced passkeys always say 0, and that's fine.
  if ((auth.signCount !== 0 || passkey.signCount !== 0) && auth.signCount <= passkey.signCount) return null;
  try {
    const key = createPublicKey({ key: fromB64(passkey.publicKey), format: "der", type: "spki" });
    const signed = Buffer.concat([raw, sha256(fromB64(body.clientDataJSON))]);
    return verify("sha256", signed, key, fromB64(body.signature)) ? auth.signCount : null;
  } catch {
    return null;
  }
}
