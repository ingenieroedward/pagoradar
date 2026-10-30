import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { openStore } from "../src/store.js";
import { createApp } from "../src/app.js";
import { hashPassword, masterKeyFrom, totpAt, totpStep } from "../src/security.js";

const masterKey = masterKeyFrom("bc".repeat(32));
const TOTP = "JBSWY3DPEHPK3PXP";
let store, server, base, passwordHash;
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${srv.address().port}`)));
const config = { ingestSecret: "i".repeat(40), masterKey, publicUrl: null, legacySources: [], retentionDays: 180 };

before(async () => {
  store = openStore(":memory:", { masterKey });
  server = createServer(createApp({ store, config, log: () => {} }));
  base = await listen(server);
  passwordHash = await hashPassword("una-clave-larga");
});
after(() => {
  server.close();
  store.close();
});

/** A new person for each test: a code can be tried 10 times per person in 15 minutes. */
function newPerson(role = "admin") {
  const person = store.admins.create({ email: `${randomBytes(6).toString("hex")}@example.com`, passwordHash, role });
  store.admins.setTotp(person.id, TOTP, -1);
  return person;
}

const b64 = (b) => Buffer.from(b).toString("base64url");
const sha256 = (b) => createHash("sha256").update(b).digest();
const rpId = () => new URL(base).hostname;

/** A tiny browser: keeps cookies, doesn't follow redirects. `session` starts it signed in. */
function browser(session) {
  const jar = new Map(session ? [["pr_s", session]] : []);
  // Its own address, so the tests don't add up to the limit of attempts per IP.
  const ip = `10.${randomBytes(3).join(".")}`;
  const req = async (path, { method = "GET", json, form, csrf, srv = base } = {}) => {
    const headers = { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "), "cf-connecting-ip": ip };
    if (csrf) headers["x-csrf"] = csrf;
    let body;
    if (json) (headers["content-type"] = "application/json"), (body = JSON.stringify(json));
    if (form) (headers["content-type"] = "application/x-www-form-urlencoded"), (body = new URLSearchParams(form).toString());
    const res = await fetch(srv + path, { method, headers, body, redirect: "manual" });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const i = pair.indexOf("=");
      jar.set(pair.slice(0, i), decodeURIComponent(pair.slice(i + 1)));
    }
    const text = await res.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {}
    return { status: res.status, location: res.headers.get("location"), text, data };
  };
  return { req, jar };
}
const signedIn = (person) => {
  const b = browser(store.sessions.create(person.id, "full", "127.0.0.1"));
  b.csrf = store.db.prepare("SELECT csrf FROM sessions ORDER BY created_at DESC, rowid DESC LIMIT 1").get().csrf;
  return b;
};
/** A browser on the login page: the form's token doubles as the cookie, so it's what the page sends in X-CSRF. */
async function atLogin(srv = base) {
  const b = browser();
  await b.req("/login", { srv });
  b.csrf = b.jar.get("pr_c");
  return b;
}
/** A fresh code for the person, whatever was used before. */
const freshCode = (person) => {
  store.admins.setTotp(person.id, TOTP, -1);
  return totpAt(TOTP, totpStep());
};

const authData = ({ rp = rpId(), flags = 0x05, signCount = 0, credId = null } = {}) => {
  const count = Buffer.alloc(4);
  count.writeUInt32BE(signCount);
  const parts = [sha256(rp), Buffer.from([flags]), count];
  if (credId) {
    const len = Buffer.alloc(2);
    len.writeUInt16BE(credId.length);
    parts.push(Buffer.alloc(16), len, credId);
  }
  return Buffer.concat(parts);
};
const clientData = (type, challenge, { origin = base, ...extra } = {}) => Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false, ...extra }));

/** What a real authenticator and browser would answer, each part overridable to fake an attack. */
function authenticator({ alg = -7, keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" }) } = {}) {
  const credId = randomBytes(32);
  const key = {
    id: b64(credId),
    create(challenge, { flags = 0x45, ...over } = {}) {
      return {
        id: b64(credId),
        name: "Mi llave",
        alg,
        clientDataJSON: b64(clientData("webauthn.create", challenge, over)),
        authenticatorData: b64(authData({ flags, credId, rp: over.rp })),
        publicKey: b64(keys.publicKey.export({ type: "spki", format: "der" })),
        transports: ["internal"],
      };
    },
    get(challenge, { signCount = 0, flags = 0x05, type = "webauthn.get", rp, origin, tamper = false } = {}) {
      const cd = clientData(type, challenge, origin ? { origin } : {});
      const ad = authData({ flags, signCount, rp });
      const signature = sign("sha256", Buffer.concat([ad, sha256(cd)]), keys.privateKey);
      if (tamper) signature[signature.length - 1] ^= 1;
      return { id: b64(credId), clientDataJSON: b64(cd), authenticatorData: b64(ad), signature: b64(signature) };
    },
  };
  return key;
}

async function register(person, key = authenticator(), over = {}) {
  const b = signedIn(person);
  const options = await b.req("/me/passkeys/options", { method: "POST", json: { code: freshCode(person) }, csrf: b.csrf });
  assert.equal(options.status, 200, options.text);
  const r = await b.req("/me/passkeys/register", { method: "POST", json: key.create(options.data.challenge, over), csrf: b.csrf });
  return { r, b, options: options.data, key };
}
const loginOptions = async (b, srv = base) => (await b.req("/login/passkey/options", { method: "POST", csrf: b.csrf, srv })).data;
const signInWith = (b, body, srv = base) => b.req("/login/passkey", { method: "POST", json: body, csrf: b.csrf, srv });

test("adding a passkey takes a full session, the CSRF token and a current 2-step code", async () => {
  const admin = newPerson();
  const anon = browser();
  assert.equal((await anon.req("/me/passkeys/options", { method: "POST", json: {} })).location, "/login");
  const b = signedIn(admin);
  assert.equal((await b.req("/me/passkeys/options", { method: "POST", json: { code: freshCode(admin) } })).status, 403, "no CSRF");
  const bad = await b.req("/me/passkeys/options", { method: "POST", json: { code: "000000" }, csrf: b.csrf });
  assert.equal(bad.status, 400);
  assert.match(bad.data.error, /Código incorrecto/);
  assert.equal((await b.req("/me/passkeys/options", { method: "POST", json: { code: 123456 }, csrf: b.csrf })).status, 400, "not even a string");
  assert.equal(store.passkeys.listFor(admin.id).length, 0);

  const { r, options, key } = await register(admin);
  assert.equal(r.status, 200, r.text);
  assert.equal(r.data.redirect, "/me?ok=passkey");
  assert.equal(options.rp.id, rpId());
  assert.equal(options.authenticatorSelection.userVerification, "required");
  assert.equal(options.authenticatorSelection.residentKey, "required");
  const [stored] = store.passkeys.listFor(admin.id);
  assert.equal(stored.id, key.id);
  assert.equal(stored.name, "Mi llave");
  assert.deepEqual(stored.transports, ["internal"]);
  const again = await signedIn(admin).req("/me", {});
  assert.match(again.text, /Mi llave/);
  assert.match(store.audit.list(5).map((a) => a.action).join(), /Agregó una passkey/);
});

test("a registration is refused when anything doesn't add up", async () => {
  const admin = newPerson();
  const client = newPerson("client");
  const refused = async (over, why, key = authenticator()) => {
    const { r } = await register(admin, key, over);
    assert.equal(r.status, 400, why);
    assert.equal(store.passkeys.listFor(admin.id).length, 0, why);
  };
  await refused({ origin: "https://sitio-falso.example" }, "another origin");
  await refused({ rp: "sitio-falso.example" }, "another site's rpId");
  await refused({ flags: 0x41 }, "user not verified");
  await refused({ flags: 0x05 }, "no attested credential");
  await refused({}, "P-384 isn't what it claims", authenticator({ keys: generateKeyPairSync("ec", { namedCurve: "secp384r1" }) }));
  await refused({}, "weak RSA", authenticator({ alg: -257, keys: generateKeyPairSync("rsa", { modulusLength: 1024 }) }));
  await refused({}, "unsupported algorithm", authenticator({ alg: -8 }));

  // A challenge answers once, and only for whoever asked for it.
  const b = signedIn(admin);
  const key = authenticator();
  const { data } = await b.req("/me/passkeys/options", { method: "POST", json: { code: freshCode(admin) }, csrf: b.csrf });
  const other = signedIn(client);
  assert.equal((await other.req("/me/passkeys/register", { method: "POST", json: key.create(data.challenge), csrf: other.csrf })).status, 400, "someone else's challenge");
  assert.equal((await b.req("/me/passkeys/register", { method: "POST", json: key.create(data.challenge), csrf: b.csrf })).status, 400, "already spent");
  const wrongId = authenticator().create(data.challenge);
  wrongId.id = b64(randomBytes(32));
  assert.equal((await b.req("/me/passkeys/register", { method: "POST", json: wrongId, csrf: b.csrf })).status, 400, "id not the one in the authenticator data");

  // The same credential can't be taken over by someone else.
  const shared = authenticator();
  assert.equal((await register(admin, shared)).r.status, 200);
  assert.equal((await register(client, shared)).r.status, 400);
  assert.equal(store.passkeys.get(shared.id).adminId, admin.id);
});

test("signing in with a passkey needs no password nor code, and starts a full session", async () => {
  const admin = newPerson();
  const { key } = await register(admin);
  const page = await browser().req("/login");
  assert.match(page.text, /data-passkey-login/);
  const b = await atLogin();
  assert.equal((await b.req("/login/passkey/options", { method: "POST" })).status, 403, "no CSRF");
  const options = await loginOptions(b);
  assert.equal(options.rpId, rpId());
  assert.equal(options.userVerification, "required");
  assert.equal(options.allowCredentials, undefined, "the browser offers its passkeys: no email to enumerate");
  const r = await signInWith(b, key.get(options.challenge));
  assert.equal(r.status, 200, r.text);
  assert.equal(r.data.redirect, "/");
  assert.equal((await b.req("/")).status, 200, "signed in");
  assert.match(store.audit.list(5).map((a) => a.action).join(), /Entró al panel con passkey/);
  assert.ok(store.passkeys.get(key.id).lastUsedAt);
  assert.ok(store.admins.get(admin.id).lastLoginAt);
});

test("a sign-in is refused when anything doesn't add up", async () => {
  const admin = newPerson();
  const { key } = await register(admin);
  const refused = async (over, why) => {
    const b = await atLogin();
    const r = await signInWith(b, key.get((await loginOptions(b)).challenge, over));
    assert.equal(r.status, 400, why);
    assert.equal((await b.req("/")).location, "/login", why);
  };
  await refused({ origin: "https://sitio-falso.example" }, "phishing site");
  await refused({ rp: "sitio-falso.example" }, "another site's rpId");
  await refused({ flags: 0x01 }, "user not verified");
  await refused({ flags: 0x04 }, "user not present");
  await refused({ type: "webauthn.create" }, "a registration's data");
  await refused({ tamper: true }, "bad signature");

  // A challenge works once, only in the browser that asked, and never one meant for adding a passkey.
  let b = await atLogin();
  let { challenge } = await loginOptions(b);
  const thief = await atLogin();
  assert.equal((await signInWith(thief, key.get(challenge))).status, 400, "another browser's challenge");
  assert.equal((await signInWith(b, key.get(challenge))).status, 400, "spent by that attempt");
  b = await atLogin();
  ({ challenge } = await loginOptions(b));
  assert.equal((await signInWith(b, key.get(challenge))).status, 200);
  assert.equal((await signInWith(b, key.get(challenge))).status, 400, "replay");
  b = await atLogin();
  assert.equal((await signInWith(b, key.get(randomBytes(32).toString("base64url")))).status, 400, "a challenge we never gave");
  const s = signedIn(admin);
  const add = await s.req("/me/passkeys/options", { method: "POST", json: { code: freshCode(admin) }, csrf: s.csrf });
  b = await atLogin();
  assert.equal((await signInWith(b, key.get(add.data.challenge))).status, 400, "an add-passkey challenge");

  b = await atLogin();
  const unknown = authenticator();
  assert.equal((await signInWith(b, unknown.get((await loginOptions(b)).challenge))).status, 400, "unknown passkey");
});

test("the counter: going up is fine, not going up means a cloned key; synced passkeys stay at 0", async () => {
  const admin = newPerson();
  const { key } = await register(admin);
  const go = async (signCount) => {
    const b = await atLogin();
    return (await signInWith(b, key.get((await loginOptions(b)).challenge, { signCount }))).status;
  };
  assert.equal(await go(0), 200, "synced passkeys say 0");
  assert.equal(await go(0), 200);
  assert.equal(await go(5), 200);
  assert.equal(store.passkeys.get(key.id).signCount, 5);
  assert.equal(await go(5), 400, "same count");
  assert.equal(await go(3), 400, "went back");
  assert.equal(await go(0), 400, "back to 0");
  assert.equal(await go(6), 200);
});

test("RSA passkeys work too", async () => {
  const admin = newPerson();
  const key = authenticator({ alg: -257, keys: generateKeyPairSync("rsa", { modulusLength: 2048 }) });
  assert.equal((await register(admin, key)).r.status, 200);
  const b = await atLogin();
  assert.equal((await signInWith(b, key.get((await loginOptions(b)).challenge))).status, 200);
});

test("with PUBLIC_URL, passkeys belong to that site whatever the request's Host says", async (t) => {
  const publicUrl = "https://pagoradar.example.com";
  const srv = createServer(createApp({ store, config: { ...config, publicUrl }, log: () => {} }));
  const url = await listen(srv);
  t.after(() => srv.close());
  const { key } = await register(newPerson());
  const b = await atLogin(url);
  const options = await loginOptions(b, url);
  assert.equal(options.rpId, "pagoradar.example.com");
  assert.equal((await signInWith(b, key.get(options.challenge), url)).status, 400, "signed for the Host, not the site");
  const b2 = await atLogin(url);
  const o2 = await loginOptions(b2, url);
  assert.equal((await signInWith(b2, key.get(o2.challenge, { origin: publicUrl, rp: "pagoradar.example.com" }), url)).status, 200);
});

test("removing passkeys: your own, or an admin for someone who lost a device; never someone else's as a client", async () => {
  const admin = newPerson();
  const client = newPerson("client");
  const mine = (await register(client)).key;
  const adminKey = (await register(admin)).key;
  const c = signedIn(client);
  const ownPage = await c.req("/me");
  assert.match(ownPage.text, new RegExp(`/me/passkeys/${mine.id}/delete`));
  const token = ownPage.text.match(/name="_csrf" value="([^"]+)"/)[1];
  await c.req(`/me/passkeys/${adminKey.id}/delete`, { method: "POST", form: { _csrf: token } });
  assert.ok(store.passkeys.get(adminKey.id), "not someone else's");
  assert.equal((await c.req(`/settings/admins/${admin.id}/passkeys/delete`, { method: "POST", form: { _csrf: token } })).status, 404, "a client can't");
  assert.ok(store.passkeys.get(adminKey.id));

  const a = signedIn(admin);
  const person = await a.req(`/settings/admins/${client.id}`);
  assert.match(person.text, /Quitar sus passkeys/);
  const adminToken = person.text.match(/name="_csrf" value="([^"]+)"/)[1];
  const r = await a.req(`/settings/admins/${client.id}/passkeys/delete`, { method: "POST", form: { _csrf: adminToken } });
  assert.equal(r.location, `/settings/admins/${client.id}?ok=passkey-removed`);
  assert.equal(store.passkeys.get(mine.id), undefined);
  const b = await atLogin();
  assert.equal((await signInWith(b, mine.get((await loginOptions(b)).challenge))).status, 400, "that passkey no longer gets in");

  await a.req(`/me/passkeys/${adminKey.id}/delete`, { method: "POST", form: { _csrf: adminToken } });
  assert.equal(store.passkeys.get(adminKey.id), undefined);
});

test("a person removed from pagoradar can't get back in with a passkey; a client stays a client", async () => {
  const person = newPerson("client");
  const { key } = await register(person);
  let b = await atLogin();
  assert.equal((await signInWith(b, key.get((await loginOptions(b)).challenge))).status, 200);
  assert.equal((await b.req("/settings")).status, 404, "same access as with a password");
  store.admins.remove(person.id);
  assert.equal(store.passkeys.get(key.id), undefined);
  b = await atLogin();
  assert.equal((await signInWith(b, key.get((await loginOptions(b)).challenge))).status, 400);
});
