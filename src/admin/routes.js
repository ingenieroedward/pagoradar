import { readFileSync } from "node:fs";
import QRCode from "qrcode";
import { analyzeEmail } from "../analyze.js";
import { BANK_IDS, gmailFilterFor } from "../parsers/index.js";
import { clientIp, cookie, list, parseCookies, parseForm, rateLimiter, readBody, redirect, sendHtml, sendJson } from "../http.js";
import { hashPassword, newTotpSecret, randomToken, safeEqual, totpUri, verifyPassword, verifyTotp } from "../security.js";
import { chooseDomain, sendTestEvent } from "../api.js";
import { ACCESS_LEVELS } from "../store.js";
import { PASSKEY_ALGS, newChallenge, verifyAssertion, verifyRegistration } from "../webauthn.js";
import { deliverDue } from "../webhooks.js";
import { parseAmountCents } from "../amount.js";
import { createCharge, expireCharges, payManually } from "../charges.js";
import {
  BANK_LABEL,
  REASON_LABEL,
  fmtAgo,
  section,
  toggle,
  accountStatus,
  badge,
  icon,
  chargeStatus,
  copyable,
  csrfField,
  flash,
  fmtDate,
  fmtMoney,
  html,
  layout,
  postButton,
  raw,
} from "./ui.js";

const SESSION_COOKIE = "pr_s";
const PRE_CSRF_COOKIE = "pr_c";
const MIN_PASSWORD = 10;
const STATIC = {
  "/static/admin.css": { type: "text/css; charset=utf-8", file: new URL("../../public/admin.css", import.meta.url) },
  "/static/admin.js": { type: "text/javascript; charset=utf-8", file: new URL("../../public/admin.js", import.meta.url) },
  "/manifest.webmanifest": { type: "application/manifest+json; charset=utf-8", file: new URL("../../public/manifest.webmanifest", import.meta.url) },
  "/sw.js": { type: "text/javascript; charset=utf-8", file: new URL("../../public/sw.js", import.meta.url), cache: "no-cache" },
  // The Cloudflare Email Worker, for whoever sets up a domain in their own Cloudflare account (it holds no secrets).
  "/static/pagoradar-email-worker.js": { type: "text/javascript; charset=utf-8", file: new URL("../../worker/src/index.js", import.meta.url) },
  "/favicon.svg": { type: "image/svg+xml", file: new URL("../../public/favicon.svg", import.meta.url) },
  "/favicon.ico": { type: "image/png", file: new URL("../../public/icons/favicon-48.png", import.meta.url) },
  ...Object.fromEntries(
    ["icon-192.png", "icon-512.png", "maskable-512.png", "apple-touch-icon.png", "favicon-32.png", "icon.svg"].map((f) => [
      `/icons/${f}`,
      { type: f.endsWith(".svg") ? "image/svg+xml" : "image/png", file: new URL(`../../public/icons/${f}`, import.meta.url) },
    ]),
  ),
};
const loginLimit = rateLimiter(10, 15 * 60_000);
const passkeyLimit = rateLimiter(30, 15 * 60_000); // a sign-in takes two requests
const MAX_PASSKEYS = 10;
// Computed once at start-up, so even the first login for an unknown email takes as long as any other.
const dummy = hashPassword(randomToken(16));
const dummyHash = () => dummy;
const staticCache = new Map();

const MESSAGES = {
  saved: "Cambios guardados.",
  created: "Creado.",
  rotated: "Secreto del webhook cambiado: actualízalo en tu app.",
  revoked: "API key revocada.",
  retry: "Reintento programado.",
  test: "Evento de prueba enviado: mira el resultado en Entregas.",
  disabled: "Cuenta desactivada.",
  enabled: "Cuenta activada de nuevo.",
  deleted: "Eliminado.",
  password: "Contraseña cambiada.",
  "totp-reset": "Configura de nuevo tu app autenticadora.",
  canceled: "Cobro cancelado.",
  charged: "Cobro creado: envíale el enlace a quien va a pagar.",
  linked: "Pago asociado al cobro: se avisó a la app.",
  default: "Ahora es el dominio predeterminado.",
  passkey: "Passkey agregada: ya puedes entrar con ella.",
  "passkey-removed": "Passkey quitada.",
};

// ---------- helpers

function isSecure(req, config) {
  return config.publicUrl?.startsWith("https://") || req.headers["x-forwarded-proto"] === "https";
}

/** A POST must come from our own pages (the Origin header, when the browser sends it, must be ours). */
function sameOrigin(req, config) {
  const origin = req.headers.origin;
  if (!origin) return true;
  if (config.publicUrl) return origin === new URL(config.publicUrl).origin;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/;

/**
 * What the signed-in person may see and do. An admin: everything. A client: only the apps they were given,
 * each with "view" (pages, payments, charges, CSV) or "manage" (also accounts, webhook, API keys, charges).
 */
function scopeFor(store, admin) {
  if (admin.role !== "client") return { all: true, appIds: undefined, can: () => true };
  const grants = store.access.forAdmin(admin.id);
  return {
    all: false,
    appIds: Object.keys(grants),
    can: (appId, level = "view") => (level === "manage" ? grants[appId] === "manage" : Boolean(grants[appId])),
  };
}

const visibleApps = (s) => s.ctx.store.apps.list().filter((a) => s.scope.can(a.id));
const manageableApps = (s) => s.ctx.store.apps.list().filter((a) => s.scope.can(a.id, "manage"));
const visibleAccounts = (s) => s.ctx.store.accounts.list().filter((a) => s.scope.can(a.appId));
/** Someone else's app (or account, payment…) is answered exactly like a missing one. */
const notFound = (s, what = "Página no encontrada.") => page(s, { title: "No encontrado", body: html`<div class="card"><h1>No encontrado</h1><p>${what}</p><p><a href="/">Volver al inicio</a></p></div>`, status: 404 });

const BOGOTA_OFFSET_MS = 5 * 3600_000;
/** Midnight in Bogotá of the given YYYY-MM-DD (or of today), as an ISO instant. */
function bogotaDayStart(ymd) {
  const d = ymd ? new Date(`${ymd}T00:00:00-05:00`) : new Date(Math.floor((Date.now() - BOGOTA_OFFSET_MS) / 86400_000) * 86400_000 + BOGOTA_OFFSET_MS);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function validUrl(s) {
  try {
    const u = new URL(s);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

function parseEmails(text) {
  return [...new Set(String(text ?? "").split(/[\s,;]+/).map((e) => e.trim().toLowerCase()).filter(Boolean))];
}
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---------- the handler

/**
 * The admin panel. Every page except login/setup needs a full session (password + 2-step code). Forms carry a
 * CSRF token, cookies are HttpOnly + SameSite=Strict, and POSTs from other origins are refused.
 */
export async function handleAdmin(req, res, url, ctx) {
  const { store, config } = ctx;
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = req.method;

  if (method === "GET" && STATIC[path]) {
    const s = STATIC[path];
    if (!staticCache.has(path)) staticCache.set(path, readFileSync(s.file));
    res.writeHead(200, { "Content-Type": s.type, "Cache-Control": s.cache ?? "public, max-age=86400", "X-Content-Type-Options": "nosniff" });
    return res.end(staticCache.get(path));
  }

  if (method === "POST" && !sameOrigin(req, config)) return sendHtml(res, 403, "Origen no permitido");

  const cookies = parseCookies(req.headers.cookie);
  const secure = isSecure(req, config);
  const token = cookies[SESSION_COOKIE];
  const session = store.sessions.get(token);
  const admin = session ? store.admins.get(session.adminId) : null;
  const s = { req, res, url, ctx, cookies, secure, token, session: admin ? session : null, admin, path };

  // ----- public: first admin, login
  if (store.admins.count() === 0) {
    if (path === "/setup") return setup(s, method);
    return sendHtml(res, 200, layout({ title: "Configurar", body: html`<div class="card"><h1>pagoradar</h1><p class="muted">Todavía no hay administrador. Abre el enlace de configuración que aparece en los logs del servidor.</p></div>` }));
  }
  if (path === "/setup") return redirect(res, "/login");
  if (path === "/login") return login(s, method);
  const invite = path.match(/^\/invite\/([\w-]+)$/);
  if (invite) return acceptInvite(s, invite[1], method);
  if (path === "/login/passkey/options" && method === "POST") return passkeyLoginOptions(s);
  if (path === "/login/passkey" && method === "POST") return passkeyLogin(s);
  if (path === "/login/2fa") return loginTotp(s, method);
  if (path === "/login/2fa/setup") return setupTotp(s, method);

  if (!s.session) return redirect(res, "/login");
  if (s.session.stage === "password") return redirect(res, "/login/2fa");
  if (s.session.stage === "totp_setup") return redirect(res, "/login/2fa/setup");

  // ----- full session from here on
  let form = {};
  if (method === "POST") {
    // These read their own body (a file, or JSON from the page's script): the token comes in a header.
    if (path.endsWith("/check") || path === "/me/passkeys/options" || path === "/me/passkeys/register") {
      if (!safeEqual(req.headers["x-csrf"] ?? "", s.session.csrf)) return sendJson(res, 403, { error: "CSRF" });
    } else {
      const body = await readBody(req, 256 * 1024);
      if (body === null) return sendHtml(res, 413, "Demasiado grande");
      form = parseForm(body);
      if (!safeEqual(form._csrf ?? "", s.session.csrf)) return sendHtml(res, 403, "Sesión vencida: vuelve a cargar la página.");
    }
  }
  s.form = form;
  s.scope = scopeFor(store, admin);
  s.audit = (action, target, detail) => store.audit.add(admin.email, action, target ?? null, detail ?? null);

  if (admin.mustChangePassword && path !== "/me" && path !== "/me/password" && path !== "/logout") return redirect(res, "/me?first=1");

  // Pagoradar-wide settings, people, domains and the audit log are for admins only.
  const adminOnly = /^\/(settings|domains|audit)(\/|$)/.test(path) || (path === "/apps" && method === "POST");
  if (adminOnly && !s.scope.all) return notFound(s);

  if (path === "/logout" && method === "POST") {
    store.sessions.destroy(token);
    return redirect(res, "/login", { "Set-Cookie": cookie(SESSION_COOKIE, "", { maxAge: 0, secure }) });
  }
  if (path === "/" && method === "GET") return dashboard(s);
  if (path === "/apps") return method === "POST" ? createApp(s) : appsPage(s);
  let m;
  if ((m = path.match(/^\/apps\/([\w-]+)$/))) return method === "POST" ? updateApp(s, m[1]) : appPage(s, m[1]);
  if ((m = path.match(/^\/apps\/([\w-]+)\/(rotate|test|keys)$/)) && method === "POST") return appAction(s, m[1], m[2]);
  if ((m = path.match(/^\/apps\/([\w-]+)\/keys\/([\w-]+)\/revoke$/)) && method === "POST") return revokeKey(s, m[1], m[2]);
  if ((m = path.match(/^\/deliveries\/(\d+)\/retry$/)) && method === "POST") return retryDelivery(s, Number(m[1]));
  if (path === "/accounts") return method === "POST" ? createAccount(s) : accountsPage(s);
  if (path === "/accounts/new" && method === "GET") return newAccountPage(s);
  if ((m = path.match(/^\/accounts\/([\w-]+)$/))) return method === "POST" ? updateAccount(s, m[1]) : accountPage(s, m[1]);
  if ((m = path.match(/^\/accounts\/([\w-]+)\/(toggle|delete)$/)) && method === "POST") return accountAction(s, m[1], m[2]);
  if ((m = path.match(/^\/accounts\/([\w-]+)\/check$/)) && method === "POST") return checkEmail(s, m[1]);
  if (path === "/payments" && method === "GET") return paymentsPage(s);
  if (path === "/payments.csv" && method === "GET") return paymentsCsv(s);
  if ((m = path.match(/^\/payments\/(pay_[\w]+)\/link$/))) return method === "POST" ? linkPayment(s, m[1]) : linkPaymentPage(s, m[1]);
  if (path === "/charges") return method === "POST" ? submitNewCharge(s) : chargesPage(s);
  if (path === "/charges/new" && method === "GET") return newChargePage(s);
  if ((m = path.match(/^\/charges\/(chg_[a-z0-9]+)$/)) && method === "GET") return chargePage(s, m[1]);
  if ((m = path.match(/^\/charges\/(chg_[a-z0-9]+)\/cancel$/)) && method === "POST") return cancelCharge(s, m[1]);
  if (path === "/inbox" && method === "GET") return inboxPage(s);
  if (path === "/settings") return method === "POST" ? saveSettings(s) : settingsPage(s);
  if (path === "/settings/admins" && method === "POST") return createAdmin(s);
  if ((m = path.match(/^\/settings\/admins\/([\w-]+)\/invite$/)) && method === "POST") return renewInvite(s, m[1]);
  if ((m = path.match(/^\/settings\/admins\/([\w-]+)$/))) return method === "POST" ? savePerson(s, m[1]) : personPage(s, m[1]);
  if (path === "/domains") return method === "POST" ? createDomain(s) : domainsPage(s);
  if ((m = path.match(/^\/domains\/([a-z0-9.-]+)$/))) return method === "POST" ? updateDomain(s, m[1]) : domainPage(s, m[1]);
  if ((m = path.match(/^\/domains\/([a-z0-9.-]+)\/(rotate|default|delete)$/)) && method === "POST") return domainAction(s, m[1], m[2]);
  if ((m = path.match(/^\/settings\/admins\/([\w-]+)\/delete$/)) && method === "POST") return deleteAdmin(s, m[1]);
  if (path === "/me" && method === "GET") return mePage(s);
  if (path === "/me/password" && method === "POST") return changePassword(s);
  if (path === "/me/totp-reset" && method === "POST") return resetTotp(s);
  if (path === "/me/passkeys/options" && method === "POST") return passkeyOptions(s);
  if (path === "/me/passkeys/register" && method === "POST") return passkeyRegister(s);
  if ((m = path.match(/^\/me\/passkeys\/([\w-]+)\/delete$/)) && method === "POST") return passkeyRemove(s, m[1]);
  if ((m = path.match(/^\/settings\/admins\/([\w-]+)\/passkeys\/delete$/)) && method === "POST") return personPasskeysRemove(s, m[1]);
  if (path === "/audit" && method === "GET") return auditPage(s);
  return notFound(s);
}

function page(s, { title, active = null, body, status = 200 }) {
  return sendHtml(s.res, status, layout({ title, admin: s.admin, csrf: s.session?.csrf, active, body }));
}

const msg = (s) => flash(MESSAGES[s.url.searchParams.get("ok")] ?? null);

// ---------- setup & login

function preCsrf(s) {
  const value = s.cookies[PRE_CSRF_COOKIE] || randomToken(18);
  return { value, header: cookie(PRE_CSRF_COOKIE, value, { maxAge: 3600, secure: s.secure }) };
}

async function readPublicForm(s) {
  const body = await readBody(s.req, 16 * 1024);
  const form = parseForm(body);
  const ok = s.cookies[PRE_CSRF_COOKIE] && safeEqual(form._csrf ?? "", s.cookies[PRE_CSRF_COOKIE]);
  return ok ? form : null;
}

/** This pagoradar's address: the PUBLIC_URL (or, without one, wherever this was opened: local development). */
const publicBase = (s) => s.ctx.config.publicUrl ?? `${s.secure ? "https" : "http"}://${s.req.headers.host}`;

/** The site passkeys belong to. */
function relyingParty(s) {
  const url = new URL(publicBase(s));
  return { id: url.hostname, origin: url.origin };
}

/** A person's invitation: chooses their password, then sets up their 2-step code like anyone. One use, 7 days. */
async function acceptInvite(s, token, method) {
  const { store } = s.ctx;
  const person = store.admins.byInvite(token);
  if (!person) {
    return sendHtml(s.res, 404, layout({ title: "Invitación", body: html`<div class="card"><h1>Este enlace ya no sirve</h1><p class="muted">Se usó o venció. Pídele uno nuevo a quien te invitó.</p><p><a href="/login">Ir a entrar</a></p></div>` }));
  }
  const pre = preCsrf(s);
  let error = null;
  let name = person.name ?? "";
  if (method === "POST") {
    const form = await readPublicForm(s);
    name = String(form?.name ?? "").trim().slice(0, 80);
    if (!form) error = "La página venció; vuelve a intentarlo.";
    else if (!loginLimit(clientIp(s.req))) error = "Demasiados intentos. Espera unos minutos.";
    else if (String(form.password ?? "").length < MIN_PASSWORD) error = `La contraseña debe tener al menos ${MIN_PASSWORD} caracteres.`;
    else if (form.password !== form.password2) error = "Las contraseñas no coinciden.";
    else {
      store.admins.acceptInvite(person.id, name || null, await hashPassword(form.password));
      store.audit.add(person.email, "Aceptó la invitación", null, clientIp(s.req));
      return redirect(s.res, "/login/2fa/setup", { "Set-Cookie": startSession(s, person.id, "totp_setup") });
    }
  }
  return sendHtml(
    s.res,
    error ? 400 : 200,
    layout({
      title: "Invitación",
      body: html`<div class="card">
        <h1>Bienvenido a pagoradar</h1>
        <p class="muted">Entrarás como <b>${person.email}</b>. Elige tu contraseña; después configurarás el código de 2 pasos.</p>
        ${flash(error, "bad")}
        <form method="post" class="stack">
          <input type="hidden" name="_csrf" value="${pre.value}">
          <label>Tu nombre <span class="hint">Opcional.</span><input type="text" name="name" maxlength="80" value="${name}" autocomplete="name"></label>
          <label>Contraseña <span class="hint">Mínimo ${MIN_PASSWORD} caracteres.</span><input type="password" name="password" required minlength="${MIN_PASSWORD}" autocomplete="new-password"></label>
          <label>Repite la contraseña <input type="password" name="password2" required autocomplete="new-password"></label>
          <button class="btn btn-primary" type="submit">Continuar</button>
        </form>
      </div>`,
    }),
    { "Set-Cookie": pre.header },
  );
}

function renewInvite(s, id) {
  const { store } = s.ctx;
  const person = store.admins.get(id);
  if (!person) return notFound(s);
  if (!person.invitePending && !person.mustChangePassword) return personPage(s, id, { error: "Esta persona ya entró: no necesita invitación." });
  s.audit("Generó un enlace de invitación nuevo", person.email);
  return personPage(s, id, { inviteToken: store.admins.newInvite(id) });
}

async function readJsonBody(req) {
  const body = await readBody(req, 16 * 1024);
  try {
    const value = JSON.parse(body?.toString("utf8") ?? "");
    return value && typeof value === "object" ? value : {};
  } catch {
    return {};
  }
}

const PASSKEY_FAILED = "No se pudo entrar con esa passkey. Usa tu contraseña o agrégala de nuevo en Mi cuenta.";

/** Sign-in without an email: the browser offers the passkeys it has for this site. Tied to this browser's login form. */
function passkeyLoginOptions(s) {
  const pre = s.cookies[PRE_CSRF_COOKIE];
  if (!pre || !safeEqual(s.req.headers["x-csrf"] ?? "", pre)) return sendJson(s.res, 403, { error: "La página venció; vuelve a cargarla." });
  if (!passkeyLimit(clientIp(s.req))) return sendJson(s.res, 429, { error: "Demasiados intentos. Espera unos minutos." });
  return sendJson(s.res, 200, { challenge: newChallenge(`login:${pre}`), rpId: relyingParty(s).id, timeout: 60_000, userVerification: "required" });
}

async function passkeyLogin(s) {
  const { store } = s.ctx;
  const pre = s.cookies[PRE_CSRF_COOKIE];
  if (!pre || !safeEqual(s.req.headers["x-csrf"] ?? "", pre)) return sendJson(s.res, 403, { error: "La página venció; vuelve a cargarla." });
  if (!passkeyLimit(clientIp(s.req))) return sendJson(s.res, 429, { error: "Demasiados intentos. Espera unos minutos." });
  const body = await readJsonBody(s.req);
  const passkey = store.passkeys.get(String(body.id ?? ""));
  const person = passkey ? store.admins.get(passkey.adminId) : null;
  const rp = relyingParty(s);
  const signCount = person ? verifyAssertion(body, passkey, { rpId: rp.id, origin: rp.origin, owner: `login:${pre}` }) : null;
  if (signCount === null) return sendJson(s.res, 400, { error: PASSKEY_FAILED });
  store.passkeys.recordUse(passkey.id, signCount);
  store.admins.recordLogin(person.id);
  store.audit.add(person.email, "Entró al panel con passkey", passkey.name, clientIp(s.req));
  return sendJson(s.res, 200, { redirect: "/" }, { "Set-Cookie": startSession(s, person.id, "full") });
}

/** Adding a passkey asks for a current 2-step code: it's a new way in, so a stolen session alone must not be enough. */
async function passkeyOptions(s) {
  const { store } = s.ctx;
  const body = await readJsonBody(s.req);
  if (!loginLimit(`totp:${s.admin.id}`)) return sendJson(s.res, 429, { error: "Demasiados intentos. Espera unos minutos." });
  const step = verifyTotp(store.admins.totpSecret(s.admin.id), body.code, { lastStep: s.admin.totpLastStep });
  if (step === null || !store.admins.useTotpStep(s.admin.id, step)) return sendJson(s.res, 400, { error: "Código incorrecto o ya usado. Espera el siguiente." });
  const existing = store.passkeys.listFor(s.admin.id);
  if (existing.length >= MAX_PASSKEYS) return sendJson(s.res, 400, { error: `Máximo ${MAX_PASSKEYS} passkeys: quita una primero.` });
  const rp = relyingParty(s);
  return sendJson(s.res, 200, {
    challenge: newChallenge(`add:${s.admin.id}`),
    rp: { id: rp.id, name: "pagoradar" },
    user: { id: Buffer.from(s.admin.id).toString("base64url"), name: s.admin.email, displayName: s.admin.name || s.admin.email },
    pubKeyCredParams: PASSKEY_ALGS.map((alg) => ({ type: "public-key", alg })),
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
    attestation: "none",
    timeout: 120_000,
    excludeCredentials: existing.map((p) => ({ type: "public-key", id: p.id, transports: p.transports })),
  });
}

async function passkeyRegister(s) {
  const { store } = s.ctx;
  const body = await readJsonBody(s.req);
  const rp = relyingParty(s);
  const key = verifyRegistration(body, { rpId: rp.id, origin: rp.origin, owner: `add:${s.admin.id}` });
  if (!key) return sendJson(s.res, 400, { error: "No se pudo verificar la passkey. Vuelve a intentarlo." });
  const name = String(body.name ?? "").trim().slice(0, 60) || "Passkey";
  if (!store.passkeys.add({ ...key, adminId: s.admin.id, name })) return sendJson(s.res, 400, { error: "Esa passkey ya está agregada." });
  s.audit("Agregó una passkey", s.admin.email, name);
  return sendJson(s.res, 200, { redirect: "/me?ok=passkey" });
}

function passkeyRemove(s, id) {
  const { store } = s.ctx;
  const passkey = store.passkeys.get(id);
  if (passkey && store.passkeys.remove(id, s.admin.id)) s.audit("Quitó una passkey", s.admin.email, passkey.name);
  return redirect(s.res, "/me?ok=passkey-removed");
}

/** For a lost or stolen device: an admin can take away someone's passkeys. */
function personPasskeysRemove(s, id) {
  const { store } = s.ctx;
  const person = store.admins.get(id);
  if (!person) return notFound(s);
  const removed = store.passkeys.removeAllFor(id);
  if (removed) s.audit("Quitó las passkeys de otra persona", person.email, `${removed}`);
  return redirect(s.res, `/settings/admins/${id}?ok=passkey-removed`);
}

function startSession(s, adminId, stage) {
  const token = s.ctx.store.sessions.create(adminId, stage, clientIp(s.req));
  return cookie(SESSION_COOKIE, token, { secure: s.secure, maxAge: 12 * 3600 });
}

async function setup(s, method) {
  const { ctx } = s;
  const tokenOk = safeEqual(s.url.searchParams.get("token") ?? "", ctx.setupToken ?? "");
  if (!tokenOk) return sendHtml(s.res, 403, layout({ title: "Configurar", body: html`<div class="card"><h1>Enlace inválido</h1><p class="muted">Usa el enlace de configuración que aparece en los logs del servidor.</p></div>` }));
  const pre = preCsrf(s);
  let error = null;
  if (method === "POST") {
    const form = await readPublicForm(s);
    if (!form) error = "La página venció; vuelve a intentarlo.";
    else if (!EMAIL_RE.test(String(form.email ?? "").trim())) error = "Escribe un correo válido.";
    else if (String(form.password ?? "").length < MIN_PASSWORD) error = `La contraseña debe tener al menos ${MIN_PASSWORD} caracteres.`;
    else if (form.password !== form.password2) error = "Las contraseñas no coinciden.";
    else {
      const created = ctx.store.admins.create({ email: form.email, name: form.name?.trim() || null, passwordHash: await hashPassword(form.password) });
      ctx.store.audit.add(created.email, "Creó el primer administrador");
      return redirect(s.res, "/login/2fa/setup", { "Set-Cookie": startSession(s, created.id, "totp_setup") });
    }
  }
  return sendHtml(
    s.res,
    error ? 400 : 200,
    layout({
      title: "Primer administrador",
      body: html`<div class="card">
        <h1>Bienvenido a pagoradar</h1>
        <p class="muted">Crea la cuenta de administrador. Después configurarás el código de 2 pasos.</p>
        ${flash(error, "bad")}
        <form method="post" class="stack">
          <input type="hidden" name="_csrf" value="${pre.value}">
          <label>Tu nombre <input type="text" name="name" autocomplete="name"></label>
          <label>Correo <input type="email" name="email" required autocomplete="username"></label>
          <label>Contraseña <span class="hint">Mínimo ${MIN_PASSWORD} caracteres.</span><input type="password" name="password" required minlength="${MIN_PASSWORD}" autocomplete="new-password"></label>
          <label>Repite la contraseña <input type="password" name="password2" required autocomplete="new-password"></label>
          <button class="btn btn-primary" type="submit">Crear administrador</button>
        </form>
      </div>`,
    }),
    { "Set-Cookie": pre.header },
  );
}

async function login(s, method) {
  const { store } = s.ctx;
  if (s.session?.stage === "full") return redirect(s.res, "/");
  const pre = preCsrf(s);
  let error = null;
  if (method === "POST") {
    const form = await readPublicForm(s);
    const ip = clientIp(s.req);
    if (!form) error = "La página venció; vuelve a intentarlo.";
    else if (!loginLimit(ip)) error = "Demasiados intentos. Espera unos minutos.";
    else {
      const found = store.admins.byEmail(form.email ?? "");
      const locked = found?.lockedUntil && new Date(found.lockedUntil) > new Date();
      // Always one password check (against a throwaway hash for unknown emails), so the response time doesn't
      // tell which emails are admins; and only the right password learns that the account is locked.
      const passwordOk = await verifyPassword(form.password ?? "", found?.passwordHash ?? (await dummyHash()));
      const ok = Boolean(found) && !locked && passwordOk;
      if (!ok) {
        if (found && !locked) store.admins.recordFailure(found.id);
        error = locked && passwordOk ? "Cuenta bloqueada por intentos fallidos. Espera 15 minutos." : "Correo o contraseña incorrectos.";
      } else {
        const stage = found.totpEnabled ? "password" : "totp_setup";
        return redirect(s.res, found.totpEnabled ? "/login/2fa" : "/login/2fa/setup", { "Set-Cookie": startSession(s, found.id, stage) });
      }
    }
  }
  return sendHtml(
    s.res,
    error ? 400 : 200,
    layout({
      title: "Entrar",
      body: html`<div class="card">
        <h1>Entrar</h1>
        ${flash(error, "bad")}
        <form method="post" class="stack">
          <input type="hidden" name="_csrf" value="${pre.value}">
          <label>Correo <input type="email" name="email" required autocomplete="username" autofocus></label>
          <label>Contraseña <input type="password" name="password" required autocomplete="current-password"></label>
          <button class="btn btn-primary" type="submit">Continuar</button>
        </form>
        <div class="passkey-login" data-passkey-login data-csrf="${pre.value}" hidden>
          <p class="or"><span>o</span></p>
          <button class="btn" type="button">${icon("key")}<span>Entrar con passkey</span></button>
          <p class="muted small" role="status" aria-live="polite" hidden></p>
        </div>
      </div>`,
    }),
    { "Set-Cookie": pre.header },
  );
}

async function loginTotp(s, method) {
  const { store } = s.ctx;
  if (!s.session) return redirect(s.res, "/login");
  if (s.session.stage === "full") return redirect(s.res, "/");
  if (s.session.stage === "totp_setup") return redirect(s.res, "/login/2fa/setup");
  let error = null;
  if (method === "POST") {
    const form = parseForm(await readBody(s.req, 4096));
    if (!safeEqual(form._csrf ?? "", s.session.csrf)) error = "La página venció; vuelve a intentarlo.";
    else if (!loginLimit(`totp:${s.admin.id}`)) error = "Demasiados intentos. Espera unos minutos.";
    else {
      const step = verifyTotp(store.admins.totpSecret(s.admin.id), form.code, { lastStep: s.admin.totpLastStep });
      if (step !== null && store.admins.useTotpStep(s.admin.id, step)) {
        store.sessions.setStage(s.token, "full");
        store.admins.recordLogin(s.admin.id);
        store.audit.add(s.admin.email, "Entró al panel", null, clientIp(s.req));
        return redirect(s.res, "/");
      }
      store.admins.recordFailure(s.admin.id);
      error = "Código incorrecto o ya usado. Espera el siguiente.";
    }
  }
  return sendHtml(
    s.res,
    error ? 400 : 200,
    layout({
      title: "Código de 2 pasos",
      body: html`<div class="card">
        <h1>Código de 2 pasos</h1>
        <p class="muted">Escribe el código de 6 dígitos de tu app autenticadora.</p>
        ${flash(error, "bad")}
        <form method="post" class="stack">
          ${csrfField(s.session.csrf)}
          <label>Código <input type="text" name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" required autocomplete="one-time-code" autofocus></label>
          <button class="btn btn-primary" type="submit">Entrar</button>
        </form>
      </div>`,
    }),
  );
}

async function setupTotp(s, method) {
  const { store } = s.ctx;
  if (!s.session) return redirect(s.res, "/login");
  if (s.session.stage !== "totp_setup") return redirect(s.res, "/");
  let secret = s.session.pendingTotp;
  if (!secret) {
    secret = newTotpSecret();
    store.sessions.setPendingTotp(s.token, secret);
  }
  let error = null;
  if (method === "POST") {
    const form = parseForm(await readBody(s.req, 4096));
    if (!safeEqual(form._csrf ?? "", s.session.csrf)) error = "La página venció; vuelve a intentarlo.";
    else {
      const step = verifyTotp(secret, form.code);
      if (step !== null) {
        store.admins.setTotp(s.admin.id, secret, step);
        store.sessions.setPendingTotp(s.token, null);
        store.sessions.setStage(s.token, "full");
        store.admins.recordLogin(s.admin.id);
        store.audit.add(s.admin.email, "Configuró su código de 2 pasos");
        return redirect(s.res, "/");
      }
      error = "Ese código no coincide. Revisa la hora del celular y vuelve a intentarlo.";
    }
  }
  const svg = await QRCode.toString(totpUri(secret, s.admin.email), { type: "svg", margin: 1 });
  return sendHtml(
    s.res,
    error ? 400 : 200,
    layout({
      title: "Configurar 2 pasos",
      body: html`<div class="card">
        <h1>Código de 2 pasos</h1>
        <p class="muted">Escanea el QR con Google Authenticator, Microsoft Authenticator, 1Password o similar, y escribe el código que muestra.</p>
        <div class="qr">${raw(svg)}</div>
        <details><summary>¿No puedes escanear? Escribe la clave a mano</summary><p>${copyable(secret)}</p></details>
        ${flash(error, "bad")}
        <form method="post" class="stack">
          ${csrfField(s.session.csrf)}
          <label>Código de 6 dígitos <input type="text" name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" required autocomplete="one-time-code" autofocus></label>
          <button class="btn btn-primary" type="submit">Activar y entrar</button>
        </form>
      </div>`,
    }),
  );
}

// ---------- dashboard

function dashboard(s) {
  const { store } = s.ctx;
  const { appIds } = s.scope;
  const today = store.payments.stats(bogotaDayStart(), appIds);
  const week = store.payments.stats(new Date(Date.now() - 7 * 86400_000).toISOString(), appIds);
  const failed = store.deliveries.countFailed(appIds);
  const rejected = store.inbox.countSince(new Date(Date.now() - 7 * 86400_000).toISOString(), appIds);
  const accounts = visibleAccounts(s);
  const pending = accounts.filter((a) => a.status === "pending");
  const recent = store.payments.search({ appIds, limit: 10 }).rows;
  const appName = Object.fromEntries(visibleApps(s).map((a) => [a.id, a.name]));
  const weekAgo = new Date(Date.now() - 7 * 86400_000).toISOString();
  const silent = accounts.filter((a) => a.silent);
  const unreadable = store.inbox.countUnrecognizedSince(weekAgo, appIds);
  return page(s, {
    title: "Inicio",
    active: "/",
    body: html`
      <div class="head"><div><h1>Inicio</h1><p class="muted">Pagos que avisaron los bancos y el estado de tus integraciones.</p></div></div>
      ${firstSteps(s, accounts)}
      ${silent.length
        ? flash(html`${silent.length === 1 ? "Una cuenta no recibe" : `${silent.length} cuentas no reciben`} avisos hace rato: ${silent.slice(0, 5).map((a, i) => html`${i ? ", " : ""}<a href="/accounts/${a.id}">${a.name}</a>`)}${silent.length > 5 ? "…" : ""}.`, "warn")
        : ""}
      ${unreadable ? flash(html`${unreadable === 1 ? "Llegó 1 aviso real del banco que no pudimos leer" : `Llegaron ${unreadable} avisos reales del banco que no pudimos leer`}: esos pagos no se registraron. <a href="/inbox">Ver cuáles</a>.`, "bad") : ""}
      ${!s.scope.all && s.scope.appIds.length === 0 ? flash("Todavía no tienes apps asignadas. Pídele acceso al administrador de pagoradar.", "warn") : ""}
      ${failed ? flash(html`${failed === 1 ? "Hay 1 entrega de webhook fallida" : `Hay ${failed} entregas de webhook fallidas`}. <a href="/apps">Revisa tus apps</a>.`, "bad") : ""}
      <div class="grid">
        <div class="stat stat-hero"><span class="stat-ico">${icon("today")}</span><span class="stat-label">Hoy</span><b>${fmtMoney(today.cents / 100)}</b><span class="stat-sub">${today.n} ${today.n === 1 ? "pago" : "pagos"}</span></div>
        <div class="stat"><span class="stat-ico">${icon("week")}</span><span class="stat-label">Últimos 7 días</span><b>${fmtMoney(week.cents / 100)}</b><span class="stat-sub">${week.n} ${week.n === 1 ? "pago" : "pagos"}</span></div>
        <a class="stat" href="/accounts"><span class="stat-ico">${icon("accounts")}</span><span class="stat-label">Cuentas receptoras</span><b>${accounts.length}</b><span class="stat-sub">${pending.length ? `${pending.length} esperando configuración` : accounts.length ? "todas listas" : "ninguna todavía"}</span></a>
        <a class="stat${rejected ? " stat-warn" : ""}" href="/inbox"><span class="stat-ico">${icon("inbox")}</span><span class="stat-label">Correos rechazados</span><b>${rejected}</b><span class="stat-sub">últimos 7 días</span></a>
      </div>
      <div class="card">
        <div class="head"><h2>Últimos pagos</h2><a href="/payments">Ver todos</a></div>
        ${paymentsTable(s, recent, appName)}
      </div>`,
  });
}

/** The App and Cuenta columns only when they tell the rows apart. */
/** The way from an empty pagoradar to the first payment, until it's done. */
function firstSteps(s, accounts) {
  const { store } = s.ctx;
  const steps = [];
  if (s.scope.all) {
    steps.push(["Agrega un dominio de recepción", "Donde las cuentas reciben los avisos, y su regla en Cloudflare.", store.domains.list().length > 0, "/domains", "Agregar dominio"]);
    steps.push(["Crea una app", "El proyecto que recibe los pagos, con su webhook y sus API keys.", store.apps.list().length > 0, "/apps", "Crear app"]);
  } else if (manageableApps(s).length === 0) {
    return ""; // only looks: nothing to set up
  }
  steps.push(["Conecta una cuenta receptora", "Una cuenta bancaria: el Gmail del dueño reenvía sus avisos.", accounts.length > 0, "/accounts/new", "Nueva cuenta"]);
  steps.push(["Recibe el primer aviso", "Haz un pago pequeño de prueba y la cuenta queda Activa.", accounts.some((a) => a.status === "active"), accounts[0] ? `/accounts/${accounts[0].id}` : "/accounts", "Ver la guía"]);
  if (steps.every(([, , done]) => done)) return "";
  const next = steps.findIndex(([, , done]) => !done);
  return html`<div class="card first-steps">
    <h2>Primeros pasos</h2>
    <ul class="list">${steps.map(([title, desc, done, href, label], i) => html`<li>
      <span class="list-ico">${done ? badge("Listo", "ok") : html`<b>${i + 1}</b>`}</span>
      <div class="list-main"><b>${title}</b><span>${desc}</span></div>
      ${i === next ? html`<a class="btn btn-primary btn-small" href="${href}">${label}</a>` : ""}
    </li>`)}</ul>
  </div>`;
}

function paymentsTable(s, rows, appName, { showAccount = true } = {}) {
  if (rows.length === 0) return html`<p class="empty">Todavía no hay pagos.</p>`;
  const showApp = visibleApps(s).length > 1 && showAccount;
  const accountName = Object.fromEntries(visibleAccounts(s).map((a) => [a.id, a.name]));
  return html`<div class="table-wrap"><table>
    <thead><tr><th>Fecha</th><th>Pagador</th><th>Banco</th>${showAccount ? html`<th>Cuenta</th>` : ""}${showApp ? html`<th>App</th>` : ""}<th>Cobro</th><th class="num">Valor</th></tr></thead>
    <tbody>${rows.map(
      (p) => html`<tr>
        <td class="t-date">${fmtDate(p.paidAt)}</td>
        <td class="t-main"><b>${p.payerName}</b>${p.payerBank ? html`<div class="muted small">desde ${p.payerBank}</div>` : ""}</td>
        <td>${BANK_LABEL[p.bank] ?? p.bank}${p.reference ? html`<div class="muted small">Ref. ${p.reference}</div>` : ""}</td>
        ${showAccount ? html`<td>${p.accountId ? html`<a class="quiet" href="/accounts/${p.accountId}">${accountName[p.accountId] ?? p.accountId}</a>` : "—"}</td>` : ""}
        ${showApp ? html`<td>${appName[p.appId] ?? p.appId}</td>` : ""}
        <td class="t-wide">${chargeCell(s, p)}</td>
        <td class="num"><b>${fmtMoney(p.amount)}</b></td>
      </tr>`,
    )}</tbody></table></div>`;
}

const MATCH_LABEL = { exact: "valor exacto", approximate: "pagó el valor redondo", manual: "asociado a mano" };

function chargeCell(s, p) {
  const { store } = s.ctx;
  const c = store.charges.byPayment(p.id);
  if (c) {
    return html`${badge("Pagó un cobro", "ok")}<div class="muted small">${c.description ?? c.reference ?? c.id}${c.match ? ` · ${MATCH_LABEL[c.match] ?? c.match}` : ""}</div>`;
  }
  // Only offer it when an open or recent charge of that account asked for about that much (±10%, at least $2.000).
  if (!s.scope.can(p.appId, "manage")) return "";
  const closest = p.accountId ? store.charges.linkable(p.accountId, p.amountCents, 7, 1)[0] : null;
  if (closest && Math.abs(closest.amountCents - p.amountCents) <= Math.max(p.amountCents * 0.1, 200_000)) {
    return html`<a class="chip" href="/payments/${p.id}/link">Asociar a un cobro</a>`;
  }
  return "";
}

function linkPaymentPage(s, id, { error = null } = {}) {
  const { store } = s.ctx;
  const p = store.payments.get(id);
  if (!p || !s.scope.can(p.appId, "manage")) return notFound(s, "Pago no encontrado.");
  const linked = store.charges.byPayment(p.id);
  const options = p.accountId && !linked ? store.charges.linkable(p.accountId, p.amountCents) : [];
  const csrf = s.session.csrf;
  return page(s, {
    title: "Asociar a un cobro",
    active: "/payments",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><a class="back" href="/payments">← Pagos</a><div><h1>Asociar a un cobro</h1><p class="muted">Para un pago que llegó con otro valor o que el cruce automático no pudo decidir.</p></div></div>
      ${flash(error, "bad")}
      <div class="card pay-hero">
        <span class="tile-ico">${icon("payments")}</span>
        <div class="pay-hero-main"><span class="stat-label">Pago recibido</span><b>${fmtMoney(p.amount)}</b><span class="muted">${p.payerName ?? "?"}${p.payerBank ? ` · desde ${p.payerBank}` : ""}</span></div>
        <dl class="pay-hero-meta">
          <div><dt>Banco</dt><dd>${BANK_LABEL[p.bank] ?? p.bank}</dd></div>
          <div><dt>Fecha</dt><dd>${fmtDate(p.paidAt)}</dd></div>
          ${p.reference ? html`<div><dt>Referencia</dt><dd>${p.reference}</dd></div>` : ""}
        </dl>
      </div>
      <div class="card">
        ${linked
          ? html`<p>Este pago ya está asociado a un cobro (${linked.description ?? linked.reference ?? linked.id}).</p>`
          : options.length === 0
            ? html`<p class="empty">No hay cobros abiertos o recientes en esta cuenta.</p>`
            : html`<p class="muted small">Cobros abiertos, o vencidos/cancelados en los últimos 7 días, del más parecido en valor al menos parecido. Se le avisa a la app.</p>
          <div class="table-wrap"><table>
            <thead><tr><th>Creado</th><th>Cobro</th><th>Estado</th><th class="num">Valor</th><th></th></tr></thead>
            <tbody>${options.map((c, i) => html`<tr${i === 0 ? raw(' class="row-best"') : ""}>
              <td class="t-date">${fmtDate(c.createdAt)}</td>
              <td class="t-main">${i === 0 ? html`<span class="best">Más parecido</span>` : ""}<b>${c.description ?? "—"}</b>${c.reference ? html`<div class="muted small">Ref. ${c.reference}</div>` : ""}${c.payerName ? html`<div class="muted small">Espera a ${c.payerName}</div>` : ""}</td>
              <td>${chargeStatus(c.status)}</td>
              <td class="num"><b>${fmtMoney(c.amount)}</b>${c.amount !== c.baseAmount ? html`<div class="muted small">pedido ${fmtMoney(c.baseAmount)}</div>` : ""}</td>
              <td class="t-act">${postButton(`/payments/${p.id}/link`, "Asociar", csrf, { tone: i === 0 ? "primary" : "secondary", small: true, fields: { chargeId: c.id }, confirm: `¿Asociar este pago de ${fmtMoney(p.amount)} al cobro de ${fmtMoney(c.amount)}?` })}</td>
            </tr>`)}</tbody></table></div>`}
      </div>`,
  });
}

function linkPayment(s, id) {
  const { store, config } = s.ctx;
  const p = store.payments.get(id);
  const charge = store.charges.get(String(s.form.chargeId ?? ""));
  if (!p || !s.scope.can(p.appId, "manage")) return notFound(s, "Pago no encontrado.");
  if (!charge) return redirect(s.res, "/payments");
  if (charge.accountId !== p.accountId) return linkPaymentPage(s, id, { error: "Ese cobro es de otra cuenta receptora." });
  if (store.charges.byPayment(p.id)) return linkPaymentPage(s, id, { error: "Este pago ya está asociado a otro cobro." });
  const app = store.apps.get(charge.appId);
  if (!app || !payManually(store, app, charge, p, { publicUrl: config.publicUrl })) return linkPaymentPage(s, id, { error: "Ese cobro ya está pagado." });
  s.audit("Asoció un pago a un cobro", charge.id, `${p.id} · ${fmtMoney(p.amount)}`);
  void deliverDue(store, { log: s.ctx.log }).catch(() => {});
  return redirect(s.res, "/payments?ok=linked");
}

// ---------- apps

function appsPage(s, error = null) {
  const { store } = s.ctx;
  const apps = visibleApps(s);
  const csrf = s.session.csrf;
  const host = (u) => {
    try {
      return new URL(u).host;
    } catch {
      return u;
    }
  };
  return page(s, {
    title: "Apps",
    active: "/apps",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><div><h1>Apps</h1><p class="muted">Cada proyecto que recibe pagos (Ibirifas, otro SaaS…): su webhook y sus API keys.</p></div><a class="btn btn-small" href="/docs" target="_blank" rel="noopener">${icon("book")}<span>Documentación para desarrolladores</span></a></div>
      ${flash(error, "bad")}
      ${apps.length === 0
        ? html`<div class="card"><p class="empty">${s.scope.all ? "Aún no hay apps. Crea la primera abajo." : "No tienes apps asignadas."}</p></div>`
        : html`<div class="tiles">${apps.map((a) => {
            const accounts = store.accounts.list(a.id);
            const keys = store.keys.listForApp(a.id).filter((k) => !k.revokedAt).length;
            const failed = store.deliveries.list({ appId: a.id, status: "failed", limit: 100 }).length;
            return html`<a class="tile" href="/apps/${a.id}">
              <div class="tile-top"><span class="tile-ico">${icon("apps")}</span><div class="tile-title"><b>${a.name}</b><span>${a.id}</span></div>${a.active ? badge("Activa", "ok") : badge("Inactiva", "muted")}</div>
              <p class="tile-line">${icon("webhook")}<span>${a.webhookUrl ? host(a.webhookUrl) : "Sin webhook"}</span></p>
              <div class="tile-foot"><span>${accounts.length} ${accounts.length === 1 ? "cuenta" : "cuentas"}</span><span>${keys} API ${keys === 1 ? "key" : "keys"}</span>${failed ? badge(failed === 1 ? "1 entrega fallida" : `${failed} entregas fallidas`, "bad") : ""}</div>
            </a>`;
          })}</div>`}
      ${s.scope.all ? html`<div class="card">
        <h2>Nueva app</h2>
        <form method="post" action="/apps" class="inline-form">
          ${csrfField(csrf)}
          <label>Nombre <input type="text" name="name" required maxlength="60" placeholder="Ej. Tienda online"></label>
          <label class="wide">URL del webhook <span class="hint">Opcional; se puede poner después.</span><input type="url" name="webhookUrl" maxlength="500" placeholder="https://tu-app.com/api/pagoradar/webhook"></label>
          <button class="btn btn-primary" type="submit">${icon("plus")}<span>Crear app</span></button>
        </form>
      </div>` : ""}`,
  });
}

function createApp(s) {
  const name = String(s.form.name ?? "").trim();
  const webhookUrl = String(s.form.webhookUrl ?? "").trim() || null;
  if (!name || name.length > 60) return appsPage(s, "Escribe un nombre (máximo 60 caracteres).");
  if (webhookUrl && !validUrl(webhookUrl)) return appsPage(s, "La URL del webhook no es válida.");
  const app = s.ctx.store.apps.create({ name, webhookUrl });
  s.audit("Creó la app", app.id, name);
  return redirect(s.res, `/apps/${app.id}?ok=created`);
}

function appPage(s, id, { error = null, newKey = null, secretShown = null } = {}) {
  const { store } = s.ctx;
  const app = store.apps.get(id);
  if (!app || !s.scope.can(id)) return notFound(s, "App no encontrada.");
  const manage = s.scope.can(id, "manage");
  const keys = store.keys.listForApp(id);
  const accounts = store.accounts.list(id);
  const deliveries = store.deliveries.list({ appId: id, limit: 30 });
  const delivered = deliveries.filter((d) => d.status === "delivered").length;
  const failed = deliveries.filter((d) => d.status === "failed").length;
  const csrf = s.session.csrf;
  return page(s, {
    title: app.name,
    active: "/apps",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><a class="back" href="/apps">← Apps</a><div><h1>${app.name} ${app.active ? badge("Activa", "ok") : badge("Inactiva", "muted")}</h1><p class="muted"><code>${app.id}</code>${manage ? "" : " · solo lectura"}</p></div>
        ${manage ? postButton(`/apps/${id}/test`, html`${icon("send")}<span>Enviar evento de prueba</span>`, csrf) : ""}</div>
      ${msg(s)}${flash(error, "bad")}
      ${newKey ? html`<div class="secret card"><h2>Tu nueva API key</h2><p>Cópiala ahora: <b>no se volverá a mostrar</b>.</p><p>${copyable(newKey)}</p></div>` : ""}
      <div class="grid grid-3">
        <a class="stat" href="#cuentas"><span class="stat-ico">${icon("accounts")}</span><span class="stat-label">Cuentas receptoras</span><b>${accounts.length}</b></a>
        <div class="stat"><span class="stat-ico">${icon("send")}</span><span class="stat-label">Entregas recientes</span><b>${delivered}</b><span class="stat-sub">${deliveries.length ? `de las últimas ${deliveries.length} llegaron` : "aún no hay entregas"}</span></div>
        <div class="stat${failed ? " stat-warn" : ""}"><span class="stat-ico">${icon("alert")}</span><span class="stat-label">Fallidas</span><b>${failed}</b><span class="stat-sub">${failed ? (manage ? "revisa la URL y reintenta" : "no llegaron a la app") : "todo bien"}</span></div>
      </div>
      ${manage ? html`<div class="card">
        <form method="post" action="/apps/${id}">
          ${csrfField(csrf)}
          ${section("Webhook", "A dónde enviamos cada pago y cada cobro, firmado con el secreto de abajo.", html`
            <label>Nombre <input type="text" name="name" value="${app.name}" required maxlength="60"></label>
            <label>URL del webhook <input type="url" name="webhookUrl" value="${app.webhookUrl ?? ""}" maxlength="500" placeholder="https://tu-app.com/api/pagoradar/webhook"></label>
            ${s.scope.all ? toggle("active", app.active, "App activa", "Si la apagas, sus API keys dejan de funcionar y no recibe avisos.") : ""}`)}
          <div class="form-actions"><button class="btn btn-primary" type="submit">Guardar cambios</button></div>
        </form>
        ${section("Secreto de la firma", html`Tu app lo usa para verificar la cabecera <code>Pagoradar-Signature</code>.`, html`
          ${secretShown
            ? html`<div class="secret">${copyable(secretShown)}</div>`
            : html`<details class="reveal"><summary>Mostrar secreto</summary><div class="mt">${copyable(store.apps.secret(id))}</div></details>`}
          <div>${postButton(`/apps/${id}/rotate`, "Cambiar secreto", csrf, { tone: "danger", small: true, confirm: "¿Cambiar el secreto? Tu app dejará de aceptar los avisos hasta que pongas el nuevo." })}</div>`)}
        ${section("API keys", "Para que tu app consulte pagos y cree cuentas o cobros (Authorization: Bearer …).", html`
          ${keys.length
            ? html`<ul class="list">${keys.map((k) => html`<li>
                <span class="list-ico">${icon("key")}</span>
                <div class="list-main"><b>${k.name}</b><span><code>${k.prefix}…</code> · creada ${fmtDate(k.createdAt)}${k.revokedAt ? "" : ` · último uso ${k.lastUsedAt ? fmtAgo(k.lastUsedAt) : "nunca"}`}</span></div>
                ${k.revokedAt ? badge("Revocada", "muted") : postButton(`/apps/${id}/keys/${k.id}/revoke`, "Revocar", csrf, { tone: "danger", small: true, confirm: "¿Revocar esta API key? Lo que la use dejará de funcionar." })}
              </li>`)}</ul>`
            : html`<p class="muted small">Sin API keys todavía.</p>`}
          <form method="post" action="/apps/${id}/keys" class="input-group">
            ${csrfField(csrf)}
            <input type="text" name="name" placeholder="Nombre de la nueva key (ej. producción)" maxlength="60" required aria-label="Nombre de la nueva API key">
            <button class="btn" type="submit">${icon("plus")}<span>Crear API key</span></button>
          </form>`)}
      </div>` : html`<div class="card">${section("Webhook", "A dónde enviamos cada pago y cada cobro.", html`<p>${app.webhookUrl ? html`<code>${app.webhookUrl}</code>` : html`<span class="muted">Sin webhook</span>`}</p>`)}</div>`}
      <div class="section-head" id="cuentas"><h2>Cuentas receptoras</h2>${manage ? html`<a class="btn btn-small" href="/accounts/new?app=${id}">${icon("plus")}<span>Nueva cuenta</span></a>` : ""}</div>
      ${accountCards(accounts, { [id]: app.name })}
      <div class="card mt">
        <h2>Entregas del webhook</h2>
        ${deliveries.length === 0
          ? html`<p class="empty">Todavía no hay entregas.</p>`
          : html`<div class="table-wrap"><table><thead><tr><th>Fecha</th><th>Evento</th><th>Estado</th><th>Intentos</th><th>Resultado</th><th></th></tr></thead><tbody>
            ${deliveries.map((d) => html`<tr>
              <td class="t-date">${fmtDate(d.created_at)}</td>
              <td class="t-main">${d.type ?? ""}<div class="muted small">${d.event_id}</div></td>
              <td>${d.status === "delivered" ? badge("Entregado", "ok") : d.status === "failed" ? badge("Fallido", "bad") : badge("Pendiente", "warn")}</td>
              <td>${d.attempts} ${d.attempts === 1 ? "intento" : "intentos"}</td>
              <td class="t-wide">${d.last_status ? `HTTP ${d.last_status}` : ""}${d.last_error && d.last_error !== `HTTP ${d.last_status}` ? html`<div class="muted small">${d.last_error}</div>` : ""}${d.status === "pending" && d.attempts ? html`<div class="muted small">Próximo: ${fmtDate(d.next_attempt_at)}</div>` : ""}</td>
              <td class="t-act">${manage && d.status !== "delivered" ? postButton(`/deliveries/${d.id}/retry`, "Reintentar", csrf, { small: true, fields: { back: `/apps/${id}` } }) : ""}</td>
            </tr>`)}</tbody></table></div>`}
      </div>`,
  });
}

function updateApp(s, id) {
  const { store } = s.ctx;
  const app = store.apps.get(id);
  if (!app || !s.scope.can(id, "manage")) return notFound(s, "App no encontrada.");
  // Only an admin turns an app on or off (it's how a client's access to the API is suspended).
  const active = s.scope.all ? s.form.active === "1" : app.active;
  const name = String(s.form.name ?? "").trim();
  const webhookUrl = String(s.form.webhookUrl ?? "").trim() || null;
  if (!name || name.length > 60) return appPage(s, id, { error: "Escribe un nombre (máximo 60 caracteres)." });
  if (webhookUrl && !validUrl(webhookUrl)) return appPage(s, id, { error: "La URL del webhook no es válida." });
  store.apps.update(id, { name, webhookUrl, active });
  s.audit("Editó la app", id, `${name} · webhook ${webhookUrl ?? "(ninguno)"} · ${active ? "activa" : "inactiva"}`);
  return redirect(s.res, `/apps/${id}?ok=saved`);
}

async function appAction(s, id, action) {
  const { store, log } = s.ctx;
  const app = store.apps.get(id);
  if (!app || !s.scope.can(id, "manage")) return notFound(s, "App no encontrada.");
  if (action === "rotate") {
    const secret = store.apps.rotateSecret(id);
    s.audit("Cambió el secreto del webhook", id);
    return appPage(s, id, { secretShown: secret });
  }
  if (action === "test") {
    const r = await sendTestEvent(store, app, log);
    if (!r) return appPage(s, id, { error: "Esta app no tiene URL de webhook." });
    return redirect(s.res, `/apps/${id}?ok=test`);
  }
  const name = String(s.form.name ?? "").trim().slice(0, 60) || "API key";
  const key = store.keys.create(id, name);
  s.audit("Creó una API key", id, `${name} (${key.prefix})`);
  return appPage(s, id, { newKey: key.key });
}

function revokeKey(s, appId, keyId) {
  if (!s.ctx.store.apps.get(appId) || !s.scope.can(appId, "manage")) return notFound(s, "App no encontrada.");
  if (s.ctx.store.keys.revoke(keyId, appId)) s.audit("Revocó una API key", appId, keyId);
  return redirect(s.res, `/apps/${appId}?ok=revoked`);
}

async function retryDelivery(s, id) {
  const d = s.ctx.store.deliveries.get(id);
  if (!d || !s.scope.can(d.source, "manage")) return notFound(s);
  if (s.ctx.store.deliveries.retry(id)) {
    s.audit("Reintentó una entrega", String(id));
    await deliverDue(s.ctx.store, { log: s.ctx.log });
  }
  const back = String(s.form.back ?? "/apps");
  return redirect(s.res, `${back.startsWith("/") && !back.startsWith("//") ? back : "/apps"}?ok=retry`);
}

// ---------- receiving accounts

function accountCards(accounts, appName) {
  if (accounts.length === 0) return html`<div class="card"><p class="empty">Sin cuentas receptoras.</p></div>`;
  return html`<div class="tiles">${accounts.map((a) => html`<a class="tile${a.status === "disabled" ? " tile-off" : ""}" href="/accounts/${a.id}">
    <div class="tile-top"><span class="tile-ico">${icon("accounts")}</span><div class="tile-title"><b>${a.name}</b><span>${appName[a.appId] ?? a.appId}${a.tenantRef ? ` · ref. ${a.tenantRef}` : ""}</span></div></div>
    <p class="tile-line">${icon("inbox")}<code>${a.address}</code></p>
    <span class="bank-tags">${a.banks.map((b) => html`<span>${BANK_LABEL[b] ?? b}</span>`)}</span>
    <div class="tile-foot">${accountStatus(a.status, a.silent)}<span>${a.lastPaymentAt ? `Último pago ${fmtAgo(a.lastPaymentAt)}` : "Sin pagos aún"}</span></div>
  </a>`)}</div>`;
}

function accountsPage(s) {
  const q = s.url.searchParams;
  const apps = visibleApps(s);
  const appName = Object.fromEntries(apps.map((a) => [a.id, a.name]));
  const status = ["active", "pending", "disabled"].includes(q.get("status")) ? q.get("status") : null;
  const text = q.get("q")?.trim().toLowerCase() ?? "";
  const base = visibleAccounts(s).filter(
    (a) => (!q.get("app") || a.appId === q.get("app")) && (!text || [a.name, a.address, a.tenantRef ?? "", ...a.ownerEmails].some((v) => v.toLowerCase().includes(text))),
  );
  const count = (st) => base.filter((a) => a.status === st).length;
  const shown = status ? base.filter((a) => a.status === status) : base;
  return page(s, {
    title: "Cuentas receptoras",
    active: "/accounts",
    body: html`
      <div class="head"><div><h1>Cuentas receptoras</h1><p class="muted">Cada cuenta bancaria que reenvía sus avisos a una dirección de pagoradar.</p></div>${manageableApps(s).length ? html`<a class="btn btn-primary" href="/accounts/new">${icon("plus")}<span>Nueva cuenta</span></a>` : ""}</div>
      ${msg(s)}
      ${filterBar(s, {
        rows: [
          html`${searchBox("q", "Buscar nombre, dirección, correo o referencia", q.get("q"))}
            ${apps.length > 1 ? html`<div class="pills">${pillSelect("app", "App", "Todas las apps", apps.map((a) => [a.id, a.name]), q.get("app"))}</div>` : ""}
            ${status ? html`<input type="hidden" name="status" value="${status}">` : ""}`,
          segmented("Estado", [
            ["Todas", withParams(s, { status: null }), !status, base.length],
            ["Activas", withParams(s, { status: "active" }), status === "active", count("active")],
            ["Esperando configuración", withParams(s, { status: "pending" }), status === "pending", count("pending")],
            ["Desactivadas", withParams(s, { status: "disabled" }), status === "disabled", count("disabled")],
          ]),
        ],
      })}
      ${shown.length === 0 && (status || text || q.get("app")) ? html`<div class="card"><p class="empty">Ninguna cuenta con estos filtros. <a href="/accounts">Ver todas</a></p></div>` : accountCards(shown, appName)}`,
  });
}

function bankChecks(selected) {
  return html`<div class="checks">${BANK_IDS.map((b) => html`<label><input type="checkbox" name="banks" value="${b}"${selected.includes(b) ? raw(" checked") : ""}> ${BANK_LABEL[b] ?? b}</label>`)}</div>`;
}

/** The domains any of `apps` may use, each labeled with the apps it is limited to (if it is). */
function domainOptions(s, apps) {
  const appName = Object.fromEntries(apps.map((a) => [a.id, a.name]));
  return s.ctx.store.domains
    .list()
    .filter((d) => !d.appIds || d.appIds.some((id) => appName[id]))
    .map((d) => [d.name, d.appIds ? `${d.name} (solo ${d.appIds.filter((id) => appName[id]).map((id) => appName[id]).join(", ")})` : d.name]);
}

function newAccountPage(s, { error = null, values = {} } = {}) {
  const apps = manageableApps(s);
  const domains = domainOptions(s, apps);
  const selectedApp = values.appId ?? s.url.searchParams.get("app") ?? apps[0]?.id;
  return page(s, {
    title: "Nueva cuenta",
    active: "/accounts",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><a class="back" href="/accounts">← Cuentas</a><div><h1>Nueva cuenta receptora</h1><p class="muted">pagoradar le dará una dirección; el Gmail del dueño reenviará ahí los avisos del banco.</p></div></div>
      ${flash(error, "bad")}
      ${domains.length === 0 ? flash(s.scope.all ? html`Primero agrega un dominio de recepción en <a href="/domains">Dominios</a>.` : "No hay un dominio de recepción para tus apps: pídeselo al administrador.", "warn") : ""}
      ${apps.length === 0 ? flash(s.scope.all ? html`Primero crea una <a href="/apps">app</a>.` : "No puedes crear cuentas en ninguna app.", "warn") : ""}
      <form method="post" action="/accounts" class="card">
        ${csrfField(s.session.csrf)}
        ${section("La cuenta", "A qué app pertenece y cómo la vas a reconocer.", html`
          <label>App <select name="appId" required>${apps.map((a) => html`<option value="${a.id}"${a.id === selectedApp ? raw(" selected") : ""}>${a.name}</option>`)}</select></label>
          <label>Nombre <span class="hint">Ej. "Nequi Negocios de Ana".</span><input type="text" name="name" required maxlength="60" value="${values.name ?? ""}" placeholder="Nequi Negocios de Ana"></label>
          ${domains.length > 1
            ? html`<label>Dominio de la dirección <span class="hint">Dónde recibe esta cuenta: <code>algo@dominio</code>.</span><select name="domain">${domains.map(([v, l]) => html`<option value="${v}"${v === values.domain ? raw(" selected") : ""}>${l}</option>`)}</select></label>`
            : ""}
          <label>Referencia externa <span class="hint">Opcional: a quién corresponde en tu app (ej. el id de la organización). Llega en cada aviso.</span><input type="text" name="tenantRef" maxlength="120" value="${values.tenantRef ?? ""}" placeholder="org_42"></label>`)}
        ${section("Avisos del banco", "Solo se aceptan avisos dirigidos a estos correos y firmados por estos bancos.", html`
          <label>Correos donde el banco avisa <span class="hint">El Gmail del dueño de la cuenta, uno por línea.</span><textarea name="ownerEmails" required rows="2" placeholder="dueno@gmail.com">${values.ownerEmails ?? ""}</textarea></label>
          <div class="field"><span class="field-label">Bancos</span>${bankChecks(values.banks ?? BANK_IDS)}</div>`)}
        <div class="form-actions"><a class="btn btn-ghost" href="/accounts">Cancelar</a><button class="btn btn-primary" type="submit"${domains.length === 0 || apps.length === 0 ? raw(" disabled") : ""}>Crear cuenta</button></div>
      </form>`,
  });
}

const SILENT_OPTIONS = [[24, "1 día"], [72, "3 días"], [168, "7 días"], [336, "14 días"], [720, "30 días"], [0, "Nunca"]];

function readAccountForm(s) {
  const values = {
    appId: String(s.form.appId ?? ""),
    domain: String(s.form.domain ?? "").trim().toLowerCase(),
    name: String(s.form.name ?? "").trim(),
    ownerEmails: String(s.form.ownerEmails ?? ""),
    banks: list(s.form.banks).filter((b) => BANK_IDS.includes(b)),
    tenantRef: String(s.form.tenantRef ?? "").trim(),
    payKey: String(s.form.payKey ?? "").trim().slice(0, 80),
    payHolder: String(s.form.payHolder ?? "").trim().slice(0, 80),
    silentAfterHours: SILENT_OPTIONS.some(([v]) => String(v) === s.form.silentAfterHours) ? Number(s.form.silentAfterHours) : undefined,
  };
  const emails = parseEmails(values.ownerEmails);
  let error = null;
  if (!values.name || values.name.length > 60) error = "Escribe un nombre (máximo 60 caracteres).";
  else if (emails.length === 0 || emails.some((e) => !EMAIL_RE.test(e))) error = "Revisa los correos del dueño: uno válido por línea.";
  else if (values.banks.length === 0) error = "Elige al menos un banco.";
  return { values, emails, error };
}

function createAccount(s) {
  const { store } = s.ctx;
  const { values, emails, error } = readAccountForm(s);
  if (!store.apps.get(values.appId) || !s.scope.can(values.appId, "manage")) return newAccountPage(s, { error: "Elige una app.", values });
  if (error) return newAccountPage(s, { error, values });
  const { domain, error: domainError } = chooseDomain(store, values.appId, values.domain || undefined);
  if (domainError) return newAccountPage(s, { error: values.domain ? "Esa app no puede usar ese dominio." : "No hay dominio de recepción para esa app.", values });
  const account = store.accounts.create({ appId: values.appId, name: values.name, ownerEmails: emails, banks: values.banks, tenantRef: values.tenantRef || null, domain });
  s.audit("Creó la cuenta receptora", account.id, `${account.name} · ${account.address}`);
  return redirect(s.res, `/accounts/${account.id}?ok=created`);
}

function accountPage(s, id, { error = null } = {}) {
  const { store } = s.ctx;
  const a = store.accounts.get(id);
  if (!a || !s.scope.can(a.appId)) return notFound(s, "Cuenta no encontrada.");
  const manage = s.scope.can(a.appId, "manage");
  const app = store.apps.get(a.appId);
  const csrf = s.session.csrf;
  const senders = gmailFilterFor(a.banks);
  const recent = store.payments.search({ accountId: id, limit: 10 }).rows;
  const rejected = store.inbox.list({ accountId: id, limit: 10 });
  const waiting = a.status === "pending";
  const okParam = s.url.searchParams.get("ok");
  const gmailSteps = html`<ol class="steps">
    <li>Gmail → ⚙️ <b>Ver toda la configuración</b> → <b>Reenvío y correo POP/IMAP</b> → <b>Agregar una dirección de reenvío</b>: ${copyable(a.address)}</li>
    <li>Gmail manda un código de confirmación a esa dirección; aparece aquí:
      ${a.confirmationCode || a.confirmationLink
        ? html`<div class="secret mt">${a.confirmationCode ? html`<p>Código: <b class="big">${a.confirmationCode}</b> <button type="button" class="btn btn-small" data-copy="${a.confirmationCode}">Copiar</button></p>` : ""}${a.confirmationLink ? html`<p class="small">O abre este enlace con la sesión de Gmail iniciada: <a href="${a.confirmationLink}" target="_blank" rel="noopener noreferrer">confirmar reenvío</a></p>` : ""}<p class="muted small">Recibido ${fmtDate(a.confirmationAt)}</p></div>`
        : html`<p class="muted">Esperando el correo de Gmail… (la página se actualiza sola)</p>`}
      <p class="small muted">Deja marcado "Inhabilitar reenvío": solo se reenvía con el filtro del siguiente paso.</p>
    </li>
    <li>Crea un filtro: en <b>De</b> pega ${copyable(senders)} → <b>Crear filtro</b> → <b>Reenviarlo a</b> la dirección de arriba.</li>
    <li>${a.status === "active"
      ? html`${badge("Listo", "ok")} Primer aviso recibido. Último: ${fmtDate(a.lastEmailAt)}`
      : html`Haz un pago pequeño de prueba: cuando llegue el primer aviso válido, la cuenta pasa a <b>Activa</b>.`}</li>
  </ol>`;
  return page(s, {
    title: a.name,
    active: "/accounts",
    status: error ? 400 : 200,
    body: html`
      ${waiting ? raw('<span data-autorefresh="15" hidden></span>') : ""}
      <div class="head"><a class="back" href="/accounts">← Cuentas</a><div><h1>${a.name} ${accountStatus(a.status, a.silent)}</h1><p class="muted">${app ? html`App <a href="/apps/${app.id}">${app.name}</a>` : a.appId}${a.tenantRef ? ` · ref. ${a.tenantRef}` : ""}</p></div>${manage && a.status !== "disabled" ? html`<a class="btn btn-primary" href="/charges/new?account=${id}">${icon("plus")}<span>Nuevo cobro</span></a>` : ""}</div>
      ${msg(s)}${flash(error, "bad")}
      ${a.silent ? flash(html`Último aviso válido: ${fmtDate(a.lastEmailAt)}. Si esperabas pagos, revisa el filtro de Gmail del dueño y los correos rechazados${manage ? ", y prueba un aviso en Configuración" : ""}.`, "warn") : ""}
      <div class="card">
        <div class="addr">
          <div><span class="stat-label">Dirección de recepción</span><p class="muted small">El Gmail de ${a.ownerEmails.join(", ")} reenvía aquí los avisos del banco.</p></div>
          ${copyable(a.address)}
        </div>
        ${a.status === "active"
          ? html`<details class="setup"><summary>${a.silent ? html`${badge("Sin avisos", "warn")} Último aviso válido ${fmtAgo(a.lastEmailAt)}` : html`${badge("Conectada", "ok")} Recibiendo avisos · último ${fmtAgo(a.lastEmailAt)}`} <span class="muted small">· ver pasos de configuración</span></summary>${gmailSteps}</details>`
          : html`<h2 class="mt">Configurar el Gmail del dueño</h2>${gmailSteps}`}
      </div>
      ${recent.length || a.status === "active" ? html`<div class="card"><h2>Últimos pagos</h2>${paymentsTable(s, recent, app ? { [app.id]: app.name } : {}, { showAccount: false })}</div>` : ""}
      ${rejected.length ? html`<div class="card"><h2>Correos rechazados</h2>${inboxTable(rejected)}</div>` : ""}
      ${manage ? html`<details class="config"${error || (okParam && okParam !== "created") ? raw(" open") : ""}><summary>Configuración de la cuenta</summary>
      <form method="post" action="/accounts/${id}" class="card">
        ${csrfField(csrf)}
        ${section("La cuenta", "Cómo la reconoces y a quién corresponde en tu app.", html`
          <label>Nombre <input type="text" name="name" value="${a.name}" required maxlength="60"></label>
          <label>Referencia externa <span class="hint">Opcional: a quién corresponde en tu app. Llega en cada aviso como <code>tenantRef</code>.</span><input type="text" name="tenantRef" value="${a.tenantRef ?? ""}" maxlength="120"></label>`)}
        ${section("Avisos del banco", "Solo se aceptan avisos dirigidos a estos correos y firmados por estos bancos.", html`
          <label>Correos donde el banco avisa <span class="hint">Uno por línea.</span><textarea name="ownerEmails" required rows="2">${a.ownerEmails.join("\n")}</textarea></label>
          <div class="field"><span class="field-label">Bancos</span>${bankChecks(a.banks)}</div>
          <label>Alertar si no llegan avisos en <span class="hint">Se ve en Inicio y tu app recibe <code>account.silent</code>. Elige según cuánto vende esta cuenta.</span><select name="silentAfterHours">${SILENT_OPTIONS.map(([v, l]) => html`<option value="${v}"${v === a.silentAfterHours ? raw(" selected") : ""}>${l}</option>`)}</select></label>`)}
        ${section("Página de pago", "Lo que ven tus clientes cuando les envías un cobro.", html`
          <label>Llave Bre-B para cobros <span class="hint">Celular, @llave, correo…</span><input type="text" name="payKey" value="${a.payKey ?? ""}" maxlength="80" placeholder="@mitienda"></label>
          <label>Titular que ven los clientes <input type="text" name="payHolder" value="${a.payHolder ?? ""}" maxlength="80" placeholder="Nombre del titular"></label>`)}
        <div class="form-actions"><button class="btn btn-primary" type="submit">Guardar cambios</button></div>
      </form>
      <div class="two">
        <div class="card" data-eml-check="/accounts/${id}/check" data-csrf="${csrf}">
          <h2>Probar un aviso</h2>
          <p class="muted small">Sube un aviso del banco (.eml: en Gmail, ⋮ → Descargar mensaje) y mira qué leería pagoradar para esta cuenta. No guarda nada.</p>
          <label class="drop">${icon("upload")}<span><b>Elegir un aviso (.eml)</b><span class="muted small">o arrástralo aquí</span></span><input type="file" accept=".eml,message/rfc822"></label>
          <pre hidden></pre>
        </div>
        <div class="card danger-zone">
          <h2>${a.status === "disabled" ? "Cuenta desactivada" : "Desactivar o eliminar"}</h2>
          <p class="muted small">${a.status === "disabled"
            ? "Sus avisos se rechazan. Actívala para volver a recibirlos."
            : recent.length === 0
              ? "Desactivada, sus avisos se rechazan. Como aún no tiene pagos, también la puedes eliminar."
              : "Desactivada, sus avisos se rechazan. Tiene pagos, así que no se puede eliminar."}</p>
          <div class="row mt">
            ${postButton(`/accounts/${id}/toggle`, a.status === "disabled" ? "Activar" : "Desactivar", csrf, a.status === "disabled" ? { tone: "primary" } : { tone: "danger", confirm: "¿Desactivar? Sus avisos se rechazarán hasta que la actives." })}
            ${recent.length === 0 ? postButton(`/accounts/${id}/delete`, "Eliminar", csrf, { tone: "danger", confirm: "¿Eliminar esta cuenta receptora?" }) : ""}
          </div>
        </div>
      </div>
      </details>` : ""}`,
  });
}

function updateAccount(s, id) {
  const { store } = s.ctx;
  const a = store.accounts.get(id);
  if (!a || !s.scope.can(a.appId, "manage")) return notFound(s, "Cuenta no encontrada.");
  const { values, emails, error } = readAccountForm(s);
  if (error) return accountPage(s, id, { error });
  store.accounts.update(id, { name: values.name, ownerEmails: emails, banks: values.banks, tenantRef: values.tenantRef || null, payKey: values.payKey || null, payHolder: values.payHolder || null, silentAfterHours: values.silentAfterHours });
  s.audit("Editó la cuenta receptora", id, `${values.name} · ${emails.join(", ")} · ${values.banks.join(", ")}`);
  return redirect(s.res, `/accounts/${id}?ok=saved`);
}

function accountAction(s, id, action) {
  const { store } = s.ctx;
  const a = store.accounts.get(id);
  if (!a || !s.scope.can(a.appId, "manage")) return notFound(s, "Cuenta no encontrada.");
  if (action === "toggle") {
    const disable = a.status !== "disabled";
    store.accounts.setDisabled(id, disable);
    s.audit(disable ? "Desactivó la cuenta receptora" : "Activó la cuenta receptora", id, a.address);
    return redirect(s.res, `/accounts/${id}?ok=${disable ? "disabled" : "enabled"}`);
  }
  if (store.payments.search({ accountId: id, limit: 1 }).total > 0) return accountPage(s, id, { error: "Tiene pagos: desactívala en vez de eliminarla." });
  store.accounts.remove(id);
  s.audit("Eliminó la cuenta receptora", id, a.address);
  return redirect(s.res, "/accounts?ok=deleted");
}

async function checkEmail(s, id) {
  const { store, resolver } = s.ctx;
  const a = store.accounts.get(id);
  if (!a || !s.scope.can(a.appId, "manage")) return sendJson(s.res, 404, { error: "Cuenta no encontrada" });
  const raw = await readBody(s.req, 5 * 1024 * 1024);
  if (!raw?.length) return sendJson(s.res, 400, { error: "Archivo vacío o demasiado grande" });
  const r = await analyzeEmail(raw, { ownerEmails: a.ownerEmails, banks: a.banks, resolver });
  delete r.text;
  if (!r.ok && r.reason) r.motivo = REASON_LABEL[r.reason] ?? r.reason;
  return sendJson(s.res, 200, r);
}

// ---------- payments & inbox

function paymentFilters(s) {
  const q = s.url.searchParams;
  const day = (v) => (/^\d{4}-\d{2}-\d{2}$/.test(v ?? "") ? bogotaDayStart(v) : null);
  return {
    appId: q.get("app") || undefined,
    accountId: q.get("account") || undefined,
    bank: q.get("bank") || undefined,
    q: q.get("q")?.trim() || undefined,
    from: day(q.get("from")) ?? undefined,
    to: day(q.get("to")) ? new Date(new Date(day(q.get("to"))).getTime() + 86400_000).toISOString() : undefined,
  };
}

// ---------- the filter bar (Pagos, Cobros): search, pill selects, segmented choices; submits itself on change

/** This page's URL with some query params changed (null removes them); always back to page 1. */
function withParams(s, changes) {
  const p = new URLSearchParams(s.url.searchParams);
  p.delete("page");
  p.delete("ok");
  for (const [k, v] of Object.entries(changes)) {
    if (v === null || v === undefined || v === "") p.delete(k);
    else p.set(k, String(v));
  }
  const qs = p.toString();
  return `${s.url.pathname}${qs ? `?${qs}` : ""}`;
}

function pillSelect(name, label, allLabel, options, current) {
  const value = current ?? "";
  return html`<label class="pill${value ? " on" : ""}"><select name="${name}" aria-label="${label}">
    <option value="">${allLabel}</option>
    ${options.map(([v, l]) => html`<option value="${v}"${v === value ? raw(" selected") : ""}>${l}</option>`)}
  </select></label>`;
}

function searchBox(name, placeholder, value) {
  return html`<div class="search">${icon("search")}<input type="search" name="${name}" value="${value ?? ""}" placeholder="${placeholder}" aria-label="${placeholder}" autocomplete="off"></div>`;
}

/** Segmented control of links; `items`: [label, href, active, count?]. */
function segmented(label, items) {
  return html`<nav class="seg" aria-label="${label}">${items.map(
    ([text, href, active, count]) =>
      html`<a href="${href}"${active ? raw(' aria-current="true"') : ""}>${text}${count !== undefined ? html`<span class="seg-n">${count}</span>` : ""}</a>`,
  )}</nav>`;
}

const bogotaYmd = (daysAgo = 0) => new Date(Date.now() - BOGOTA_OFFSET_MS - daysAgo * 86400_000).toISOString().slice(0, 10);
const shortDay = new Intl.DateTimeFormat("es-CO", { day: "numeric", month: "short", timeZone: "UTC" });
const ymdLabel = (ymd) => shortDay.format(new Date(`${ymd}T12:00:00Z`));

/** Todo / Hoy / 7 días / 30 días, plus a "Rango" popover with two dates (inside the filter form). */
function dateFilter(s) {
  const q = s.url.searchParams;
  const from = /^\d{4}-\d{2}-\d{2}$/.test(q.get("from") ?? "") ? q.get("from") : "";
  const to = /^\d{4}-\d{2}-\d{2}$/.test(q.get("to") ?? "") ? q.get("to") : "";
  const today = bogotaYmd();
  const presets = [["Todo", null], ["Hoy", 0], ["7 días", 6], ["30 días", 29]];
  const current = !from && !to ? "Todo" : presets.find(([, d]) => d !== null && from === bogotaYmd(d) && to === today)?.[0];
  const custom = Boolean((from || to) && !current);
  const label = custom ? (from && to ? (from === to ? ymdLabel(from) : `${ymdLabel(from)} – ${ymdLabel(to)}`) : from ? `Desde ${ymdLabel(from)}` : `Hasta ${ymdLabel(to)}`) : "Rango";
  return html`${segmented("Fechas", presets.map(([text, d]) => [text, withParams(s, d === null ? { from: null, to: null } : { from: bogotaYmd(d), to: today }), current === text]))}
    <details class="pop${custom ? " on" : ""}">
      <summary class="pill-btn">${icon("week")}<span>${label}</span></summary>
      <div class="pop-body">
        <label>Desde <input type="date" name="from" value="${from}" max="${today}"></label>
        <label>Hasta <input type="date" name="to" value="${to}" max="${today}"></label>
        <button class="btn btn-primary btn-small" type="submit">Aplicar</button>
      </div>
    </details>`;
}

function filterBar(s, { rows }) {
  const active = [...s.url.searchParams.keys()].some((k) => !["page", "ok"].includes(k) && s.url.searchParams.get(k));
  return html`<form method="get" class="filterbar" data-autosubmit>
    ${rows.map((r, i) => html`<div class="fb-row">${r}${i === rows.length - 1 && active ? html`<a class="clear" href="${s.url.pathname}">Limpiar filtros</a>` : ""}</div>`)}
    <noscript><button class="btn btn-primary btn-small" type="submit">Filtrar</button></noscript>
  </form>`;
}

function paymentsPage(s) {
  const { store } = s.ctx;
  const q = s.url.searchParams;
  const pageNo = Math.max(1, Number(q.get("page") ?? 1) || 1);
  const filters = paymentFilters(s);
  const { total, cents, rows } = store.payments.search({ ...filters, appIds: s.scope.appIds, limit: 50, offset: (pageNo - 1) * 50 });
  const apps = visibleApps(s);
  const accounts = visibleAccounts(s);
  const appName = Object.fromEntries(apps.map((a) => [a.id, a.name]));
  const pageLink = (n) => withParams(s, { page: n });
  const filtered = Object.values(filters).some(Boolean);
  return page(s, {
    title: "Pagos",
    active: "/payments",
    body: html`
      <div class="head"><div><h1>Pagos</h1><p class="muted">${total} ${total === 1 ? "pago" : "pagos"} · <b class="sum">${fmtMoney(cents / 100)}</b>${filtered ? " con estos filtros" : ""}</p></div>
        <a class="btn btn-small" href="/payments.csv${s.url.search}">${icon("download")}<span>CSV</span></a></div>
      ${msg(s)}
      ${filterBar(s, {
        rows: [
          html`${searchBox("q", "Buscar pagador o referencia", q.get("q"))}
            <div class="pills">
              ${apps.length > 1 ? pillSelect("app", "App", "Todas las apps", apps.map((a) => [a.id, a.name]), q.get("app")) : ""}
              ${pillSelect("account", "Cuenta", "Todas las cuentas", accounts.map((a) => [a.id, a.name]), q.get("account"))}
              ${pillSelect("bank", "Banco", "Todos los bancos", BANK_IDS.map((b) => [b, BANK_LABEL[b] ?? b]), q.get("bank"))}
            </div>`,
          dateFilter(s),
        ],
      })}
      <div class="card">${rows.length === 0 && filtered ? html`<p class="empty">Ningún pago con estos filtros. <a href="/payments">Ver todos</a></p>` : paymentsTable(s, rows, appName)}</div>
      <div class="row">
        ${pageNo > 1 ? html`<a class="btn" href="${pageLink(pageNo - 1)}">← Anteriores</a>` : ""}
        ${pageNo * 50 < total ? html`<a class="btn" href="${pageLink(pageNo + 1)}">Siguientes →</a>` : ""}
      </div>`,
  });
}

function paymentsCsv(s) {
  const { store } = s.ctx;
  const { rows } = store.payments.search({ ...paymentFilters(s), appIds: s.scope.appIds, limit: 10_000 });
  const cell = (v) => {
    const t = String(v ?? "");
    const safe = /^[=+\-@\t\r]/.test(t) ? `'${t}` : t; // never a formula in a spreadsheet
    return /[",\n;]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
  };
  const lines = [["fecha", "pagador", "banco_origen", "banco", "metodo", "valor", "referencia", "transaccion", "cuenta", "app", "id"].join(",")];
  for (const p of rows) lines.push([p.paidAt, p.payerName, p.payerBank, p.bank, p.methodText ?? p.method, p.amount, p.reference, p.transactionId, p.accountId, p.appId, p.id].map(cell).join(","));
  s.audit("Descargó pagos en CSV", null, `${rows.length} filas`);
  s.res.writeHead(200, { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": 'attachment; filename="pagos.csv"', "Cache-Control": "no-store" });
  return s.res.end("﻿" + lines.join("\n"));
}

// ---------- charges

function chargesPage(s) {
  const { store, config } = s.ctx;
  if (expireCharges(store, { publicUrl: config.publicUrl })) void deliverDue(store, { log: s.ctx.log }).catch(() => {});
  const q = s.url.searchParams;
  const pageNo = Math.max(1, Number(q.get("page") ?? 1) || 1);
  const status = ["pending", "paid", "expired", "canceled"].includes(q.get("status")) ? q.get("status") : undefined;
  const filters = { appId: q.get("app") || undefined, accountId: q.get("account") || undefined, q: q.get("q")?.trim() || undefined };
  const { total, rows } = store.charges.search({ ...filters, appIds: s.scope.appIds, status, limit: 50, offset: (pageNo - 1) * 50 });
  const counts = store.charges.countByStatus({ ...filters, appIds: s.scope.appIds });
  const all = counts.pending + counts.paid + counts.expired + counts.canceled;
  const apps = visibleApps(s);
  const accounts = visibleAccounts(s);
  const appName = Object.fromEntries(apps.map((a) => [a.id, a.name]));
  const accountName = Object.fromEntries(accounts.map((a) => [a.id, a.name]));
  const pageLink = (n) => withParams(s, { page: n });
  const csrf = s.session.csrf;
  const tabs = [
    ["Todos", null, all],
    ["Esperando pago", "pending", counts.pending],
    ["Pagados", "paid", counts.paid],
    ["Vencidos", "expired", counts.expired],
    ["Cancelados", "canceled", counts.canceled],
  ];
  return page(s, {
    title: "Cobros",
    active: "/charges",
    body: html`
      <div class="head"><div><h1>Cobros</h1><p class="muted">Cada cobro tiene un valor único y su propia página de pago. Créalos aquí o desde tu app, por API.</p></div>${manageableApps(s).length ? html`<a class="btn btn-primary" href="/charges/new">${icon("plus")}<span>Nuevo cobro</span></a>` : ""}</div>
      ${msg(s)}
      ${filterBar(s, {
        rows: [
          html`${searchBox("q", "Buscar descripción, referencia o pagador", q.get("q"))}
            <div class="pills">
              ${apps.length > 1 ? pillSelect("app", "App", "Todas las apps", apps.map((a) => [a.id, a.name]), q.get("app")) : ""}
              ${pillSelect("account", "Cuenta", "Todas las cuentas", accounts.map((a) => [a.id, a.name]), q.get("account"))}
            </div>
            ${status ? html`<input type="hidden" name="status" value="${status}">` : ""}`,
          segmented("Estado", tabs.map(([text, v, n]) => [text, withParams(s, { status: v }), (status ?? null) === v, n])),
        ],
      })}
      <div class="card">
        ${rows.length === 0
          ? html`<p class="empty">${all === 0 && !Object.values(filters).some(Boolean) ? "Todavía no hay cobros." : html`Ningún cobro con estos filtros. <a href="/charges">Ver todos</a>`}</p>`
          : html`<div class="table-wrap"><table>
          <thead><tr><th>Creado</th><th>Cobro</th><th>Cuenta</th><th>Estado</th><th class="num">Valor</th><th></th></tr></thead>
          <tbody>${rows.map((c) => {
            const payment = c.paymentId ? store.payments.get(c.paymentId) : null;
            return html`<tr>
              <td class="t-date">${fmtDate(c.createdAt)}<div class="muted small">vence ${fmtDate(c.expiresAt)}</div></td>
              <td class="t-main"><b><a class="quiet" href="/charges/${c.id}">${c.description ?? "Cobro sin descripción"}</a></b>${c.reference ? html`<div class="muted small">Ref. ${c.reference}</div>` : ""}${apps.length > 1 ? html`<div class="muted small">${appName[c.appId] ?? c.appId}</div>` : ""}</td>
              <td><a class="quiet" href="/accounts/${c.accountId}">${accountName[c.accountId] ?? c.accountId}</a></td>
              <td>${chargeStatus(c.status)}${payment ? html`<div class="muted small">${payment.payerName} · ${fmtDate(payment.paidAt)}</div>` : ""}</td>
              <td class="num"><b>${fmtMoney(c.amount)}</b>${c.amount !== c.baseAmount ? html`<div class="muted small">pedido ${fmtMoney(c.baseAmount)}</div>` : ""}</td>
              <td class="t-act"><div class="row"><a class="btn btn-small" href="/c/${c.id}" target="_blank" rel="noopener">Página de pago</a>${c.status === "pending" && s.scope.can(c.appId, "manage") ? html`${postButton(`/charges/${c.id}/cancel`, "Cancelar", csrf, { tone: "danger", confirm: "¿Cancelar este cobro? Su página de pago dirá que fue cancelado.", small: true })}` : ""}</div></td>
            </tr>`;
          })}</tbody></table></div>`}
      </div>
      <div class="row">
        ${pageNo > 1 ? html`<a class="btn" href="${pageLink(pageNo - 1)}">← Anteriores</a>` : ""}
        ${pageNo * 50 < total ? html`<a class="btn" href="${pageLink(pageNo + 1)}">Siguientes →</a>` : ""}
      </div>`,
  });
}

function cancelCharge(s, id) {
  const { store } = s.ctx;
  const c = store.charges.get(id);
  if (!c || !s.scope.can(c.appId, "manage")) return notFound(s, "Cobro no encontrado.");
  if (store.charges.cancel(id)) s.audit("Canceló un cobro", id);
  return redirect(s.res, "/charges?ok=canceled");
}

const EXPIRY_OPTIONS = [[30, "30 minutos"], [60, "1 hora"], [240, "4 horas"], [1440, "1 día"], [4320, "3 días"], [10080, "7 días"]];
const DEFAULT_EXPIRY = 1440; // a link sent by hand may take a while to be paid

/** Accounts a charge can be created in from the panel: of an app this person manages, both switched on. */
function chargeableAccounts(s) {
  const apps = manageableApps(s).filter((a) => a.active);
  const appName = Object.fromEntries(apps.map((a) => [a.id, a.name]));
  const accounts = s.ctx.store.accounts.list().filter((a) => appName[a.appId] && a.status !== "disabled");
  return accounts.map((a) => ({ ...a, label: `${a.name}${apps.length > 1 ? ` · ${appName[a.appId]}` : ""}${a.payKey ? "" : " (sin llave Bre-B)"}` }));
}

function newChargePage(s, { error = null, values = {} } = {}) {
  if (manageableApps(s).length === 0) return notFound(s);
  const accounts = chargeableAccounts(s);
  const usable = accounts.filter((a) => a.payKey);
  const selected = values.account ?? s.url.searchParams.get("account") ?? usable[0]?.id;
  const expiry = Number(values.expiresInMinutes ?? DEFAULT_EXPIRY);
  return page(s, {
    title: "Nuevo cobro",
    active: "/charges",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><a class="back" href="/charges">← Cobros</a><div><h1>Nuevo cobro</h1><p class="muted">Crea un enlace de pago y envíaselo a quien te va a pagar por Bre-B.</p></div></div>
      ${flash(error, "bad")}
      ${accounts.length === 0
        ? flash(html`Primero crea una <a href="/accounts/new">cuenta receptora</a>.`, "warn")
        : usable.length === 0
          ? flash("Ninguna cuenta tiene llave Bre-B: agrégala en la cuenta, en Página de pago.", "warn")
          : ""}
      <form method="post" action="/charges" class="card">
        ${csrfField(s.session.csrf)}
        ${section("El cobro", "Se le suma hasta $ 999 al valor: así, cuando llega el aviso del banco, se sabe qué cobro se pagó.", html`
          <label>Cuenta donde recibes <select name="account" required>${accounts.map((a) => html`<option value="${a.id}"${a.id === selected ? raw(" selected") : ""}>${a.label}</option>`)}</select></label>
          <div class="field-pair">
            <label>Valor en pesos <input type="text" name="amount" inputmode="numeric" required maxlength="20" value="${values.amount ?? ""}" placeholder="25.000" autocomplete="off"></label>
            <label>Vence en <select name="expiresInMinutes">${EXPIRY_OPTIONS.map(([v, l]) => html`<option value="${v}"${v === expiry ? raw(" selected") : ""}>${l}</option>`)}</select></label>
          </div>
          <label>Descripción <span class="hint">Opcional. La ve quien paga.</span><input type="text" name="description" maxlength="140" value="${values.description ?? ""}" placeholder="Pedido 123"></label>
          <label>Quién va a pagar <span class="hint">Opcional. Ayuda a reconocer el pago si varios cobros piden el mismo valor.</span><input type="text" name="payerName" maxlength="120" value="${values.payerName ?? ""}" placeholder="Ana Pérez" autocomplete="off"></label>`)}
        <div class="form-actions"><a class="btn btn-ghost" href="/charges">Cancelar</a><button class="btn btn-primary" type="submit"${usable.length === 0 ? raw(" disabled") : ""}>Crear cobro</button></div>
      </form>`,
  });
}

function submitNewCharge(s) {
  const { store } = s.ctx;
  if (manageableApps(s).length === 0) return notFound(s);
  const values = {
    account: String(s.form.account ?? ""),
    amount: String(s.form.amount ?? "").trim(),
    expiresInMinutes: String(s.form.expiresInMinutes ?? DEFAULT_EXPIRY),
    description: String(s.form.description ?? "").trim(),
    payerName: String(s.form.payerName ?? "").trim(),
  };
  const account = chargeableAccounts(s).find((a) => a.id === values.account);
  if (!account) return newChargePage(s, { error: "Elige una cuenta.", values });
  if (!account.payKey) return newChargePage(s, { error: html`${account.name} no tiene llave Bre-B: quien paga no sabría a dónde enviar. <a href="/accounts/${account.id}">Agrégala en la cuenta</a>.`, values });
  const cents = parseAmountCents(values.amount);
  if (cents == null || cents % 100 !== 0 || cents < 100 || cents > 100_000_000_00) return newChargePage(s, { error: "Escribe el valor en pesos, sin centavos, hasta 100.000.000. Ej. 25.000.", values });
  const r = createCharge(store, store.apps.get(account.appId), {
    account: account.id,
    amount: cents / 100,
    expiresInMinutes: Number(values.expiresInMinutes),
    description: values.description,
    payerName: values.payerName,
  });
  if (r.error) return newChargePage(s, { error: r.error, values });
  s.audit("Creó un cobro", r.charge.id, `${fmtMoney(r.charge.amount)} · ${account.name}`);
  return redirect(s.res, `/charges/${r.charge.id}?ok=charged`);
}

function chargePage(s, id) {
  const { store, config } = s.ctx;
  if (expireCharges(store, { publicUrl: config.publicUrl })) void deliverDue(store, { log: s.ctx.log }).catch(() => {});
  const c = store.charges.get(id);
  if (!c || !s.scope.can(c.appId)) return notFound(s, "Cobro no encontrado.");
  const account = store.accounts.get(c.accountId);
  const payment = c.paymentId ? store.payments.get(c.paymentId) : null;
  const pending = c.status === "pending";
  const link = `${publicBase(s)}/c/${c.id}`;
  const message = `Hola. ${c.description ? `Para pagar ${c.description}: ` : "Para pagar: "}${fmtMoney(c.amount)} por Bre-B, aquí están los datos: ${link}`;
  return page(s, {
    title: c.description ?? "Cobro",
    active: "/charges",
    body: html`
      ${pending ? raw('<span data-autorefresh="15" hidden></span>') : ""}
      <div class="head"><a class="back" href="/charges">← Cobros</a><div><h1>${c.description ?? "Cobro"} ${chargeStatus(c.status)}</h1>${c.reference ? html`<p class="muted">Ref. ${c.reference}</p>` : ""}</div></div>
      ${msg(s)}
      ${pending && account?.status === "pending" ? flash(html`<a href="/accounts/${account.id}">${account.name}</a> todavía no ha recibido ningún aviso del banco: termina de configurarla o este pago no se reconocerá solo.`, "warn") : ""}
      <div class="card pay-hero">
        <span class="tile-ico">${icon("charges")}</span>
        <div class="pay-hero-main"><span class="stat-label">${pending ? "Valor a pagar" : "Valor del cobro"}</span><b>${fmtMoney(c.amount)}</b>${c.amount !== c.baseAmount ? html`<span class="muted">pedido ${fmtMoney(c.baseAmount)}</span>` : ""}</div>
        <dl class="pay-hero-meta">
          ${account ? html`<div><dt>Cuenta</dt><dd><a class="quiet" href="/accounts/${account.id}">${account.name}</a></dd></div>` : ""}
          ${c.status === "paid" ? "" : html`<div><dt>${c.status === "expired" ? "Venció" : "Vence"}</dt><dd>${fmtDate(c.expiresAt)}</dd></div>`}
          ${c.payerName ? html`<div><dt>Espera a</dt><dd>${c.payerName}</dd></div>` : ""}
        </dl>
      </div>
      ${payment ? html`<div class="card"><h2>Pago recibido</h2><p><b>${fmtMoney(payment.amount)}</b> de ${payment.payerName ?? "?"}${payment.payerBank ? ` · desde ${payment.payerBank}` : ""} · ${fmtDate(payment.paidAt)}${c.match ? ` · ${MATCH_LABEL[c.match] ?? c.match}` : ""}</p></div>` : ""}
      <div class="card">
        <h2>Enlace de pago</h2>
        <p class="muted small">${pending ? "Envíaselo a quien va a pagar: ahí ve el valor exacto, la llave Bre-B y cuándo se confirma. Esta página se actualiza sola." : "Este cobro ya no está esperando pago; el enlace muestra su estado."}</p>
        <p>${copyable(link)}</p>
        <div class="row mt">
          ${pending ? html`<a class="btn btn-primary" href="https://wa.me/?text=${encodeURIComponent(message)}" target="_blank" rel="noopener noreferrer">${icon("send")}<span>Enviar por WhatsApp</span></a>` : ""}
          <a class="btn" href="/c/${c.id}" target="_blank" rel="noopener">Ver página de pago</a>
          ${pending && s.scope.can(c.appId, "manage") ? postButton(`/charges/${c.id}/cancel`, "Cancelar", s.session.csrf, { tone: "danger", confirm: "¿Cancelar este cobro? Su página de pago dirá que fue cancelado." }) : ""}
        </div>
      </div>`,
  });
}

const REASON_TONE = { dkim_failed: "bad", weak_signature: "bad", not_owner: "bad", ambiguous_headers: "bad", unrecognized: "warn", unreadable: "warn", dkim_error: "warn", gmail_forwarding_confirmation: "ok" };

function inboxTable(rows) {
  if (rows.length === 0) return html`<p class="empty">Nada por aquí.</p>`;
  return html`<div class="table-wrap"><table><thead><tr><th>Fecha</th><th>Motivo</th><th>De</th><th>Asunto</th></tr></thead><tbody>
    ${rows.map((r) => html`<tr>
      <td class="t-date">${fmtDate(r.received_at)}</td>
      <td class="t-main">${badge(REASON_LABEL[r.reason] ?? r.reason, REASON_TONE[r.reason] ?? "muted")}${r.code ? html`<div class="mt">Código: <b>${r.code}</b></div>` : ""}</td>
      <td>${r.from_addr ?? ""}</td>
      <td class="t-wide">${r.subject ?? ""}${r.snippet ? html`<details><summary>Ver texto</summary><pre>${r.snippet}</pre></details>` : ""}</td>
    </tr>`)}</tbody></table></div>`;
}

function inboxPage(s) {
  return page(s, {
    title: "Correos rechazados",
    active: "/inbox",
    body: html`
      <div class="head"><div><h1>Correos rechazados</h1><p class="muted">Lo que llegó y no contó como pago, con el motivo. Se guardan 7 días.</p></div></div>
      <div class="card">${inboxTable(s.ctx.store.inbox.list({ appIds: s.scope.appIds, limit: 200 }))}</div>`,
  });
}

// ---------- settings, people, domains, my account, audit

const ROLE_LABEL = { admin: "Administrador", client: "Cliente" };
const ACCESS_LABEL = { view: "ve", manage: "gestiona" };

/** "Administrador", or the apps a client sees: "Cliente · Tienda (gestiona), Rifas (ve)". */
function personAccess(store, person, appName) {
  if (person.role !== "client") return ROLE_LABEL.admin;
  const grants = Object.entries(store.access.forAdmin(person.id)).filter(([id]) => appName[id]);
  return `Cliente · ${grants.length ? grants.map(([id, level]) => `${appName[id]} (${ACCESS_LABEL[level]})`).join(", ") : "sin apps"}`;
}

function settingsPage(s, { error = null } = {}) {
  const { store, config } = s.ctx;
  const csrf = s.session.csrf;
  const people = store.admins.list();
  const domains = store.domains.list();
  const appName = Object.fromEntries(store.apps.list().map((a) => [a.id, a.name]));
  return page(s, {
    title: "Ajustes",
    active: "/settings",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><div><h1>Ajustes</h1><p class="muted">Dominios de recepción, retención de datos y quién entra al panel.</p></div><a class="btn btn-small" href="/audit">${icon("audit")}<span>Registro de cambios</span></a></div>
      ${msg(s)}${flash(error, "bad")}
      <div class="card">
        ${section("Dominios de recepción", "Las direcciones de las cuentas (algo@dominio). Pueden estar en tu Cloudflare (tu Worker sirve para todos) o en el de un cliente (un Worker por cuenta).", html`
          ${domains.length
            ? html`<ul class="list">${domains.map((d) => html`<li>
                <span class="list-ico">${icon("inbox")}</span>
                <div class="list-main"><b>${d.name}</b><span>${cfLabel(store, d)} · ${d.appIds ? `Solo ${d.appIds.map((id) => appName[id] ?? id).join(", ")}` : "Todas las apps"} · ${d.lastEmailAt ? `último correo ${fmtAgo(d.lastEmailAt)}` : "sin correos aún"}</span></div>
                ${d.isDefault ? badge("Predeterminado", "ok") : ""}
                <a class="btn btn-small" href="/domains/${d.name}">Configurar</a>
              </li>`)}</ul>`
            : html`<p class="muted small">Aún no hay dominios.</p>`}
          <div><a class="btn" href="/domains">${icon("plus")}<span>Agregar dominio</span></a></div>`)}
      </div>
      <form method="post" action="/settings" class="card">
        ${csrfField(csrf)}
        ${section("Datos", "Los correos rechazados se guardan 7 días; las entregas, 30.", html`
          <label>Días que se guardan los pagos <span class="hint">Entre 30 y 3650.</span><input type="number" name="retentionDays" min="30" max="3650" value="${store.settings.get("retention_days", String(config.retentionDays ?? 180))}"></label>`)}
        <div class="form-actions"><button class="btn btn-primary" type="submit">Guardar cambios</button></div>
      </form>
      <div class="card">
        ${section("Personas con acceso", "Los administradores ven todo. Un cliente solo ve las apps que le asignes, para verlas o para gestionarlas. Todos entran con contraseña y código de 2 pasos.", html`
          <ul class="list">${people.map((a) => html`<li>
            <span class="list-ico">${icon("user")}</span>
            <div class="list-main"><b>${a.name || a.email}</b><span>${a.name ? `${a.email} · ` : ""}${personAccess(store, a, appName)} · último ingreso ${a.lastLoginAt ? fmtAgo(a.lastLoginAt) : "nunca"}</span></div>
            ${a.invitePending ? badge("Invitación pendiente", "warn") : a.totpEnabled ? badge("2 pasos", "ok") : badge("Sin 2 pasos", "warn")}
            ${a.id === s.admin.id
              ? html`<span class="muted small">Tú</span>`
              : html`<a class="btn btn-small" href="/settings/admins/${a.id}">Permisos</a>${postButton(`/settings/admins/${a.id}/delete`, "Quitar", csrf, { tone: "danger", small: true, confirm: `¿Quitar a ${a.email}?` })}`}
          </li>`)}</ul>
          <form method="post" action="/settings/admins" class="input-group">
            ${csrfField(csrf)}
            <input type="email" name="email" placeholder="correo@ejemplo.com" required aria-label="Correo de la persona">
            <select name="role" aria-label="Rol"><option value="client">Cliente (solo sus apps)</option><option value="admin">Administrador (todo)</option></select>
            <button class="btn" type="submit">${icon("plus")}<span>Agregar</span></button>
          </form>`)}
      </div>`,
  });
}

function saveSettings(s) {
  const { store } = s.ctx;
  const days = Number(s.form.retentionDays);
  if (!Number.isInteger(days) || days < 30 || days > 3650) return settingsPage(s, { error: "Los días deben estar entre 30 y 3650." });
  store.settings.set("retention_days", days);
  s.audit("Cambió los ajustes", null, `${days} días`);
  return redirect(s.res, "/settings?ok=saved");
}

async function createAdmin(s) {
  const { store } = s.ctx;
  const email = String(s.form.email ?? "").trim().toLowerCase();
  const role = s.form.role === "admin" ? "admin" : "client";
  if (!EMAIL_RE.test(email)) return settingsPage(s, { error: "Escribe un correo válido." });
  if (store.admins.byEmail(email)) return settingsPage(s, { error: "Ese correo ya tiene acceso." });
  // A password nobody knows, until they choose theirs with the link.
  const person = store.admins.create({ email, role, passwordHash: await hashPassword(randomToken(32)) });
  s.audit(role === "admin" ? "Agregó un administrador" : "Agregó un cliente", email);
  return personPage(s, person.id, { inviteToken: store.admins.newInvite(person.id) });
}

/** A person's role and, for a client, what they may do with each app. */
function personPage(s, id, { error = null, inviteToken = null } = {}) {
  const { store } = s.ctx;
  const person = store.admins.get(id);
  if (!person) return notFound(s);
  const apps = store.apps.list();
  const grants = store.access.forAdmin(id);
  const self = id === s.admin.id;
  const passkeyCount = store.passkeys.listFor(id).length;
  return page(s, {
    title: person.email,
    active: "/settings",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><a class="back" href="/settings">← Ajustes</a><div><h1>${person.name || person.email}</h1>${person.name ? html`<p class="muted">${person.email}</p>` : ""}</div></div>
      ${msg(s)}${flash(error, "bad")}
      ${inviteToken
        ? html`<div class="secret card"><h2>Enlace de invitación</h2><p>Envíaselo a ${person.email} por un canal seguro: quien lo abra elige la contraseña de esta cuenta. Sirve una sola vez y vence en 7 días. <b>No se volverá a mostrar.</b></p>
            <p>${copyable(`${publicBase(s)}/invite/${inviteToken}`)}</p>
            <div class="row mt"><a class="btn btn-primary" href="https://wa.me/?text=${encodeURIComponent(`Te invito a pagoradar. Entra aquí para elegir tu contraseña (sirve una vez y vence en 7 días): ${publicBase(s)}/invite/${inviteToken}`)}" target="_blank" rel="noopener noreferrer">${icon("send")}<span>Enviar por WhatsApp</span></a></div></div>`
        : person.invitePending || person.mustChangePassword
          ? html`<div class="card"><h2>Invitación pendiente</h2><p class="muted small">${person.inviteExpiresAt && new Date(person.inviteExpiresAt) > new Date() ? `Todavía no ha entrado. Vencimiento del enlace: ${fmtDate(person.inviteExpiresAt)}` : "Todavía no ha entrado y su enlace venció."} · Un enlace nuevo anula el anterior.</p><div class="row mt">${postButton(`/settings/admins/${id}/invite`, "Generar enlace nuevo", s.session.csrf)}</div></div>`
          : ""}
      <form method="post" action="/settings/admins/${id}" class="card">
        ${csrfField(s.session.csrf)}
        ${section("Rol", self ? "No puedes cambiar tu propio rol." : "Un administrador ve y cambia todo, también los ajustes y las demás personas.", html`
          <div class="checks">${Object.entries(ROLE_LABEL).map(([v, l]) => html`<label><input type="radio" name="role" value="${v}"${person.role === v ? raw(" checked") : ""}${self ? raw(" disabled") : ""}> ${l}</label>`)}</div>`)}
        <div class="client-only">${section("Apps del cliente", "Ver: pagos, cobros, cuentas y CSV. Gestionar: además crear y editar cuentas, webhook, API keys, crear y cancelar cobros y asociar pagos.", apps.length
          ? html`${apps.map((a) => html`<label>${a.name} <select name="access_${a.id}">
              <option value="">Sin acceso</option>
              ${ACCESS_LEVELS.map((level) => html`<option value="${level}"${grants[a.id] === level ? raw(" selected") : ""}>${level === "view" ? "Ver" : "Gestionar"}</option>`)}
            </select></label>`)}`
          : html`<p class="muted small">Aún no hay apps.</p>`)}</div>
        <div class="form-actions"><button class="btn btn-primary" type="submit">Guardar permisos</button></div>
      </form>
      ${!self && passkeyCount
        ? html`<div class="card danger-zone">
            <h2>Passkeys</h2>
            <p class="muted small">Tiene ${passkeyCount} ${passkeyCount === 1 ? "passkey" : "passkeys"}. Si perdió un dispositivo, quítalas: seguirá entrando con su contraseña y su código de 2 pasos.</p>
            <div class="row mt">${postButton(`/settings/admins/${id}/passkeys/delete`, "Quitar sus passkeys", s.session.csrf, { tone: "danger", confirm: `¿Quitar las passkeys de ${person.email}?` })}</div>
          </div>`
        : ""}`,
  });
}

function savePerson(s, id) {
  const { store } = s.ctx;
  const person = store.admins.get(id);
  if (!person) return notFound(s);
  const role = id === s.admin.id ? person.role : s.form.role === "admin" ? "admin" : "client";
  store.admins.setRole(id, role);
  if (role === "client") {
    for (const app of store.apps.list()) {
      const level = s.form[`access_${app.id}`];
      store.access.set(id, app.id, ACCESS_LEVELS.includes(level) ? level : null);
    }
  }
  s.audit("Cambió los permisos", person.email, personAccess(store, store.admins.get(id), Object.fromEntries(store.apps.list().map((a) => [a.id, a.name]))));
  return redirect(s.res, `/settings/admins/${id}?ok=saved`);
}

function deleteAdmin(s, id) {
  const { store } = s.ctx;
  const target = store.admins.get(id);
  if (target && id !== s.admin.id) {
    store.admins.remove(id);
    s.audit(target.role === "client" ? "Quitó un cliente" : "Quitó un administrador", target.email);
  }
  return redirect(s.res, "/settings?ok=deleted");
}

/** Where a domain's email is handled: your Cloudflare (your Worker) or one of your customers' accounts. */
function cfSelect(s, current, newName = "") {
  const accounts = s.ctx.store.cfAccounts.list();
  return html`<label>Cuenta de Cloudflare <span class="hint">Donde está el dominio. Cada cuenta necesita su Worker una sola vez, para todos sus dominios.</span><select name="cf">
      <option value="mine"${!current ? raw(" selected") : ""}>Mi cuenta (el Worker que ya tengo)</option>
      ${accounts.map((a) => html`<option value="${a.id}"${current === a.id ? raw(" selected") : ""}>${a.name}</option>`)}
      <option value="new"${current === "new" ? raw(" selected") : ""}>Otra cuenta (de un cliente)…</option>
    </select></label>
    <label class="cf-new">Nombre de la otra cuenta <span class="hint">Ej. "Cloudflare de Ana".</span><input type="text" name="cfName" maxlength="60" value="${newName}" placeholder="Cloudflare de Ana"></label>`;
}

/** The Cloudflare account chosen in cfSelect: { cfAccountId } (null = yours), { newName } or { error }. */
function readCf(s) {
  const v = String(s.form.cf ?? "mine");
  if (v === "mine") return { cfAccountId: null };
  if (v === "new") {
    const newName = String(s.form.cfName ?? "").trim();
    return newName && newName.length <= 60 ? { newName } : { error: "Escribe el nombre de la otra cuenta de Cloudflare (máximo 60 caracteres)." };
  }
  return s.ctx.store.cfAccounts.get(v) ? { cfAccountId: v } : { error: "Elige una cuenta de Cloudflare." };
}

const cfLabel = (store, d) => (d.cfAccountId ? (store.cfAccounts.get(d.cfAccountId)?.name ?? d.cfAccountId) : "Mi Cloudflare");

function domainsPage(s, { error = null, value = "" } = {}) {
  return page(s, {
    title: "Agregar dominio",
    active: "/settings",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><a class="back" href="/settings">← Ajustes</a><div><h1>Agregar dominio</h1><p class="muted">Un dominio (o subdominio) donde las cuentas reciben los avisos. Puede estar en tu Cloudflare o en el de un cliente.</p></div></div>
      ${flash(error, "bad")}
      <form method="post" action="/domains" class="card">
        ${csrfField(s.session.csrf)}
        ${section("Dominio", "Usa un subdominio (ej. pagos.tudominio.com) para no tocar el correo del dominio principal. En tu propia cuenta de Cloudflare solo hay que agregar una regla.", html`
          <label>Dominio <input type="text" name="name" required maxlength="120" value="${value}" placeholder="pagos.tudominio.com" autocapitalize="off" spellcheck="false"></label>
          ${cfSelect(s, s.form.cf === "new" ? "new" : s.form.cf && s.form.cf !== "mine" ? s.form.cf : null, String(s.form.cfName ?? ""))}`)}
        <div class="form-actions"><a class="btn btn-ghost" href="/settings">Cancelar</a><button class="btn btn-primary" type="submit">Agregar y ver cómo configurarlo</button></div>
      </form>`,
  });
}

function createDomain(s) {
  const { store } = s.ctx;
  const name = String(s.form.name ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (name.length > 120 || !DOMAIN_RE.test(name)) return domainsPage(s, { error: "El dominio no es válido.", value: name });
  if (store.domains.get(name)) return domainsPage(s, { error: "Ese dominio ya está agregado.", value: name });
  const cf = readCf(s);
  if (cf.error) return domainsPage(s, { error: cf.error, value: name });
  const cfAccountId = cf.newName ? store.cfAccounts.create(cf.newName).id : cf.cfAccountId;
  store.domains.create(name, { cfAccountId });
  s.audit("Agregó el dominio", name, cfLabel(store, store.domains.get(name)));
  return redirect(s.res, `/domains/${name}?ok=created`);
}

function domainPage(s, name, { error = null, secretShown = null } = {}) {
  const { store, config } = s.ctx;
  const d = store.domains.get(name);
  if (!d) return notFound(s, "Dominio no encontrado.");
  const csrf = s.session.csrf;
  const apps = store.apps.list();
  const accounts = store.domains.accountCount(d.name);
  const cf = d.cfAccountId ? store.cfAccounts.get(d.cfAccountId) : null;
  const siblings = store.domains.inCfAccount(d.cfAccountId).filter((x) => x.name !== d.name);
  // Another domain of the same Cloudflare account already gets email: its Worker is there.
  const workerUp = siblings.find((x) => x.lastEmailAt) ?? (d.lastEmailAt ? d : null);
  const publicUrl = config.publicUrl ?? `https://${s.req.headers.host ?? "pagoradar.tudominio.com"}`;
  const workerSteps = html`<b>Workers &amp; Pages → Create → Hello World</b>, nombre ${copyable("pagoradar-email")} → <b>Edit code</b>: pega <a href="/static/pagoradar-email-worker.js" download="pagoradar-email-worker.js">el código del Worker</a> → <b>Deploy</b>. En el Worker, <b>Settings → Variables and Secrets</b>:
    <div class="mt">Texto <code>PAGORADAR_URL</code> = ${copyable(publicUrl)}</div>
    <div class="mt">Secret <code>INGEST_SECRET</code> = ${cf
      ? secretShown
        ? html`(el de arriba)`
        : html`<details class="reveal"><summary>Mostrar secreto de ${cf.name}</summary><div class="mt">${copyable(store.cfAccounts.secret(cf.id))}</div></details>`
      : html`el mismo <code>INGEST_SECRET</code> de pagoradar en Dokploy`}</div>`;
  return page(s, {
    title: d.name,
    active: "/settings",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><a class="back" href="/settings">← Ajustes</a><div><h1>${d.name} ${d.isDefault ? badge("Predeterminado", "ok") : ""}</h1><p class="muted">${cfLabel(store, d)} · ${accounts} ${accounts === 1 ? "cuenta" : "cuentas"} · ${d.lastEmailAt ? `último correo ${fmtAgo(d.lastEmailAt)}` : "todavía no ha llegado ningún correo"}</p></div>
        ${d.isDefault ? "" : postButton(`/domains/${d.name}/default`, "Hacer predeterminado", csrf)}</div>
      ${msg(s)}${flash(error, "bad")}
      ${secretShown ? html`<div class="secret card"><h2>Nuevo secreto del Worker de ${cf?.name}</h2><p>Ponlo en el Worker de esa cuenta de Cloudflare (<code>INGEST_SECRET</code>). Hasta entonces, los correos de todos sus dominios se rechazan.</p><p>${copyable(secretShown)}</p></div>` : ""}
      <div class="card">
        <h2>Configurar en Cloudflare</h2>
        <p class="muted small">En ${cf ? html`la cuenta <b>${cf.name}</b>` : "tu cuenta de Cloudflare"}, donde está ${d.name} (o su dominio principal). Se hace una sola vez: después, cada cuenta nueva en este dominio funciona sin tocar Cloudflare.</p>
        <ol class="steps">
          <li><b>Email Routing</b> de ${d.name} → actívalo. Si es un subdominio (ej. <code>pagos</code> de <code>pagos.cliente.com</code>): <b>Settings → Subdomains → Add subdomain</b> con esa primera parte.</li>
          <li>${cf
            ? workerUp && workerUp.name !== d.name
              ? html`${badge("Ya está", "ok")} El Worker de ${cf.name} ya recibe correos (de ${workerUp.name}): no hay que hacer nada aquí. <details><summary class="small">Ver cómo se configuró</summary><div class="mt">${workerSteps}</div></details>`
              : html`<b>Solo la primera vez en ${cf.name}</b>: ${workerSteps}${siblings.length ? html`<p class="small muted">Este mismo Worker sirve para sus otros dominios: ${siblings.map((x) => x.name).join(", ")}.</p>` : ""}`
            : html`Usa el Worker <code class="nb">pagoradar-email</code> que ya tienes en tu cuenta: no hay que crear otro. <details><summary class="small">¿Aún no lo tienes?</summary><div class="mt">${workerSteps}</div></details>`}</li>
          <li><b>Email Routing → Routing rules → Catch-all address</b> de ${d.name} → acción <b>Send to a Worker</b> → <code class="nb">pagoradar-email</code>.</li>
          <li>${d.lastEmailAt ? html`${badge("Listo", "ok")} Llegan correos (último: ${fmtDate(d.lastEmailAt)}).` : html`Crea una cuenta en este dominio y agrega su dirección en Gmail: el correo de confirmación de Gmail debe aparecer en la cuenta.`}</li>
        </ol>
      </div>
      <form method="post" action="/domains/${d.name}" class="card">
        ${csrfField(csrf)}
        ${section("Cloudflare", "Si mueves el dominio a otra cuenta, configura allí el Worker (si no lo tiene) y la regla catch-all.", cfSelect(s, d.cfAccountId))}
        ${section("Quién lo puede usar", "Las apps que pueden crear cuentas en este dominio (en el panel y por API). Las cuentas que ya existen siguen funcionando aunque cambies esto.", html`
          <div class="checks">
            <label><input type="radio" name="scope" value="all"${d.appIds ? "" : raw(" checked")}> Todas las apps</label>
            <label><input type="radio" name="scope" value="some"${d.appIds ? raw(" checked") : ""}> Solo estas:</label>
          </div>
          <div class="checks scope-apps">${apps.map((a) => html`<label><input type="checkbox" name="apps" value="${a.id}"${d.appIds?.includes(a.id) ? raw(" checked") : ""}> ${a.name}</label>`)}</div>`)}
        <div class="form-actions"><button class="btn btn-primary" type="submit">Guardar</button></div>
      </form>
      <div class="card danger-zone">
        <h2>${cf ? "Secreto y eliminar" : "Eliminar"}</h2>
        <p class="muted small">${d.isDefault ? "Es el predeterminado: para eliminarlo, primero haz predeterminado otro." : accounts ? "Tiene cuentas, así que no se puede eliminar." : "Sin cuentas: se puede eliminar."}</p>
        <div class="row mt">
          ${cf ? postButton(`/domains/${d.name}/rotate`, `Cambiar secreto del Worker de ${cf.name}`, csrf, { tone: "danger", confirm: `¿Cambiar el secreto? Los correos de todos los dominios de ${cf.name} se rechazan hasta que pongas el nuevo en su Worker.` }) : ""}
          ${!d.isDefault && !accounts ? postButton(`/domains/${d.name}/delete`, "Eliminar", csrf, { tone: "danger", confirm: `¿Eliminar ${d.name}?` }) : ""}
        </div>
      </div>`,
  });
}

function updateDomain(s, name) {
  const { store } = s.ctx;
  const d = store.domains.get(name);
  if (!d) return notFound(s, "Dominio no encontrado.");
  const known = new Set(store.apps.list().map((a) => a.id));
  const appIds = s.form.scope === "some" ? list(s.form.apps).filter((id) => known.has(id)) : null;
  if (appIds && appIds.length === 0) return domainPage(s, name, { error: "Elige al menos una app, o marca Todas las apps." });
  const cf = s.form.cf === undefined ? { cfAccountId: d.cfAccountId } : readCf(s);
  if (cf.error) return domainPage(s, name, { error: cf.error });
  const cfAccountId = cf.newName ? store.cfAccounts.create(cf.newName).id : cf.cfAccountId;
  store.domains.setApps(d.name, appIds);
  if (cfAccountId !== d.cfAccountId) {
    store.domains.setCfAccount(d.name, cfAccountId);
    if (d.cfAccountId) store.cfAccounts.removeIfUnused(d.cfAccountId);
  }
  const updated = store.domains.get(d.name);
  s.audit("Editó el dominio", d.name, `${cfLabel(store, updated)} · ${appIds ? appIds.join(", ") : "todas las apps"}`);
  return redirect(s.res, `/domains/${d.name}?ok=saved`);
}

function domainAction(s, name, action) {
  const { store } = s.ctx;
  const d = store.domains.get(name);
  if (!d) return notFound(s, "Dominio no encontrado.");
  if (action === "rotate") {
    if (!d.cfAccountId) return domainPage(s, d.name, { error: "Este dominio usa tu Worker: su secreto es el INGEST_SECRET del servidor." });
    const secret = store.cfAccounts.rotateSecret(d.cfAccountId);
    s.audit("Cambió el secreto del Worker", cfLabel(store, d), d.name);
    return domainPage(s, d.name, { secretShown: secret });
  }
  if (action === "default") {
    store.settings.set("inbound_domain", d.name);
    s.audit("Cambió el dominio predeterminado", d.name);
    return redirect(s.res, `/domains/${d.name}?ok=default`);
  }
  if (d.isDefault || store.domains.accountCount(d.name) > 0) return domainPage(s, d.name, { error: "No se puede eliminar: es el predeterminado o tiene cuentas." });
  store.domains.remove(d.name);
  if (d.cfAccountId) store.cfAccounts.removeIfUnused(d.cfAccountId);
  s.audit("Eliminó el dominio", d.name);
  return redirect(s.res, "/settings?ok=deleted");
}

function mePage(s, { error = null } = {}) {
  const csrf = s.session.csrf;
  const first = s.admin.mustChangePassword;
  const passkeys = s.ctx.store.passkeys.listFor(s.admin.id);
  return page(s, {
    title: "Mi cuenta",
    active: "/me",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><div><h1>Mi cuenta</h1><p class="muted">${s.admin.email}</p></div></div>
      ${msg(s)}${flash(error, "bad")}
      ${first ? flash("Antes de seguir, cambia la contraseña temporal.", "warn") : ""}
      <form method="post" action="/me/password" class="card">
        ${csrfField(csrf)}
        ${section("Contraseña", `Mínimo ${MIN_PASSWORD} caracteres. Al cambiarla se cierran tus otras sesiones.`, html`
          <label>Contraseña actual <input type="password" name="current" required autocomplete="current-password"></label>
          <div class="field-pair">
            <label>Nueva contraseña <input type="password" name="password" required minlength="${MIN_PASSWORD}" autocomplete="new-password"></label>
            <label>Repite la nueva <input type="password" name="password2" required autocomplete="new-password"></label>
          </div>`)}
        <div class="form-actions"><button class="btn btn-primary" type="submit">Cambiar contraseña</button></div>
      </form>
      ${first
        ? ""
        : html`<div class="card">
        ${section("Passkeys", "Entra con tu huella, tu cara o el PIN del dispositivo, sin contraseña ni código. Son más seguras porque no se pueden usar en un sitio falso. Tu contraseña y tu código de 2 pasos siguen sirviendo.", html`
          ${passkeys.length
            ? html`<ul class="list">${passkeys.map((p) => html`<li>
                <span class="list-ico">${icon("key")}</span>
                <div class="list-main"><b>${p.name}</b><span>Agregada ${fmtDate(p.createdAt)} · último uso ${p.lastUsedAt ? fmtAgo(p.lastUsedAt) : "nunca"}</span></div>
                ${postButton(`/me/passkeys/${p.id}/delete`, "Quitar", csrf, { tone: "danger", small: true, confirm: `¿Quitar la passkey ${p.name}?` })}
              </li>`)}</ul>`
            : ""}
          <div class="stack-tight" data-passkey-add data-csrf="${csrf}" hidden>
            <div class="field-pair">
              <label>Nombre <span class="hint">Para reconocerla después.</span><input type="text" name="passkeyName" maxlength="60" placeholder="iPhone de Ana" autocomplete="off"></label>
              <label>Código actual de 2 pasos <span class="hint">De tu app autenticadora.</span><input type="text" name="passkeyCode" inputmode="numeric" maxlength="7" autocomplete="one-time-code" placeholder="123 456" class="code-input"></label>
            </div>
            <div><button class="btn" type="button">${icon("plus")}<span>Agregar passkey</span></button></div>
            <p class="flash flash-bad" role="alert" hidden></p>
          </div>
          <p class="muted small" data-passkey-unsupported>Este navegador no permite agregar passkeys.</p>`)}
      </div>
      <form method="post" action="/me/totp-reset" class="card">
        ${csrfField(csrf)}
        ${section("Código de 2 pasos", "¿Cambiaste de celular? Escribe un código actual y configura la app autenticadora de nuevo.", html`
          <label>Código actual <input type="text" name="code" inputmode="numeric" maxlength="7" required autocomplete="one-time-code" placeholder="123 456" class="code-input"></label>`)}
        <div class="form-actions"><button class="btn" type="submit">Configurar de nuevo</button></div>
      </form>`}`,
  });
}

async function changePassword(s) {
  const { store } = s.ctx;
  const fresh = store.admins.get(s.admin.id);
  if (!(await verifyPassword(s.form.current ?? "", fresh.passwordHash))) return mePage(s, { error: "La contraseña actual no es correcta." });
  if (String(s.form.password ?? "").length < MIN_PASSWORD) return mePage(s, { error: `La nueva contraseña debe tener al menos ${MIN_PASSWORD} caracteres.` });
  if (s.form.password !== s.form.password2) return mePage(s, { error: "Las contraseñas nuevas no coinciden." });
  store.admins.setPassword(s.admin.id, await hashPassword(s.form.password));
  store.sessions.destroyAllFor(s.admin.id, s.token);
  s.audit("Cambió su contraseña");
  return redirect(s.res, "/me?ok=password");
}

function resetTotp(s) {
  const { store } = s.ctx;
  const step = verifyTotp(store.admins.totpSecret(s.admin.id), s.form.code, { lastStep: s.admin.totpLastStep });
  if (step === null || !store.admins.useTotpStep(s.admin.id, step)) return mePage(s, { error: "Código incorrecto o ya usado." });
  store.admins.setTotp(s.admin.id, null);
  store.sessions.destroyAllFor(s.admin.id, s.token);
  store.sessions.setStage(s.token, "totp_setup");
  s.audit("Reinició su código de 2 pasos");
  return redirect(s.res, "/login/2fa/setup");
}

function auditPage(s) {
  const rows = s.ctx.store.audit.list(300);
  return page(s, {
    title: "Registro de cambios",
    active: "/audit",
    body: html`
      <div class="head"><a class="back" href="/settings">← Ajustes</a><div><h1>Registro de cambios</h1><p class="muted">Quién hizo qué en el panel (se guarda un año).</p></div></div>
      <div class="card">${rows.length === 0
        ? html`<p class="empty">Sin registros.</p>`
        : html`<div class="table-wrap"><table><thead><tr><th>Fecha</th><th>Quién</th><th>Qué</th><th>Sobre</th></tr></thead><tbody>
          ${rows.map((r) => html`<tr><td class="t-date">${fmtDate(r.at)}</td><td>${r.admin_email ?? ""}</td><td class="t-main">${r.action}${r.detail ? html`<div class="muted small">${r.detail}</div>` : ""}</td><td>${r.target ?? ""}</td></tr>`)}
        </tbody></table></div>`}</div>`,
  });
}
