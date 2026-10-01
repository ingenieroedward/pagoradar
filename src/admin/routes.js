import { readFileSync } from "node:fs";
import QRCode from "qrcode";
import { analyzeEmail } from "../analyze.js";
import { BANK_IDS, gmailFilterFor } from "../parsers/index.js";
import { clientIp, cookie, list, parseCookies, parseForm, rateLimiter, readBody, redirect, sendHtml, sendJson } from "../http.js";
import { hashPassword, newTotpSecret, randomToken, safeEqual, totpUri, verifyPassword, verifyTotp } from "../security.js";
import { sendTestEvent } from "../api.js";
import { deliverDue } from "../webhooks.js";
import {
  BANK_LABEL,
  REASON_LABEL,
  accountStatus,
  badge,
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
};
const loginLimit = rateLimiter(10, 15 * 60_000);
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

function inboundDomain(ctx) {
  return ctx.store.settings.get("inbound_domain") ?? ctx.config.inboundDomain ?? null;
}

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
    res.writeHead(200, { "Content-Type": s.type, "Cache-Control": "public, max-age=300", "X-Content-Type-Options": "nosniff" });
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
  if (path === "/login/2fa") return loginTotp(s, method);
  if (path === "/login/2fa/setup") return setupTotp(s, method);

  if (!s.session) return redirect(res, "/login");
  if (s.session.stage === "password") return redirect(res, "/login/2fa");
  if (s.session.stage === "totp_setup") return redirect(res, "/login/2fa/setup");

  // ----- full session from here on
  let form = {};
  if (method === "POST") {
    if (path.endsWith("/check")) {
      if (!safeEqual(req.headers["x-csrf"] ?? "", s.session.csrf)) return sendJson(res, 403, { error: "CSRF" });
    } else {
      const body = await readBody(req, 256 * 1024);
      if (body === null) return sendHtml(res, 413, "Demasiado grande");
      form = parseForm(body);
      if (!safeEqual(form._csrf ?? "", s.session.csrf)) return sendHtml(res, 403, "Sesión vencida: vuelve a cargar la página.");
    }
  }
  s.form = form;
  s.audit = (action, target, detail) => store.audit.add(admin.email, action, target ?? null, detail ?? null);

  if (admin.mustChangePassword && path !== "/me" && path !== "/me/password" && path !== "/logout") return redirect(res, "/me?first=1");

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
  if (path === "/inbox" && method === "GET") return inboxPage(s);
  if (path === "/settings") return method === "POST" ? saveSettings(s) : settingsPage(s);
  if (path === "/settings/admins" && method === "POST") return createAdmin(s);
  if ((m = path.match(/^\/settings\/admins\/([\w-]+)\/delete$/)) && method === "POST") return deleteAdmin(s, m[1]);
  if (path === "/me" && method === "GET") return mePage(s);
  if (path === "/me/password" && method === "POST") return changePassword(s);
  if (path === "/me/totp-reset" && method === "POST") return resetTotp(s);
  if (path === "/audit" && method === "GET") return auditPage(s);
  return page(s, { title: "No encontrado", body: html`<div class="card"><h1>No encontrado</h1><p><a href="/">Volver al inicio</a></p></div>`, status: 404 });
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
      const ok = found && !locked && (await verifyPassword(form.password ?? "", found.passwordHash));
      if (!ok) {
        if (found && !locked) store.admins.recordFailure(found.id);
        error = locked ? "Cuenta bloqueada por intentos fallidos. Espera 15 minutos." : "Correo o contraseña incorrectos.";
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
  const today = store.payments.stats(bogotaDayStart());
  const week = store.payments.stats(new Date(Date.now() - 7 * 86400_000).toISOString());
  const failed = store.deliveries.countFailed();
  const rejected = store.inbox.countSince(new Date(Date.now() - 7 * 86400_000).toISOString());
  const accounts = store.accounts.list();
  const pending = accounts.filter((a) => a.status === "pending");
  const recent = store.payments.search({ limit: 10 }).rows;
  const appName = Object.fromEntries(store.apps.list().map((a) => [a.id, a.name]));
  const domain = inboundDomain(s.ctx);
  return page(s, {
    title: "Inicio",
    active: "/",
    body: html`
      <div class="head"><div><h1>Inicio</h1><p class="muted">Pagos que avisaron los bancos y el estado de tus integraciones.</p></div></div>
      ${!domain ? flash("Falta el dominio de recepción: configúralo en Ajustes antes de crear cuentas.", "warn") : ""}
      ${failed ? flash(html`Hay ${failed} entregas de webhook fallidas. <a href="/apps">Revisa tus apps</a>.`, "bad") : ""}
      <div class="grid">
        <div class="stat"><b>${fmtMoney(today.cents / 100)}</b><span>Hoy · ${today.n} pagos</span></div>
        <div class="stat"><b>${fmtMoney(week.cents / 100)}</b><span>Últimos 7 días · ${week.n} pagos</span></div>
        <div class="stat"><b>${accounts.length}</b><span>Cuentas receptoras${pending.length ? ` · ${pending.length} esperando` : ""}</span></div>
        <div class="stat"><b>${rejected}</b><span><a href="/inbox">Correos rechazados (7 días)</a></span></div>
      </div>
      <div class="card">
        <div class="head"><h2>Últimos pagos</h2><a href="/payments">Ver todos</a></div>
        ${paymentsTable(recent, appName, store)}
      </div>`,
  });
}

function paymentsTable(rows, appName, store) {
  if (rows.length === 0) return html`<p class="empty">Todavía no hay pagos.</p>`;
  const accountName = Object.fromEntries(store.accounts.list().map((a) => [a.id, a.name]));
  return html`<div class="table-wrap"><table>
    <thead><tr><th>Fecha</th><th>Pagador</th><th>Banco</th><th>Cuenta</th><th>App</th><th class="num">Valor</th></tr></thead>
    <tbody>${rows.map(
      (p) => html`<tr>
        <td>${fmtDate(p.paidAt)}</td>
        <td>${p.payerName}${p.payerBank ? html`<div class="muted small">desde ${p.payerBank}</div>` : ""}</td>
        <td>${BANK_LABEL[p.bank] ?? p.bank}${p.reference ? html`<div class="muted small">Ref. ${p.reference}</div>` : ""}</td>
        <td>${p.accountId ? html`<a href="/accounts/${p.accountId}">${accountName[p.accountId] ?? p.accountId}</a>` : "—"}</td>
        <td>${appName[p.appId] ?? p.appId}</td>
        <td class="num">${fmtMoney(p.amount)}</td>
      </tr>`,
    )}</tbody></table></div>`;
}

// ---------- apps

function appsPage(s, error = null) {
  const { store } = s.ctx;
  const apps = store.apps.list();
  return page(s, {
    title: "Apps",
    active: "/apps",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><div><h1>Apps</h1><p class="muted">Cada proyecto que recibe pagos (Ibirifas, otro SaaS…): su webhook y sus API keys.</p></div></div>
      ${flash(error, "bad")}
      <div class="card">
        ${apps.length === 0
          ? html`<p class="empty">Aún no hay apps.</p>`
          : html`<div class="table-wrap"><table><thead><tr><th>App</th><th>Webhook</th><th>Cuentas</th><th>Estado</th></tr></thead><tbody>
              ${apps.map((a) => html`<tr>
                <td><a href="/apps/${a.id}"><b>${a.name}</b></a><div class="muted small">${a.id}</div></td>
                <td>${a.webhookUrl ? html`<code>${a.webhookUrl}</code>` : html`<span class="muted">Sin webhook</span>`}</td>
                <td>${store.accounts.list(a.id).length}</td>
                <td>${a.active ? badge("Activa", "ok") : badge("Inactiva", "muted")}</td>
              </tr>`)}
            </tbody></table></div>`}
      </div>
      <div class="card">
        <h2>Nueva app</h2>
        <form method="post" action="/apps" class="stack">
          ${csrfField(s.session.csrf)}
          <label>Nombre <input type="text" name="name" required maxlength="60" placeholder="Ej. Ibirifas"></label>
          <label>URL del webhook <span class="hint">Opcional; se puede poner después. Ej. https://tu-app.com/api/pagoradar/webhook</span><input type="url" name="webhookUrl" maxlength="500"></label>
          <button class="btn btn-primary" type="submit">Crear app</button>
        </form>
      </div>`,
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
  if (!app) return page(s, { title: "No encontrada", body: html`<div class="card">App no encontrada.</div>`, status: 404 });
  const keys = store.keys.listForApp(id);
  const accounts = store.accounts.list(id);
  const deliveries = store.deliveries.list({ appId: id, limit: 30 });
  const csrf = s.session.csrf;
  return page(s, {
    title: app.name,
    active: "/apps",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><div><h1>${app.name}</h1><p class="muted">${app.id}</p></div><a href="/apps">← Apps</a></div>
      ${msg(s)}${flash(error, "bad")}
      ${newKey ? html`<div class="secret card"><h2>Tu nueva API key</h2><p>Cópiala ahora: <b>no se volverá a mostrar</b>.</p><p>${copyable(newKey)}</p></div>` : ""}
      <div class="two">
        <div class="card">
          <h2>Webhook</h2>
          <form method="post" action="/apps/${id}" class="stack">
            ${csrfField(csrf)}
            <label>Nombre <input type="text" name="name" value="${app.name}" required maxlength="60"></label>
            <label>URL del webhook <input type="url" name="webhookUrl" value="${app.webhookUrl ?? ""}" maxlength="500" placeholder="https://tu-app.com/api/pagoradar/webhook"></label>
            <div class="checks"><label><input type="checkbox" name="active" value="1"${app.active ? raw(" checked") : ""}> App activa (si no, sus API keys dejan de funcionar y no recibe avisos)</label></div>
            <button class="btn btn-primary" type="submit">Guardar</button>
          </form>
          <hr class="sep">
          <p><b>Secreto para verificar la firma</b> <span class="muted small">(cabecera Pagoradar-Signature)</span></p>
          ${secretShown
            ? html`<div class="secret">${copyable(secretShown)}</div>`
            : html`<details><summary>Mostrar secreto</summary><p>${copyable(store.apps.secret(id))}</p></details>`}
          <div class="row mt">
            ${postButton(`/apps/${id}/test`, "Enviar evento de prueba", csrf)}
            ${postButton(`/apps/${id}/rotate`, "Cambiar secreto", csrf, { tone: "danger", confirm: "¿Cambiar el secreto? Tu app dejará de aceptar los avisos hasta que pongas el nuevo." })}
          </div>
        </div>
        <div class="card">
          <h2>API keys</h2>
          <p class="muted small">Para que tu app consulte pagos y cree cuentas o cobros (Authorization: Bearer …).</p>
          ${keys.length
            ? html`<div class="table-wrap"><table><thead><tr><th>Nombre</th><th>Key</th><th>Último uso</th><th></th></tr></thead><tbody>
              ${keys.map((k) => html`<tr>
                <td>${k.name}<div class="muted small">${fmtDate(k.createdAt)}</div></td>
                <td><code>${k.prefix}…</code></td>
                <td>${k.revokedAt ? badge("Revocada", "muted") : fmtDate(k.lastUsedAt)}</td>
                <td>${k.revokedAt ? "" : postButton(`/apps/${id}/keys/${k.id}/revoke`, "Revocar", csrf, { tone: "danger", confirm: "¿Revocar esta API key? Lo que la use dejará de funcionar." })}</td>
              </tr>`)}</tbody></table></div>`
            : html`<p class="empty">Sin API keys.</p>`}
          <form method="post" action="/apps/${id}/keys" class="row mt">
            ${csrfField(csrf)}
            <input type="text" name="name" placeholder="Nombre (ej. producción)" maxlength="60" required class="grow">
            <button class="btn" type="submit">Crear API key</button>
          </form>
        </div>
      </div>
      <div class="card">
        <div class="head"><h2>Cuentas receptoras</h2><a class="btn btn-small" href="/accounts/new?app=${id}">Nueva cuenta</a></div>
        ${accountsTable(accounts, { [id]: app.name })}
      </div>
      <div class="card">
        <h2>Entregas del webhook</h2>
        ${deliveries.length === 0
          ? html`<p class="empty">Todavía no hay entregas.</p>`
          : html`<div class="table-wrap"><table><thead><tr><th>Fecha</th><th>Evento</th><th>Estado</th><th>Intentos</th><th>Resultado</th><th></th></tr></thead><tbody>
            ${deliveries.map((d) => html`<tr>
              <td>${fmtDate(d.created_at)}</td>
              <td>${d.type ?? ""}<div class="muted small">${d.event_id}</div></td>
              <td>${d.status === "delivered" ? badge("Entregado", "ok") : d.status === "failed" ? badge("Fallido", "bad") : badge("Pendiente", "warn")}</td>
              <td>${d.attempts}</td>
              <td>${d.last_status ? `HTTP ${d.last_status}` : ""}${d.last_error ? html`<div class="muted small">${d.last_error}</div>` : ""}${d.status === "pending" && d.attempts ? html`<div class="muted small">Próximo: ${fmtDate(d.next_attempt_at)}</div>` : ""}</td>
              <td>${d.status !== "delivered" ? postButton(`/deliveries/${d.id}/retry`, "Reintentar", csrf, { fields: { back: `/apps/${id}` } }) : ""}</td>
            </tr>`)}</tbody></table></div>`}
      </div>`,
  });
}

function updateApp(s, id) {
  const { store } = s.ctx;
  if (!store.apps.get(id)) return redirect(s.res, "/apps");
  const name = String(s.form.name ?? "").trim();
  const webhookUrl = String(s.form.webhookUrl ?? "").trim() || null;
  if (!name || name.length > 60) return appPage(s, id, { error: "Escribe un nombre (máximo 60 caracteres)." });
  if (webhookUrl && !validUrl(webhookUrl)) return appPage(s, id, { error: "La URL del webhook no es válida." });
  store.apps.update(id, { name, webhookUrl, active: s.form.active === "1" });
  s.audit("Editó la app", id, `${name} · webhook ${webhookUrl ?? "(ninguno)"} · ${s.form.active === "1" ? "activa" : "inactiva"}`);
  return redirect(s.res, `/apps/${id}?ok=saved`);
}

async function appAction(s, id, action) {
  const { store, log } = s.ctx;
  const app = store.apps.get(id);
  if (!app) return redirect(s.res, "/apps");
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
  if (s.ctx.store.keys.revoke(keyId, appId)) s.audit("Revocó una API key", appId, keyId);
  return redirect(s.res, `/apps/${appId}?ok=revoked`);
}

async function retryDelivery(s, id) {
  if (s.ctx.store.deliveries.retry(id)) {
    s.audit("Reintentó una entrega", String(id));
    await deliverDue(s.ctx.store, { log: s.ctx.log });
  }
  const back = String(s.form.back ?? "/apps");
  return redirect(s.res, `${back.startsWith("/") && !back.startsWith("//") ? back : "/apps"}?ok=retry`);
}

// ---------- receiving accounts

function accountsTable(accounts, appName) {
  if (accounts.length === 0) return html`<p class="empty">Sin cuentas receptoras.</p>`;
  return html`<div class="table-wrap"><table><thead><tr><th>Cuenta</th><th>Dirección</th><th>App</th><th>Estado</th><th>Último pago</th></tr></thead><tbody>
    ${accounts.map((a) => html`<tr>
      <td><a href="/accounts/${a.id}"><b>${a.name}</b></a>${a.tenantRef ? html`<div class="muted small">Cliente: ${a.tenantRef}</div>` : ""}</td>
      <td><code>${a.address}</code></td>
      <td>${appName[a.appId] ?? a.appId}</td>
      <td>${accountStatus(a.status)}</td>
      <td>${fmtDate(a.lastPaymentAt)}</td>
    </tr>`)}</tbody></table></div>`;
}

function accountsPage(s) {
  const { store } = s.ctx;
  const appName = Object.fromEntries(store.apps.list().map((a) => [a.id, a.name]));
  return page(s, {
    title: "Cuentas receptoras",
    active: "/accounts",
    body: html`
      <div class="head"><div><h1>Cuentas receptoras</h1><p class="muted">Cada cuenta bancaria que reenvía sus avisos a una dirección de pagoradar.</p></div><a class="btn btn-primary" href="/accounts/new">Nueva cuenta</a></div>
      ${msg(s)}
      <div class="card">${accountsTable(store.accounts.list(), appName)}</div>`,
  });
}

function bankChecks(selected) {
  return html`<div class="checks">${BANK_IDS.map((b) => html`<label><input type="checkbox" name="banks" value="${b}"${selected.includes(b) ? raw(" checked") : ""}> ${BANK_LABEL[b] ?? b}</label>`)}</div>`;
}

function newAccountPage(s, { error = null, values = {} } = {}) {
  const { store } = s.ctx;
  const apps = store.apps.list();
  const domain = inboundDomain(s.ctx);
  const selectedApp = values.appId ?? s.url.searchParams.get("app") ?? apps[0]?.id;
  return page(s, {
    title: "Nueva cuenta",
    active: "/accounts",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><div><h1>Nueva cuenta receptora</h1><p class="muted">pagoradar le dará una dirección; el Gmail del dueño reenviará ahí los avisos del banco.</p></div><a href="/accounts">← Cuentas</a></div>
      ${flash(error, "bad")}
      ${!domain ? flash(html`Primero configura el dominio de recepción en <a href="/settings">Ajustes</a>.`, "warn") : ""}
      ${apps.length === 0 ? flash(html`Primero crea una <a href="/apps">app</a>.`, "warn") : ""}
      <div class="card">
        <form method="post" action="/accounts" class="stack">
          ${csrfField(s.session.csrf)}
          <label>App <select name="appId" required>${apps.map((a) => html`<option value="${a.id}"${a.id === selectedApp ? raw(" selected") : ""}>${a.name}</option>`)}</select></label>
          <label>Nombre <span class="hint">Para reconocerla, ej. "Nequi Negocios de Ana".</span><input type="text" name="name" required maxlength="60" value="${values.name ?? ""}"></label>
          <label>Correos donde el banco avisa <span class="hint">El Gmail del dueño de la cuenta (uno por línea). Un aviso dirigido a otro correo se rechaza.</span><textarea name="ownerEmails" required>${values.ownerEmails ?? ""}</textarea></label>
          <div><b class="small">Bancos</b>${bankChecks(values.banks ?? BANK_IDS)}</div>
          <label>Id del cliente en tu app <span class="hint">Opcional: a quién pertenece en tu app (ej. el id de la organización). Llega en cada aviso.</span><input type="text" name="tenantRef" maxlength="120" value="${values.tenantRef ?? ""}"></label>
          <button class="btn btn-primary" type="submit"${!domain || apps.length === 0 ? raw(" disabled") : ""}>Crear cuenta</button>
        </form>
      </div>`,
  });
}

function readAccountForm(s) {
  const values = {
    appId: String(s.form.appId ?? ""),
    name: String(s.form.name ?? "").trim(),
    ownerEmails: String(s.form.ownerEmails ?? ""),
    banks: list(s.form.banks).filter((b) => BANK_IDS.includes(b)),
    tenantRef: String(s.form.tenantRef ?? "").trim(),
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
  const domain = inboundDomain(s.ctx);
  const { values, emails, error } = readAccountForm(s);
  if (!store.apps.get(values.appId)) return newAccountPage(s, { error: "Elige una app.", values });
  if (!domain) return newAccountPage(s, { error: "Falta el dominio de recepción (Ajustes).", values });
  if (error) return newAccountPage(s, { error, values });
  const account = store.accounts.create({ appId: values.appId, name: values.name, ownerEmails: emails, banks: values.banks, tenantRef: values.tenantRef || null, domain });
  s.audit("Creó la cuenta receptora", account.id, `${account.name} · ${account.address}`);
  return redirect(s.res, `/accounts/${account.id}?ok=created`);
}

function accountPage(s, id, { error = null } = {}) {
  const { store } = s.ctx;
  const a = store.accounts.get(id);
  if (!a) return page(s, { title: "No encontrada", body: html`<div class="card">Cuenta no encontrada.</div>`, status: 404 });
  const app = store.apps.get(a.appId);
  const csrf = s.session.csrf;
  const senders = gmailFilterFor(a.banks);
  const recent = store.payments.search({ accountId: id, limit: 10 }).rows;
  const rejected = store.inbox.list({ accountId: id, limit: 10 });
  const waiting = a.status === "pending";
  return page(s, {
    title: a.name,
    active: "/accounts",
    status: error ? 400 : 200,
    body: html`
      ${waiting ? raw('<span data-autorefresh="15" hidden></span>') : ""}
      <div class="head"><div><h1>${a.name}</h1><p class="muted">${app ? html`App <a href="/apps/${app.id}">${app.name}</a>` : a.appId} · ${accountStatus(a.status)}</p></div><a href="/accounts">← Cuentas</a></div>
      ${msg(s)}${flash(error, "bad")}
      <div class="card">
        <h2>Dirección de recepción</h2>
        <p>${copyable(a.address)}</p>
      </div>
      <div class="card">
        <h2>Configurar el Gmail del dueño (${a.ownerEmails.join(", ")})</h2>
        <ol class="steps">
          <li>Gmail → ⚙️ <b>Ver toda la configuración</b> → <b>Reenvío y correo POP/IMAP</b> → <b>Agregar una dirección de reenvío</b>: ${copyable(a.address)}</li>
          <li>Gmail manda un código de confirmación a esa dirección; aparece aquí:
            ${a.confirmationCode || a.confirmationLink
              ? html`<div class="secret mt">${a.confirmationCode ? html`<p>Código: <b class="big">${a.confirmationCode}</b></p>` : ""}${a.confirmationLink ? html`<p class="small">O abre este enlace con la sesión de Gmail iniciada: <a href="${a.confirmationLink}" target="_blank" rel="noopener noreferrer">confirmar reenvío</a></p>` : ""}<p class="muted small">Recibido ${fmtDate(a.confirmationAt)}</p></div>`
              : html`<p class="muted">Esperando el correo de Gmail… (la página se actualiza sola)</p>`}
            <p class="small muted">Deja marcado "Inhabilitar reenvío": solo se reenvía con el filtro del siguiente paso.</p>
          </li>
          <li>Crea un filtro: en <b>De</b> pega ${copyable(senders)} → <b>Crear filtro</b> → <b>Reenviarlo a</b> la dirección de arriba.</li>
          <li>${a.status === "active"
            ? html`${badge("Listo", "ok")} Recibiendo avisos (último: ${fmtDate(a.lastEmailAt)}).`
            : html`Haz un pago pequeño de prueba: cuando llegue el primer aviso válido, la cuenta pasa a <b>Activa</b>.`}</li>
        </ol>
      </div>
      <div class="two">
        <div class="card">
          <h2>Datos de la cuenta</h2>
          <form method="post" action="/accounts/${id}" class="stack">
            ${csrfField(csrf)}
            <label>Nombre <input type="text" name="name" value="${a.name}" required maxlength="60"></label>
            <label>Correos donde el banco avisa <textarea name="ownerEmails" required>${a.ownerEmails.join("\n")}</textarea></label>
            <div><b class="small">Bancos</b>${bankChecks(a.banks)}</div>
            <label>Id del cliente en tu app <input type="text" name="tenantRef" value="${a.tenantRef ?? ""}" maxlength="120"></label>
            <button class="btn btn-primary" type="submit">Guardar</button>
          </form>
          <div class="row mt">
            ${postButton(`/accounts/${id}/toggle`, a.status === "disabled" ? "Activar" : "Desactivar", csrf, a.status === "disabled" ? {} : { tone: "danger", confirm: "¿Desactivar? Sus avisos se rechazarán hasta que la actives." })}
            ${recent.length === 0 ? postButton(`/accounts/${id}/delete`, "Eliminar", csrf, { tone: "danger", confirm: "¿Eliminar esta cuenta receptora?" }) : ""}
          </div>
        </div>
        <div class="card" data-eml-check="/accounts/${id}/check" data-csrf="${csrf}">
          <h2>Probar un aviso</h2>
          <p class="muted small">Sube un aviso del banco (.eml: en Gmail, ⋮ → Descargar mensaje) y mira qué leería pagoradar para esta cuenta. No guarda nada.</p>
          <input type="file" accept=".eml,message/rfc822">
          <pre hidden></pre>
        </div>
      </div>
      <div class="card"><h2>Últimos pagos</h2>${paymentsTable(recent, app ? { [app.id]: app.name } : {}, store)}</div>
      <div class="card"><h2>Correos rechazados</h2>${inboxTable(rejected)}</div>`,
  });
}

function updateAccount(s, id) {
  const { store } = s.ctx;
  if (!store.accounts.get(id)) return redirect(s.res, "/accounts");
  const { values, emails, error } = readAccountForm(s);
  if (error) return accountPage(s, id, { error });
  store.accounts.update(id, { name: values.name, ownerEmails: emails, banks: values.banks, tenantRef: values.tenantRef || null });
  s.audit("Editó la cuenta receptora", id, `${values.name} · ${emails.join(", ")} · ${values.banks.join(", ")}`);
  return redirect(s.res, `/accounts/${id}?ok=saved`);
}

function accountAction(s, id, action) {
  const { store } = s.ctx;
  const a = store.accounts.get(id);
  if (!a) return redirect(s.res, "/accounts");
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
  if (!a) return sendJson(s.res, 404, { error: "Cuenta no encontrada" });
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
  return {
    appId: q.get("app") || undefined,
    accountId: q.get("account") || undefined,
    bank: q.get("bank") || undefined,
    q: q.get("q")?.trim() || undefined,
    from: q.get("from") ? bogotaDayStart(q.get("from")) : undefined,
    to: q.get("to") ? new Date(new Date(bogotaDayStart(q.get("to"))).getTime() + 86400_000).toISOString() : undefined,
  };
}

function paymentsPage(s) {
  const { store } = s.ctx;
  const q = s.url.searchParams;
  const pageNo = Math.max(1, Number(q.get("page") ?? 1) || 1);
  const filters = paymentFilters(s);
  const { total, rows } = store.payments.search({ ...filters, limit: 50, offset: (pageNo - 1) * 50 });
  const apps = store.apps.list();
  const accounts = store.accounts.list();
  const appName = Object.fromEntries(apps.map((a) => [a.id, a.name]));
  const qs = (extra) => {
    const p = new URLSearchParams(q);
    for (const [k, v] of Object.entries(extra)) p.set(k, v);
    return `?${p}`;
  };
  const opt = (value, label, current) => html`<option value="${value}"${value === (current ?? "") ? raw(" selected") : ""}>${label}</option>`;
  return page(s, {
    title: "Pagos",
    active: "/payments",
    body: html`
      <div class="head"><div><h1>Pagos</h1><p class="muted">${total} pagos</p></div><a class="btn" href="/payments.csv${qs({})}">Descargar CSV</a></div>
      <form method="get" class="card filters">
        <label>App <select name="app">${opt("", "Todas", q.get("app"))}${apps.map((a) => opt(a.id, a.name, q.get("app")))}</select></label>
        <label>Cuenta <select name="account">${opt("", "Todas", q.get("account"))}${accounts.map((a) => opt(a.id, a.name, q.get("account")))}</select></label>
        <label>Banco <select name="bank">${opt("", "Todos", q.get("bank"))}${BANK_IDS.map((b) => opt(b, BANK_LABEL[b] ?? b, q.get("bank")))}</select></label>
        <label>Pagador o referencia <input type="search" name="q" value="${q.get("q") ?? ""}"></label>
        <label>Desde <input type="text" name="from" placeholder="AAAA-MM-DD" pattern="\\d{4}-\\d{2}-\\d{2}" value="${q.get("from") ?? ""}"></label>
        <label>Hasta <input type="text" name="to" placeholder="AAAA-MM-DD" pattern="\\d{4}-\\d{2}-\\d{2}" value="${q.get("to") ?? ""}"></label>
        <button class="btn btn-primary" type="submit">Filtrar</button>
      </form>
      <div class="card">${paymentsTable(rows, appName, store)}</div>
      <div class="row">
        ${pageNo > 1 ? html`<a class="btn" href="${qs({ page: pageNo - 1 })}">← Anteriores</a>` : ""}
        ${pageNo * 50 < total ? html`<a class="btn" href="${qs({ page: pageNo + 1 })}">Siguientes →</a>` : ""}
      </div>`,
  });
}

function paymentsCsv(s) {
  const { store } = s.ctx;
  const { rows } = store.payments.search({ ...paymentFilters(s), limit: 10_000 });
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

function inboxTable(rows) {
  if (rows.length === 0) return html`<p class="empty">Nada por aquí.</p>`;
  return html`<div class="table-wrap"><table><thead><tr><th>Fecha</th><th>Motivo</th><th>De</th><th>Asunto</th></tr></thead><tbody>
    ${rows.map((r) => html`<tr>
      <td>${fmtDate(r.received_at)}</td>
      <td>${REASON_LABEL[r.reason] ?? r.reason}${r.code ? html`<div>Código: <b>${r.code}</b></div>` : ""}</td>
      <td>${r.from_addr ?? ""}</td>
      <td>${r.subject ?? ""}${r.snippet ? html`<details><summary>Ver texto</summary><pre>${r.snippet}</pre></details>` : ""}</td>
    </tr>`)}</tbody></table></div>`;
}

function inboxPage(s) {
  return page(s, {
    title: "Correos rechazados",
    active: "/inbox",
    body: html`
      <div class="head"><div><h1>Correos rechazados</h1><p class="muted">Lo que llegó y no contó como pago, con el motivo. Se guardan 7 días.</p></div></div>
      <div class="card">${inboxTable(s.ctx.store.inbox.list({ limit: 200 }))}</div>`,
  });
}

// ---------- settings, admins, my account, audit

function settingsPage(s, { error = null, tempPassword = null } = {}) {
  const { store, config } = s.ctx;
  const domain = inboundDomain(s.ctx);
  const csrf = s.session.csrf;
  const admins = store.admins.list();
  return page(s, {
    title: "Ajustes",
    active: "/settings",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><div><h1>Ajustes</h1></div><a href="/audit">Registro de cambios →</a></div>
      ${msg(s)}${flash(error, "bad")}
      ${tempPassword ? html`<div class="secret card"><h2>Contraseña temporal</h2><p>Dásela a la persona por un canal seguro; tendrá que cambiarla y configurar su código de 2 pasos al entrar. <b>No se volverá a mostrar.</b></p><p>${copyable(tempPassword)}</p></div>` : ""}
      <div class="two">
        <div class="card">
          <h2>Recepción de correos</h2>
          <form method="post" action="/settings" class="stack">
            ${csrfField(csrf)}
            <label>Dominio de recepción <span class="hint">Las cuentas nuevas reciben en <code>algo@dominio</code>. Ej. pagos.edwsystem.com</span><input type="text" name="inboundDomain" value="${domain ?? ""}" pattern="[a-z0-9.-]+\\.[a-z]{2,}" required></label>
            <label>Días que se guardan los pagos <input type="number" name="retentionDays" min="30" max="3650" value="${store.settings.get("retention_days", String(config.retentionDays))}"></label>
            <button class="btn btn-primary" type="submit">Guardar</button>
          </form>
          <p class="muted small mt">En Cloudflare → Email Routing de ${domain ?? "tu dominio"}: una regla <b>Catch-all</b> con acción <b>Send to a Worker</b> → tu Worker de pagoradar. Así cada cuenta nueva funciona sin tocar Cloudflare.</p>
        </div>
        <div class="card">
          <h2>Administradores</h2>
          <div class="table-wrap"><table><thead><tr><th>Correo</th><th>2 pasos</th><th>Último ingreso</th><th></th></tr></thead><tbody>
            ${admins.map((a) => html`<tr>
              <td>${a.email}${a.name ? html`<div class="muted small">${a.name}</div>` : ""}</td>
              <td>${a.totpEnabled ? badge("Activo", "ok") : badge("Pendiente", "warn")}</td>
              <td>${fmtDate(a.lastLoginAt)}</td>
              <td>${a.id === s.admin.id ? html`<span class="muted small">Tú</span>` : postButton(`/settings/admins/${a.id}/delete`, "Quitar", csrf, { tone: "danger", confirm: `¿Quitar a ${a.email}?` })}</td>
            </tr>`)}
          </tbody></table></div>
          <form method="post" action="/settings/admins" class="row mt">
            ${csrfField(csrf)}
            <input type="email" name="email" placeholder="correo@ejemplo.com" required class="grow">
            <button class="btn" type="submit">Agregar administrador</button>
          </form>
        </div>
      </div>`,
  });
}

function saveSettings(s) {
  const { store } = s.ctx;
  const domain = String(s.form.inboundDomain ?? "").trim().toLowerCase();
  const days = Number(s.form.retentionDays);
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) return settingsPage(s, { error: "El dominio no es válido." });
  if (!Number.isInteger(days) || days < 30 || days > 3650) return settingsPage(s, { error: "Los días deben estar entre 30 y 3650." });
  store.settings.set("inbound_domain", domain);
  store.settings.set("retention_days", days);
  s.audit("Cambió los ajustes", null, `dominio ${domain} · ${days} días`);
  return redirect(s.res, "/settings?ok=saved");
}

async function createAdmin(s) {
  const { store } = s.ctx;
  const email = String(s.form.email ?? "").trim().toLowerCase();
  if (!EMAIL_RE.test(email)) return settingsPage(s, { error: "Escribe un correo válido." });
  if (store.admins.byEmail(email)) return settingsPage(s, { error: "Ese correo ya es administrador." });
  const temp = randomToken(12);
  store.admins.create({ email, passwordHash: await hashPassword(temp), mustChangePassword: true });
  s.audit("Agregó un administrador", email);
  return settingsPage(s, { tempPassword: temp });
}

function deleteAdmin(s, id) {
  const { store } = s.ctx;
  const target = store.admins.get(id);
  if (target && id !== s.admin.id) {
    store.admins.remove(id);
    s.audit("Quitó un administrador", target.email);
  }
  return redirect(s.res, "/settings?ok=deleted");
}

function mePage(s, { error = null } = {}) {
  const csrf = s.session.csrf;
  const first = s.admin.mustChangePassword;
  return page(s, {
    title: "Mi cuenta",
    status: error ? 400 : 200,
    body: html`
      <div class="head"><div><h1>Mi cuenta</h1><p class="muted">${s.admin.email}</p></div></div>
      ${msg(s)}${flash(error, "bad")}
      ${first ? flash("Antes de seguir, cambia la contraseña temporal.", "warn") : ""}
      <div class="two">
        <div class="card">
          <h2>Cambiar contraseña</h2>
          <form method="post" action="/me/password" class="stack">
            ${csrfField(csrf)}
            <label>Contraseña actual <input type="password" name="current" required autocomplete="current-password"></label>
            <label>Nueva contraseña <span class="hint">Mínimo ${MIN_PASSWORD} caracteres.</span><input type="password" name="password" required minlength="${MIN_PASSWORD}" autocomplete="new-password"></label>
            <label>Repite la nueva <input type="password" name="password2" required autocomplete="new-password"></label>
            <button class="btn btn-primary" type="submit">Cambiar contraseña</button>
          </form>
        </div>
        ${first
          ? ""
          : html`<div class="card">
          <h2>Código de 2 pasos</h2>
          <p class="muted small">¿Cambiaste de celular? Escribe un código actual y configura la app autenticadora de nuevo.</p>
          <form method="post" action="/me/totp-reset" class="stack">
            ${csrfField(csrf)}
            <label>Código actual <input type="text" name="code" inputmode="numeric" maxlength="7" required autocomplete="one-time-code"></label>
            <button class="btn" type="submit">Configurar de nuevo</button>
          </form>
        </div>`}
      </div>`,
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
    active: "/settings",
    body: html`
      <div class="head"><div><h1>Registro de cambios</h1><p class="muted">Quién hizo qué en el panel (se guarda un año).</p></div><a href="/settings">← Ajustes</a></div>
      <div class="card">${rows.length === 0
        ? html`<p class="empty">Sin registros.</p>`
        : html`<div class="table-wrap"><table><thead><tr><th>Fecha</th><th>Quién</th><th>Qué</th><th>Sobre</th></tr></thead><tbody>
          ${rows.map((r) => html`<tr><td>${fmtDate(r.at)}</td><td>${r.admin_email ?? ""}</td><td>${r.action}${r.detail ? html`<div class="muted small">${r.detail}</div>` : ""}</td><td>${r.target ?? ""}</td></tr>`)}
        </tbody></table></div>`}</div>`,
  });
}
