import { readFileSync } from "node:fs";
import { expireCharges } from "./charges.js";
import { deliverDue } from "./webhooks.js";
import { clientIp, rateLimiter, sendHtml, sendJson } from "./http.js";
import { BANK_LABEL, fmtMoney, html } from "./admin/ui.js";

const STATIC = {
  "/static/checkout.css": { type: "text/css; charset=utf-8", file: new URL("../public/checkout.css", import.meta.url) },
  "/static/checkout.js": { type: "text/javascript; charset=utf-8", file: new URL("../public/checkout.js", import.meta.url) },
};
const cache = new Map();
const pageLimit = rateLimiter(120, 60_000);
const ID_RE = /^\/c\/(chg_[a-z0-9]{8,40})(\/status)?$/;

/** Amount for typing in a banking app: digits only ("25037"). */
const plainAmount = (n) => String(Math.round(n));

function shell(title, body) {
  return `<!doctype html>${html`<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<title>${title}</title>
<link rel="stylesheet" href="/static/checkout.css">
<script src="/static/checkout.js" defer></script>
</head>
<body>
<main class="pay">${body}</main>
</body>
</html>`}`;
}

function statusBlock(charge, remainingSec) {
  if (charge.status === "paid") {
    return html`<section class="state state-ok" aria-live="polite">
      <div class="check" aria-hidden="true"></div>
      <h2>¡Pago recibido!</h2>
      <p>Tu banco confirmó el pago de <b>${fmtMoney(charge.paidAmount ?? charge.amount)}</b>. Ya puedes cerrar esta página.</p>
      ${charge.paidAmount != null && charge.paidAmount !== charge.amount ? html`<p class="muted small">Pagaste un valor distinto al indicado, pero ya quedó asociado a este cobro.</p>` : ""}
      ${charge.returnUrl ? html`<a class="btn" href="${charge.returnUrl}" data-return>Volver al comercio</a>` : ""}
    </section>`;
  }
  if (charge.status === "expired") {
    return html`<section class="state state-off"><h2>Este cobro venció</h2><p>Si ya pagaste, el comercio lo verá en unos minutos. Si no, pídele un cobro nuevo.</p>${charge.returnUrl ? html`<a class="btn btn-ghost" href="${charge.returnUrl}">Volver al comercio</a>` : ""}</section>`;
  }
  if (charge.status === "canceled") {
    return html`<section class="state state-off"><h2>Este cobro fue cancelado</h2><p>No hagas ningún pago con estos datos.</p></section>`;
  }
  return html`<section class="state state-wait" aria-live="polite">
    <span class="spinner" aria-hidden="true"></span>
    <div><b>Esperando tu pago…</b><p class="muted">Esta página se actualiza sola cuando el banco lo confirme. Vence en <span data-countdown="${remainingSec}">${Math.floor(remainingSec / 60)} min</span>.</p></div>
  </section>`;
}

function chargePage(charge, account) {
  const remainingSec = Math.max(0, Math.round((new Date(charge.expiresAt).getTime() - Date.now()) / 1000));
  const adjustment = charge.amount - charge.baseAmount;
  const open = charge.status === "pending";
  const banks = (account?.banks ?? []).map((b) => BANK_LABEL[b] ?? b).join(", ");
  const name = account?.name ?? "Comercio";
  return shell(
    `Pagar ${fmtMoney(charge.amount)} · ${name}`,
    html`
    <span data-charge="${charge.id}" data-status="${charge.status}" hidden></span>
    <header class="merchant">
      <span class="avatar" aria-hidden="true">${name.trim().charAt(0).toUpperCase() || "?"}</span>
      <div><b>${name}</b>${charge.description ? html`<span>${charge.description}</span>` : ""}</div>
    </header>

    <section class="amount-card${open ? "" : " dim"}">
      <p class="label">Valor a pagar</p>
      <p class="amount">${fmtMoney(charge.amount)}</p>
      ${open ? html`<button type="button" class="btn btn-small" data-copy="${plainAmount(charge.amount)}">Copiar valor</button>` : ""}
      ${adjustment !== 0 && open
        ? html`<p class="note">Paga <b>exactamente</b> este valor: ${adjustment > 0 ? html`incluye ${fmtMoney(adjustment)} para reconocer tu pago` : html`tiene ${fmtMoney(-adjustment)} de descuento para reconocer tu pago`} al instante.</p>`
        : ""}
    </section>

    ${statusBlock(charge, remainingSec)}

    ${open
      ? html`<section class="how">
      <h2>Cómo pagar</h2>
      <ol>
        <li>Abre la app de tu banco y elige <b>enviar plata con llave Bre-B</b>.</li>
        ${account?.payKey
          ? html`<li>Llave: <span class="copy"><code>${account.payKey}</code><button type="button" class="btn btn-small" data-copy="${account.payKey}">Copiar</button></span>${account.payHolder ? html`<span class="muted small block">A nombre de ${account.payHolder}</span>` : ""}</li>`
          : html`<li>Envía a la cuenta de <b>${account?.payHolder ?? name}</b>${banks ? ` (${banks})` : ""} que te indicó el comercio.</li>`}
        <li>Escribe el valor exacto: <b>${fmtMoney(charge.amount)}</b>, y confirma.</li>
      </ol>
    </section>`
      : ""}

    <footer class="foot">Pago verificado con el aviso de tu banco · <span>pagoradar</span></footer>
    <noscript><p class="muted small center">Recarga la página para ver si ya llegó tu pago.</p></noscript>`,
  );
}

/** Public pages for a charge: GET /c/<id> (what to pay and how) and GET /c/<id>/status (polled by the page). */
export function handleCheckout(req, res, url, ctx) {
  const path = url.pathname.replace(/\/+$/, "");
  if (req.method === "GET" && STATIC[path]) {
    const s = STATIC[path];
    if (!cache.has(path)) cache.set(path, readFileSync(s.file));
    res.writeHead(200, { "Content-Type": s.type, "Cache-Control": "public, max-age=300", "X-Content-Type-Options": "nosniff" });
    res.end(cache.get(path));
    return true;
  }
  const m = path.match(ID_RE);
  if (!m) {
    if (path === "/c" || path.startsWith("/c/")) {
      sendHtml(res, 404, shell("Cobro no encontrado", html`<section class="state state-off"><h2>Cobro no encontrado</h2><p>Revisa el enlace que te enviaron.</p></section>`));
      return true;
    }
    return false;
  }
  if (req.method !== "GET") {
    sendJson(res, 405, { error: "Método no permitido" });
    return true;
  }
  if (!pageLimit(clientIp(req))) {
    sendJson(res, 429, { error: "Demasiadas solicitudes" });
    return true;
  }
  const { store, config } = ctx;
  let charge = store.charges.get(m[1]);
  if (charge?.status === "pending" && new Date(charge.expiresAt).getTime() <= Date.now()) {
    if (expireCharges(store, { publicUrl: config?.publicUrl })) void deliverDue(store, { log: ctx.log }).catch(() => {});
    charge = store.charges.get(m[1]);
  }
  if (m[2]) {
    if (!charge) sendJson(res, 404, { error: "Cobro no encontrado" });
    else sendJson(res, 200, { status: charge.status, paidAt: charge.paidAt, expiresAt: charge.expiresAt, returnUrl: charge.status === "paid" ? charge.returnUrl : null });
    return true;
  }
  if (!charge) {
    sendHtml(res, 404, shell("Cobro no encontrado", html`<section class="state state-off"><h2>Cobro no encontrado</h2><p>Revisa el enlace que te enviaron.</p></section>`));
    return true;
  }
  sendHtml(res, 200, chargePage(charge, store.accounts.get(charge.accountId)), { "Referrer-Policy": "no-referrer" });
  return true;
}
