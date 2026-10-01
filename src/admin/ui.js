/**
 * HTML for the admin panel, rendered on the server. `html` is a tagged template that escapes every
 * interpolated value unless it is itself `html` output (or `raw()`), so user data can never inject markup.
 */

class Safe {
  constructor(value) {
    this.value = value;
  }
  toString() {
    return this.value;
  }
}

export const raw = (s) => new Safe(String(s));

const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const escape = (s) => String(s).replace(/[&<>"']/g, (c) => ESC[c]);

function render(value) {
  if (value === null || value === undefined || value === false) return "";
  if (value instanceof Safe) return value.value;
  if (Array.isArray(value)) return value.map(render).join("");
  return escape(value);
}

export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += render(values[i]) + strings[i + 1];
  return new Safe(out);
}

// ---------- formatting

const money = new Intl.NumberFormat("es-CO", { style: "currency", currency: "COP", maximumFractionDigits: 0 });
export const fmtMoney = (n) => money.format(n);
const dt = new Intl.DateTimeFormat("es-CO", { day: "numeric", month: "short", hour: "numeric", minute: "2-digit", timeZone: "America/Bogota" });
export const fmtDate = (iso) => (iso ? dt.format(new Date(iso)) : "—");

export const BANK_LABEL = { nequi_negocios: "Nequi Negocios", nequi: "Nequi", bancolombia: "Bancolombia" };
export const REASON_LABEL = {
  dkim_failed: "Sin firma válida del banco (posible correo falso)",
  weak_signature: "Firma del banco incompleta",
  not_a_bank: "No viene de un banco soportado",
  not_owner: "Aviso de otra cuenta (no de los correos dueños)",
  unrecognized: "Formato del banco que aún no entendemos",
  not_approved: "Venta no aprobada",
  unknown_address: "Dirección sin cuenta receptora",
  account_disabled: "Cuenta receptora desactivada",
  ambiguous_headers: "Cabeceras duplicadas",
  gmail_forwarding_confirmation: "Confirmación de reenvío de Gmail",
  unreadable: "Correo ilegible",
  dkim_error: "Error verificando la firma",
};

// ---------- components

export const badge = (text, tone = "muted") => html`<span class="badge badge-${tone}">${text}</span>`;

export function accountStatus(status) {
  if (status === "active") return badge("Activa", "ok");
  if (status === "disabled") return badge("Desactivada", "muted");
  return badge("Esperando primer aviso", "warn");
}

export const csrfField = (token) => html`<input type="hidden" name="_csrf" value="${token}">`;

export function postButton(action, label, csrf, { tone = "secondary", confirm = null, fields = {} } = {}) {
  return html`<form method="post" action="${action}" class="inline"${confirm ? html` data-confirm="${confirm}"` : ""}>
    ${csrfField(csrf)}${Object.entries(fields).map(([k, v]) => html`<input type="hidden" name="${k}" value="${v}">`)}
    <button type="submit" class="btn btn-${tone}">${label}</button>
  </form>`;
}

export const copyable = (value) =>
  html`<span class="copy"><code>${value}</code><button type="button" class="btn btn-small" data-copy="${value}">Copiar</button></span>`;

export function flash(msg, tone = "ok") {
  return msg ? html`<div class="flash flash-${tone}" role="status">${msg}</div>` : "";
}

const NAV = [
  ["/", "Inicio"],
  ["/apps", "Apps"],
  ["/accounts", "Cuentas"],
  ["/payments", "Pagos"],
  ["/inbox", "Correos"],
  ["/settings", "Ajustes"],
];

/** The page shell. `admin` null = public pages (login, setup). */
export function layout({ title, admin = null, csrf = null, active = null, body }) {
  return `<!doctype html>${html`<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${title} · pagoradar</title>
<link rel="stylesheet" href="/static/admin.css">
<script src="/static/admin.js" defer></script>
</head>
<body>
<header class="top">
  <a class="brand" href="/"><span class="dot"></span>pagoradar</a>
  ${
    admin
      ? html`<nav aria-label="Secciones">${NAV.map(([href, label]) => html`<a href="${href}"${active === href ? raw(' aria-current="page"') : ""}>${label}</a>`)}</nav>
  <div class="me">
    <a href="/me" class="who">${admin.email}</a>
    <form method="post" action="/logout" class="inline">${csrfField(csrf)}<button class="btn btn-small" type="submit">Salir</button></form>
  </div>`
      : ""
  }
</header>
<main class="${admin ? "wide" : "narrow"}">
${body}
</main>
</body>
</html>`}`;
}
