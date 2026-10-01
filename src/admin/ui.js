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

export function chargeStatus(status) {
  if (status === "paid") return badge("Pagado", "ok");
  if (status === "pending") return badge("Esperando pago", "warn");
  if (status === "expired") return badge("Vencido", "muted");
  return badge("Cancelado", "muted");
}

export const csrfField = (token) => html`<input type="hidden" name="_csrf" value="${token}">`;

export function postButton(action, label, csrf, { tone = "secondary", confirm = null, fields = {}, small = false } = {}) {
  return html`<form method="post" action="${action}" class="inline"${confirm ? html` data-confirm="${confirm}"` : ""}>
    ${csrfField(csrf)}${Object.entries(fields).map(([k, v]) => html`<input type="hidden" name="${k}" value="${v}">`)}
    <button type="submit" class="btn btn-${tone}${small ? " btn-small" : ""}">${label}</button>
  </form>`;
}

export const copyable = (value) =>
  html`<span class="copy"><code>${value}</code><button type="button" class="btn btn-small" data-copy="${value}">Copiar</button></span>`;

export function flash(msg, tone = "ok") {
  return msg ? html`<div class="flash flash-${tone}" role="status">${msg}</div>` : "";
}

// ---------- icons (inline SVG: no requests, and the CSP allows them)

const ICON_PATHS = {
  home: '<path d="m3 10 9-7 9 7v10a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>',
  apps: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>',
  accounts: '<path d="M3 21h18M5 18v-7M9.5 18v-7M14.5 18v-7M19 18v-7M12 3l9 5H3z"/>',
  payments: '<rect x="2" y="6" width="20" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M6 12h.01M18 12h.01"/>',
  charges: '<path d="M5 3v18l2.5-1.5L10 21l2-1.5 2 1.5 2.5-1.5L19 21V3l-2.5 1.5L14 3l-2 1.5L10 3 7.5 4.5z"/><path d="M9 9h6M9 13h6"/>',
  inbox: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/>',
  settings: '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M2 14h4M10 8h4M18 16h4"/>',
  user: '<circle cx="12" cy="8" r="4.5"/><path d="M20 21a8 8 0 0 0-16 0"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  more: '<circle cx="5" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="19" cy="12" r="1.6"/>',
  audit: '<path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
  today: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  week: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
  alert: '<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>',
  upload: '<path d="M12 16V4M7 9l5-5 5 5M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/>',
};
export const icon = (name, cls = "ico") =>
  raw(`<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[name] ?? ""}</svg>`);

/** The radar mark: rings, a sweep and a blip. */
export const logo = (cls = "logo") =>
  raw(`<svg class="${cls}" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="15" fill="var(--accent-soft)"/><circle cx="16" cy="16" r="10.5" fill="none" stroke="var(--accent)" stroke-opacity=".45" stroke-width="1.6"/><circle cx="16" cy="16" r="5.5" fill="none" stroke="var(--accent)" stroke-opacity=".7" stroke-width="1.6"/><path d="M16 16 25.6 9.4A11.7 11.7 0 0 0 16 4.3z" fill="var(--accent)" fill-opacity=".35"/><circle cx="16" cy="16" r="2" fill="var(--accent)"/><circle cx="21.5" cy="10.8" r="1.8" fill="var(--accent)"/></svg>`);

const NAV = [
  ["/", "Inicio", "home"],
  ["/payments", "Pagos", "payments"],
  ["/charges", "Cobros", "charges"],
  ["/accounts", "Cuentas", "accounts"],
  ["/apps", "Apps", "apps"],
  ["/inbox", "Correos", "inbox"],
  ["/settings", "Ajustes", "settings"],
];
/** On a phone the first four go in the bottom bar; the rest under "Más". */
const TABS = 4;

const navLink = ([href, label, ico], active) =>
  html`<a href="${href}"${active === href ? raw(' aria-current="page"') : ""}>${icon(ico)}<span>${label}</span></a>`;

/** The page shell. `admin` null = public pages (login, setup). */
export function layout({ title, admin = null, csrf = null, active = null, body }) {
  const head = html`<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#0a1013">
<title>${title} · pagoradar</title>
<link rel="stylesheet" href="/static/admin.css">
<script src="/static/admin.js" defer></script>
</head>`;
  if (!admin) {
    return `<!doctype html>${html`<html lang="es">
${head}
<body class="public">
<main class="narrow">
  <a class="brand brand-lg" href="/">${logo()}<span>pagoradar</span></a>
  <p class="tagline">Pagos Bre-B verificados con el aviso de tu banco</p>
  ${body}
</main>
</body>
</html>`}`;
  }
  const more = NAV.slice(TABS);
  const moreActive = more.some(([href]) => href === active) || active === "/me" || active === "/audit";
  const logout = html`<form method="post" action="/logout" class="inline">${csrfField(csrf)}<button class="linkish" type="submit">${icon("logout")}<span>Salir</span></button></form>`;
  return `<!doctype html>${html`<html lang="es">
${head}
<body class="app">
<aside class="side" aria-label="Menú">
  <a class="brand" href="/">${logo()}<span>pagoradar</span></a>
  <nav class="side-nav">${NAV.map((n) => navLink(n, active))}</nav>
  <div class="side-foot">
    <a href="/me" class="who"${active === "/me" ? raw(' aria-current="page"') : ""}>${icon("user")}<span>${admin.name || admin.email}</span></a>
    ${logout}
  </div>
</aside>
<header class="mtop">
  <a class="brand" href="/">${logo()}<span>pagoradar</span></a>
  <a href="/me" class="mtop-me" aria-label="Mi cuenta">${icon("user")}</a>
</header>
<main class="wide">
${body}
</main>
<nav class="tabbar" aria-label="Secciones">
  ${NAV.slice(0, TABS).map((n) => navLink(n, active))}
  <details class="more">
    <summary${moreActive ? raw(' aria-current="page"') : ""}>${icon("more")}<span>Más</span></summary>
    <div class="more-sheet">
      ${more.map((n) => navLink(n, active))}
      <a href="/audit"${active === "/audit" ? raw(' aria-current="page"') : ""}>${icon("audit")}<span>Auditoría</span></a>
      <a href="/me"${active === "/me" ? raw(' aria-current="page"') : ""}>${icon("user")}<span>Mi cuenta</span></a>
      ${logout}
    </div>
  </details>
</nav>
</body>
</html>`}`;
}
