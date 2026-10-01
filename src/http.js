/** Small helpers on top of node:http (no framework). */

export function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > max) {
      req.resume();
      return resolve(null);
    }
    const chunks = [];
    let size = 0;
    let tooBig = false;
    req.on("data", (c) => {
      size += c.length;
      if (size > max) tooBig = true;
      else chunks.push(c);
    });
    req.on("end", () => resolve(tooBig ? null : Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    const k = part.slice(0, i).trim();
    if (k) out[k] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

/** application/x-www-form-urlencoded → { key: value | value[] }. */
export function parseForm(buf) {
  const out = {};
  for (const [k, v] of new URLSearchParams(buf?.toString("utf8") ?? "")) {
    if (k in out) out[k] = [].concat(out[k], v);
    else out[k] = v;
  }
  return out;
}

export const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

export function cookie(name, value, { maxAge, secure, path = "/", sameSite = "Strict" } = {}) {
  return [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${path}`,
    "HttpOnly",
    `SameSite=${sameSite}`,
    secure ? "Secure" : null,
    maxAge !== undefined ? `Max-Age=${maxAge}` : null,
  ]
    .filter(Boolean)
    .join("; ");
}

/** The visitor's IP: Cloudflare's header when present, else the first X-Forwarded-For hop, else the socket. */
export function clientIp(req) {
  return String(req.headers["cf-connecting-ip"] ?? String(req.headers["x-forwarded-for"] ?? "").split(",")[0] ?? "").trim() || req.socket.remoteAddress || "?";
}

export function sendJson(res, status, body, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(JSON.stringify(body));
}

const PAGE_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin",
};

export function sendHtml(res, status, html, headers = {}) {
  res.writeHead(status, { ...PAGE_HEADERS, ...headers });
  res.end(html);
}

export function redirect(res, location, headers = {}) {
  res.writeHead(303, { Location: location, "Cache-Control": "no-store", ...headers });
  res.end();
}

/** In-memory sliding-window limiter: at most `max` hits per `windowMs` per key. */
export function rateLimiter(max, windowMs) {
  const hits = new Map();
  return (key) => {
    const now = Date.now();
    const recent = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
    if (recent.length >= max) {
      hits.set(key, recent);
      return false;
    }
    recent.push(now);
    hits.set(key, recent);
    if (hits.size > 10_000) for (const [k, v] of hits) if (v.every((t) => now - t >= windowMs)) hits.delete(k);
    return true;
  };
}
