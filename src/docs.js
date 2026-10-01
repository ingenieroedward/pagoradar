import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { sendHtml } from "./http.js";

const FILES = {
  "/static/docs.css": { type: "text/css; charset=utf-8", file: new URL("../public/docs.css", import.meta.url) },
  "/static/docs.js": { type: "text/javascript; charset=utf-8", file: new URL("../public/docs.js", import.meta.url) },
};
const PAGE = new URL("../public/docs.html", import.meta.url);
const cache = new Map();
const read = (url) => {
  if (!cache.has(url.href)) cache.set(url.href, readFileSync(url));
  return cache.get(url.href);
};
const V = createHash("sha256").update(read(FILES["/static/docs.css"].file)).update(read(FILES["/static/docs.js"].file)).digest("hex").slice(0, 10);
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/** GET /docs: the developer documentation (public, no data), with this server's own URL in the examples. */
export function handleDocs(req, res, url, ctx) {
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (req.method !== "GET") return false;
  if (FILES[path]) {
    res.writeHead(200, { "Content-Type": FILES[path].type, "Cache-Control": "public, max-age=86400", "X-Content-Type-Options": "nosniff" });
    res.end(read(FILES[path].file));
    return true;
  }
  if (path !== "/docs") return false;
  const base = escapeHtml(ctx.config?.publicUrl ?? `https://${req.headers.host ?? "pagoradar.tudominio.com"}`);
  sendHtml(res, 200, read(PAGE).toString("utf8").replaceAll("{{BASE}}", base).replaceAll("{{V}}", V), { "Cache-Control": "public, max-age=300" });
  return true;
}
