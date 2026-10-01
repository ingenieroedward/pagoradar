import { handleAdmin } from "./admin/routes.js";
import { handleApi } from "./api.js";
import { readBody, sendJson } from "./http.js";
import { MAX_EMAIL_BYTES, ingestEmail, ingestSignature, validIngestSignature } from "./ingest.js";

export { ingestSignature };

/**
 * pagoradar's HTTP side, as a plain (req, res) handler:
 *   POST /ingest   raw email from the Cloudflare Worker (signed with INGEST_SECRET)
 *   /v1/*          API for apps (Bearer API key) — see api.js
 *   GET /health
 *   everything else: the admin panel (password + 2-step code) — see admin/routes.js
 */
export function createApp(ctx) {
  const { store, config, resolver, log = console.log } = ctx;
  const full = { ...ctx, log };

  return async function handle(req, res) {
    try {
      const url = new URL(req.url, "http://x");
      const path = url.pathname.replace(/\/+$/, "") || "/";

      if (path === "/favicon.ico") {
        res.writeHead(204, { "Cache-Control": "public, max-age=86400" });
        return res.end();
      }
      if (path === "/health" && req.method === "GET") {
        store.db.prepare("SELECT 1").get();
        return sendJson(res, 200, { ok: true });
      }
      if (path === "/ingest" && req.method === "POST") {
        const raw = await readBody(req, MAX_EMAIL_BYTES);
        if (raw === null) return sendJson(res, 413, { error: "Correo demasiado grande" });
        if (!validIngestSignature(config.ingestSecret, req.headers, raw)) return sendJson(res, 401, { error: "Firma inválida" });
        return sendJson(res, 200, await ingestEmail(store, raw, req.headers["x-pagoradar-to"], { resolver, log }));
      }
      if (await handleApi(req, res, url, full)) return;
      return await handleAdmin(req, res, url, full);
    } catch (e) {
      log(`error: ${e?.stack ?? e}`);
      if (!res.headersSent) sendJson(res, 500, { error: "Error interno" });
    }
  };
}
