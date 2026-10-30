import { handleAdmin } from "./admin/routes.js";
import { handleApi } from "./api.js";
import { handleCheckout } from "./checkout.js";
import { handleDocs } from "./docs.js";
import { readBody, sendJson } from "./http.js";
import { MAX_EMAIL_BYTES, ingestAuth, ingestEmail, ingestSignature } from "./ingest.js";

export { ingestSignature };

/**
 * pagoradar's HTTP side, as a plain (req, res) handler:
 *   POST /ingest   raw email from a Cloudflare Worker (signed with INGEST_SECRET, or with its domain's secret)
 *   /v1/*          API for apps (Bearer API key) — see api.js
 *   /c/<id>        public checkout page of a charge — see checkout.js
 *   /docs          developer documentation — see docs.js
 *   GET /health
 *   everything else: the admin panel (password + 2-step code) — see admin/routes.js
 */
export function createApp(ctx) {
  const { store, config, resolver, log = console.log } = ctx;
  const full = { ...ctx, log };

  return async function handle(req, res) {
    try {
      // On every response: no MIME sniffing, and over HTTPS, HTTPS only from now on (HSTS).
      res.setHeader("X-Content-Type-Options", "nosniff");
      if (config.publicUrl?.startsWith("https://")) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
      const url = new URL(req.url, "http://x");
      const path = url.pathname.replace(/\/+$/, "") || "/";

      if (path === "/health" && req.method === "GET") {
        store.db.prepare("SELECT 1").get();
        return sendJson(res, 200, { ok: true });
      }
      if (path === "/ingest" && req.method === "POST") {
        const raw = await readBody(req, MAX_EMAIL_BYTES);
        if (raw === null) return sendJson(res, 413, { error: "Correo demasiado grande" });
        const auth = ingestAuth(store, config.ingestSecret, req.headers, raw);
        if (!auth.ok) return sendJson(res, 401, { error: "Firma inválida" });
        if (auth.domain) store.domains.touch(auth.domain.name);
        return sendJson(res, 200, await ingestEmail(store, raw, req.headers["x-pagoradar-to"], { resolver, publicUrl: config.publicUrl, log }));
      }
      if (await handleApi(req, res, url, full)) return;
      if (await handleCheckout(req, res, url, full)) return;
      if (handleDocs(req, res, url, full)) return;
      return await handleAdmin(req, res, url, full);
    } catch (e) {
      log(`error: ${e?.stack ?? e}`);
      if (!res.headersSent) sendJson(res, 500, { error: "Error interno" });
    }
  };
}
