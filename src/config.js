import { readFileSync } from "node:fs";
import { BANK_IDS } from "./parsers/index.js";
import { masterKeyFrom } from "./security.js";

/**
 * Only what can't live in the database comes from the environment:
 *
 *   INGEST_SECRET   shared with the Cloudflare Worker (min. 32 chars)
 *   MASTER_KEY      encrypts webhook and 2-step secrets in the database (openssl rand -hex 32)
 *   PUBLIC_URL      https://pagoradar.example.com — links, secure cookies, origin check
 *   INBOUND_DOMAIN  default domain for new receiving addresses (pagos.example.com); editable in Ajustes
 *   SETUP_TOKEN     optional: the token for creating the first admin (otherwise one is printed in the logs)
 *
 * Everything else (apps, receiving accounts, keys, webhooks) is managed from the panel. PAGORADAR_SOURCES,
 * the old JSON configuration, is imported once into the database on first start and then ignored.
 */
export function loadConfig(env = process.env) {
  const ingestSecret = env.INGEST_SECRET ?? "";
  if (ingestSecret.length < 32) throw new Error("INGEST_SECRET debe tener al menos 32 caracteres.");
  const masterKey = masterKeyFrom(env.MASTER_KEY);
  const publicUrl = String(env.PUBLIC_URL ?? "").trim().replace(/\/+$/, "") || null;
  if (publicUrl && !/^https?:\/\//.test(publicUrl)) throw new Error("PUBLIC_URL debe empezar por https://");
  const rawSources = env.PAGORADAR_SOURCES_FILE ? readFileSync(env.PAGORADAR_SOURCES_FILE, "utf8") : (env.PAGORADAR_SOURCES ?? "[]");
  let legacy;
  try {
    legacy = JSON.parse(rawSources);
  } catch (e) {
    throw new Error(`PAGORADAR_SOURCES no es JSON válido: ${e.message}`);
  }
  return {
    port: Number(env.PORT ?? 3000),
    dbPath: env.DATABASE_PATH ?? "./data/pagoradar.db",
    ingestSecret,
    masterKey,
    publicUrl,
    inboundDomain: String(env.INBOUND_DOMAIN ?? "").trim().toLowerCase() || null,
    setupToken: env.SETUP_TOKEN && env.SETUP_TOKEN.length >= 16 ? env.SETUP_TOKEN : null,
    retentionDays: Number(env.RETENTION_DAYS ?? 180),
    legacySources: validateSources(legacy),
  };
}

export function validateSources(list) {
  if (!Array.isArray(list)) throw new Error("PAGORADAR_SOURCES debe ser una lista.");
  const ids = new Set();
  const addresses = new Set();
  return list.map((s, i) => {
    const where = `fuente ${i + 1}${s?.id ? ` (${s.id})` : ""}`;
    if (!s || typeof s.id !== "string" || !/^[a-z0-9][a-z0-9_-]{0,39}$/.test(s.id)) throw new Error(`${where}: "id" en minúsculas, números, - o _.`);
    if (ids.has(s.id)) throw new Error(`${where}: id repetido.`);
    ids.add(s.id);
    const addrs = (s.addresses ?? []).map((a) => String(a).trim().toLowerCase());
    if (addrs.length === 0) throw new Error(`${where}: falta "addresses".`);
    for (const a of addrs) {
      if (addresses.has(a)) throw new Error(`${where}: la dirección ${a} ya es de otra fuente.`);
      addresses.add(a);
    }
    const owners = (s.ownerEmails ?? []).map((a) => String(a).trim().toLowerCase());
    if (owners.length === 0) throw new Error(`${where}: falta "ownerEmails" (el correo al que te escribe el banco).`);
    const banks = s.banks ?? BANK_IDS;
    for (const b of banks) if (!BANK_IDS.includes(b)) throw new Error(`${where}: banco desconocido "${b}". Opciones: ${BANK_IDS.join(", ")}.`);
    if (typeof s.apiKey !== "string" || s.apiKey.length < 24) throw new Error(`${where}: "apiKey" de al menos 24 caracteres.`);
    const webhooks = (s.webhooks ?? []).map((w, j) => {
      if (!w || typeof w.url !== "string" || !/^https?:\/\//.test(w.url)) throw new Error(`${where}: webhook ${j + 1} sin url válida.`);
      if (typeof w.secret !== "string" || w.secret.length < 24) throw new Error(`${where}: webhook ${j + 1} necesita "secret" de al menos 24 caracteres.`);
      return { url: w.url, secret: w.secret };
    });
    return { id: s.id, addresses: addrs, ownerEmails: owners, banks, apiKey: s.apiKey, webhooks };
  });
}
