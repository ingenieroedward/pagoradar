import { readFileSync } from "node:fs";
import { BANK_IDS } from "./parsers/index.js";

/**
 * Configuration comes from the environment. Sources (one per app or business that receives payments)
 * are JSON, in PAGORADAR_SOURCES or in the file PAGORADAR_SOURCES_FILE:
 *
 *   [{
 *     "id": "ibirifas",
 *     "addresses": ["pagos-ibirifas-k3x9@pagos.edwsystem.com"],   // where the Worker delivers its mail
 *     "ownerEmails": ["tu-correo@gmail.com"],                      // the inbox the bank writes to
 *     "banks": ["nequi_negocios", "nequi", "bancolombia"],         // optional, default all
 *     "apiKey": "…",                                               // for GET /v1/payments
 *     "webhooks": [{ "url": "https://app/api/…", "secret": "…" }]
 *   }]
 */
export function loadConfig(env = process.env) {
  const ingestSecret = env.INGEST_SECRET ?? "";
  if (ingestSecret.length < 32) throw new Error("INGEST_SECRET debe tener al menos 32 caracteres.");
  const rawSources = env.PAGORADAR_SOURCES_FILE ? readFileSync(env.PAGORADAR_SOURCES_FILE, "utf8") : (env.PAGORADAR_SOURCES ?? "[]");
  let list;
  try {
    list = JSON.parse(rawSources);
  } catch (e) {
    throw new Error(`PAGORADAR_SOURCES no es JSON válido: ${e.message}`);
  }
  return {
    port: Number(env.PORT ?? 3000),
    dbPath: env.DATABASE_PATH ?? "./data/pagoradar.db",
    ingestSecret,
    adminToken: env.ADMIN_TOKEN && env.ADMIN_TOKEN.length >= 24 ? env.ADMIN_TOKEN : null,
    retentionDays: Number(env.RETENTION_DAYS ?? 180),
    sources: validateSources(list),
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
