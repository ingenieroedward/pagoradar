import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { loadConfig } from "./config.js";
import { openStore } from "./store.js";
import { createApp } from "./app.js";
import { deliverDue } from "./webhooks.js";
import { importLegacySources } from "./importLegacy.js";
import { expireCharges } from "./charges.js";
import { randomToken } from "./security.js";

const config = loadConfig();
const log = (msg) => console.log(`${new Date().toISOString()} ${msg}`);
const newDatabase = config.dbPath !== ":memory:" && !existsSync(config.dbPath);
const store = openStore(config.dbPath, { masterKey: config.masterKey });
// A fresh database on a server that already had one means the data volume wasn't mounted (or changed):
// say so loudly before anyone recreates the admin over it.
if (newDatabase) log(`AVISO: base de datos nueva en ${config.dbPath}. Si pagoradar ya tenía datos, el volumen no es el de antes (ver README → "Datos y volumen").`);

importLegacySources(store, config.legacySources, log);
if (config.inboundDomain && !store.settings.get("inbound_domain")) store.settings.set("inbound_domain", config.inboundDomain);

// No admin yet: a one-time link to create the first one (SETUP_TOKEN, or a random token printed here).
let setupToken = null;
if (store.admins.count() === 0) {
  setupToken = config.setupToken ?? randomToken(18);
  log(`No hay administrador. Créalo en: ${config.publicUrl ?? `http://localhost:${config.port}`}/setup?token=${setupToken}`);
}

const server = createServer(createApp({ store, config, log, get setupToken() { return setupToken; } }));
server.listen(config.port, () => {
  log(`pagoradar escuchando en :${config.port} · ${store.apps.list().length} apps · ${store.accounts.list().length} cuentas receptoras`);
});

// Expired charges and webhook retries every 15 s; retention once an hour.
let delivering = false;
const tick = setInterval(async () => {
  if (delivering) return;
  delivering = true;
  try {
    const expired = expireCharges(store, { publicUrl: config.publicUrl });
    if (expired) log(`${expired} cobro(s) vencido(s)`);
    await deliverDue(store, { log });
  } catch (e) {
    log(`error enviando webhooks: ${e?.message ?? e}`);
  } finally {
    delivering = false;
  }
}, 15_000);
const retention = () => store.cleanup(Number(store.settings.get("retention_days", config.retentionDays)));
const cleanup = setInterval(retention, 3600_000);
retention();

for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () => {
    clearInterval(tick);
    clearInterval(cleanup);
    server.close(() => {
      store.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
