import { createServer } from "node:http";
import { loadConfig } from "./config.js";
import { openStore } from "./store.js";
import { createApp } from "./app.js";
import { deliverDue } from "./webhooks.js";

const config = loadConfig();
const store = openStore(config.dbPath);
const log = (msg) => console.log(`${new Date().toISOString()} ${msg}`);
const server = createServer(createApp({ config, store, log }));

server.listen(config.port, () => {
  log(`pagoradar escuchando en :${config.port} · fuentes: ${config.sources.map((s) => s.id).join(", ") || "(ninguna)"}`);
});

// Webhook retries every 15 s; retention once an hour.
let delivering = false;
const tick = setInterval(async () => {
  if (delivering) return;
  delivering = true;
  try {
    await deliverDue(store, config.sources, { log });
  } catch (e) {
    log(`error enviando webhooks: ${e?.message ?? e}`);
  } finally {
    delivering = false;
  }
}, 15_000);
const cleanup = setInterval(() => store.cleanup(config.retentionDays), 3600_000);
store.cleanup(config.retentionDays);

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
