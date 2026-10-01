/**
 * The first version was configured with PAGORADAR_SOURCES (JSON in the environment). On start, each source
 * not yet in the database becomes an app (same id, webhook URL and secret, and its API key) with one
 * receiving account per address — so apps already connected keep working without changing anything.
 * Afterwards the variable is ignored: everything is edited from the panel.
 */
export function importLegacySources(store, sources, log = () => {}) {
  let imported = 0;
  for (const s of sources) {
    if (store.apps.get(s.id)) continue;
    const hook = s.webhooks[0];
    store.apps.create({ id: s.id, name: s.id, webhookUrl: hook?.url ?? null, webhookSecret: hook?.secret ?? null });
    store.keys.create(s.id, "Importada de PAGORADAR_SOURCES", s.apiKey);
    let first = null;
    for (const address of s.addresses) {
      if (store.accounts.byAddress(address)) continue;
      const account = store.accounts.create({ appId: s.id, name: s.id, ownerEmails: s.ownerEmails, banks: s.banks, address, domain: address.split("@")[1] });
      first ??= account;
    }
    if (first) {
      // Payments stored before accounts existed belong to the app's (first) account.
      store.db.prepare("UPDATE payments SET account_id = ? WHERE source = ? AND account_id IS NULL").run(first.id, s.id);
      if (!store.settings.get("inbound_domain")) store.settings.set("inbound_domain", first.address.split("@")[1]);
    }
    store.audit.add("sistema", "Importó la configuración de PAGORADAR_SOURCES", s.id);
    log(`importada la fuente "${s.id}" de PAGORADAR_SOURCES (ya puedes quitar esa variable)`);
    imported++;
  }
  return imported;
}
