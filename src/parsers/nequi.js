import { parseAmountCents } from "../amount.js";
import { parseLongDate } from "../dates.js";

/**
 * Nequi (personal): "¡Recibiste plata por Bre-B!" —
 * "Recibiste 100.000 de Ana Pérez el 16 de septiembre de 2026 a las 7:09 p.m, desde el banco Banco Uno."
 */
const RECEIVED = /Recibiste\s+(\$?\s*[\d.,]+)\s+de\s+(.+?)\s+el\s+(\d{1,2}\s+de\s+[a-záéíóú]+\s+de\s+\d{4}(?:\s+a\s+las\s+\d{1,2}:\d{2}\s*(?:[ap]\.?\s*m\.?)?)?)(?:[,.]?\s*desde\s+(?:el\s+banco\s+)?(.+?)\.)?(?=\s|$)/i;

export const nequi = {
  id: "nequi",
  name: "Nequi",
  dkimDomains: ["nequi.com.co"],
  matches: (text) => RECEIVED.test(text),
  parse(text) {
    const m = RECEIVED.exec(text);
    if (!m) return null;
    const amountCents = parseAmountCents(m[1]);
    if (amountCents == null) return null;
    return {
      approved: true,
      amountCents,
      payerName: m[2].trim(),
      payerBank: m[4]?.trim() || null,
      reference: null,
      transactionId: null,
      method: /Bre-?B/i.test(text) ? "breb" : "transfer",
      methodText: null,
      accountHint: null,
      paidAt: parseLongDate(m[3]),
    };
  },
};
