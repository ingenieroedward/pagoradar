import { parseAmountCents } from "../amount.js";
import { parseNumericDate } from "../dates.js";

// "recibiste una transferencia de JOSE PEREZ por $4,000.00 en tu cuenta *0000 conectada a la llave x@y.com el 30/09/26 a las 18:16"
const FROM_FIRST = /recibiste (?:una transferencia|un pago|una consignaci[óo]n) de (.+?) por (\$?\s*[\d.,]+) en (?:tu )?cuenta (\*+\s?\d+)(?: conectada a la llave (\S+?))? el (\d{1,2}\/\d{1,2}\/\d{2,4}) a las (\d{1,2}:\d{2}(?:\s*[ap]\.?\s*m\.?)?)/i;
// "Recibiste una transferencia por $50,000.00 de JOSE PEREZ en tu cuenta **0000, el 30/09/2026 a las 18:16"
const AMOUNT_FIRST = /recibiste (?:una transferencia|un pago|una consignaci[óo]n) por (\$?\s*[\d.,]+) de (.+?) en (?:tu )?cuenta (\*+\s?\d+)(?: conectada a la llave (\S+?))?,? el (\d{1,2}\/\d{1,2}\/\d{2,4}) a las (\d{1,2}:\d{2}(?:\s*[ap]\.?\s*m\.?)?)/i;

export const bancolombia = {
  id: "bancolombia",
  name: "Bancolombia",
  dkimDomains: ["notificacionesbancolombia.com", "bancolombia.com.co", "bancolombia.com"],
  matches: (text) => FROM_FIRST.test(text) || AMOUNT_FIRST.test(text),
  parse(text) {
    let payer, amount, account, key, date, time;
    let m = FROM_FIRST.exec(text);
    if (m) [, payer, amount, account, key, date, time] = m;
    else if ((m = AMOUNT_FIRST.exec(text))) [, amount, payer, account, key, date, time] = m;
    else return null;
    const amountCents = parseAmountCents(amount);
    if (amountCents == null) return null;
    return {
      approved: true,
      amountCents,
      payerName: payer.trim(),
      payerBank: null,
      reference: null,
      transactionId: null,
      method: key ? "breb" : "transfer",
      methodText: key ? `llave ${key.replace(/[.,]$/, "")}` : null,
      accountHint: account.replace(/\s/g, ""),
      paidAt: parseNumericDate(date, time),
    };
  },
};
