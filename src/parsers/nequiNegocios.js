import { parseAmountCents } from "../amount.js";
import { parseNumericDate } from "../dates.js";
import { labeledFields } from "./fields.js";

const LABELS = ["Monto", "Estado", "Fecha", "Pagador", "Banco", "Referencia", "Número de transacción", "Método de pago"];
const STOP = ["Si tienes dudas", "Este es un correo"];

/** Nequi Negocios: "Detalle de tu venta por Bre-B" — a sale paid to the business (QR or llave). */
export const nequiNegocios = {
  id: "nequi_negocios",
  name: "Nequi Negocios",
  dkimDomains: ["nequi.com.co"],
  matches: (text) => /Venta exitosa|Detalle de la venta/i.test(text) && /Pagador\s*:/i.test(text),
  parse(text) {
    const f = labeledFields(text, LABELS, STOP);
    const amountCents = parseAmountCents(f["Monto"] ?? text.match(/Venta exitosa por\s*([$\d.,\s]+?)(?=\s+[A-Za-zÁ-ú])/i)?.[1]);
    if (amountCents == null || !f["Pagador"]) return null;
    const status = (f["Estado"] ?? "").toLowerCase();
    return {
      approved: status === "" || status.startsWith("aprobad"),
      amountCents,
      payerName: f["Pagador"],
      payerBank: f["Banco"] || null,
      reference: f["Referencia"] || null,
      transactionId: f["Número de transacción"] || null,
      method: /QR/i.test(f["Método de pago"] ?? "") ? "breb_qr" : /Bre-?B/i.test(f["Método de pago"] ?? text) ? "breb" : "other",
      methodText: f["Método de pago"] || null,
      accountHint: null,
      paidAt: f["Fecha"] ? parseNumericDate(f["Fecha"]) : null,
    };
  },
};
