/**
 * Amounts as banks write them, to integer cents:
 *   "$ 100" · "100.000" · "$ 1.250.000,50" (Colombian) · "$4,000.00" (US style, Bancolombia).
 * A separator followed by exactly three digits groups thousands; one followed by one or two digits
 * at the end is the decimal mark. Returns null when the text is not an amount.
 */
export function parseAmountCents(raw) {
  if (raw == null) return null;
  const s = String(raw).replace(/COP|\$|\s| /gi, "");
  if (!/^\d[\d.,]*$/.test(s)) return null;
  const lastSep = Math.max(s.lastIndexOf("."), s.lastIndexOf(","));
  let intPart = s;
  let decPart = "";
  if (lastSep !== -1) {
    const tail = s.slice(lastSep + 1);
    if (tail.length === 1 || tail.length === 2) {
      intPart = s.slice(0, lastSep);
      decPart = tail;
    }
  }
  // What is left must be plain digits or groups of three after one separator kind.
  if (!/^\d+$/.test(intPart)) {
    if (!/^\d{1,3}([.,]\d{3})+$/.test(intPart)) return null;
    const seps = new Set(intPart.replace(/\d/g, ""));
    if (seps.size !== 1) return null;
    if (decPart && seps.has(s[lastSep])) return null; // "1.000.50" is not an amount
    intPart = intPart.replace(/[.,]/g, "");
  }
  const cents = Number(intPart) * 100 + (decPart ? Number(decPart.padEnd(2, "0")) : 0);
  return Number.isSafeInteger(cents) ? cents : null;
}
