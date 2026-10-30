/**
 * Payment QR codes follow EMVCo: a text of tag + 2-digit length + value, ending with a CRC (tag 63). Bre-B's are
 * expected to be like that, but which bank apps honor an amount we add is unknown: that's why it's opt-in per account
 * and the page always keeps the Bre-B key next to it.
 */

/** [{ id, value }] or null when the text isn't well formed. */
export function parseTlv(text) {
  const tags = [];
  for (let i = 0; i < text.length; ) {
    const head = text.slice(i, i + 4);
    if (!/^\d{4}$/.test(head)) return null;
    const length = Number(head.slice(2));
    if (i + 4 + length > text.length) return null;
    tags.push({ id: head.slice(0, 2), value: text.slice(i + 4, i + 4 + length) });
    i += 4 + length;
  }
  return tags;
}

/** CRC-16/CCITT-FALSE, the one EMVCo uses. */
export function crc16(text) {
  let crc = 0xffff;
  for (const byte of Buffer.from(text, "utf8")) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc.toString(16).toUpperCase().padStart(4, "0");
}

/** Is this a whole EMVCo payment QR: starts with its format, ends with a CRC that adds up? */
export function isEmvQr(text) {
  if (typeof text !== "string" || text.length < 12) return false;
  const tags = parseTlv(text);
  if (!tags || tags[0]?.id !== "00" || tags.at(-1).id !== "63" || tags.at(-1).value.length !== 4) return false;
  return crc16(text.slice(0, -4)) === tags.at(-1).value.toUpperCase();
}

const tlv = ({ id, value }) => `${id}${String(value.length).padStart(2, "0")}${value}`;

/**
 * The same QR carrying this amount (tag 54). `format`: "plain" 101 or "decimal" 101.00. It's also marked as one-time
 * (tag 01 = 12), unless `oneTime` is false: some apps may refuse that mark on a key's QR, and that's what's being tried.
 */
export function withAmount(text, pesos, format = "plain", { oneTime = true } = {}) {
  const amount = format === "decimal" ? Number(pesos).toFixed(2) : String(Math.round(pesos));
  const tags = parseTlv(text).filter((t) => t.id !== "54" && t.id !== "63" && !(oneTime && t.id === "01"));
  const place = (tag) => {
    const at = tags.findIndex((t) => t.id > tag.id);
    tags.splice(at === -1 ? tags.length : at, 0, tag);
  };
  if (oneTime) place({ id: "01", value: "12" });
  place({ id: "54", value: amount });
  const body = `${tags.map(tlv).join("")}6304`;
  return body + crc16(body);
}
