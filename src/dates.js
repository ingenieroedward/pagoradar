// Dates in bank emails are Colombian local time (UTC-5, no daylight saving).
const BOGOTA_OFFSET = "-05:00";

const MONTHS = { enero: 1, febrero: 2, marzo: 3, abril: 4, mayo: 5, junio: 6, julio: 7, agosto: 8, septiembre: 9, setiembre: 9, octubre: 10, noviembre: 11, diciembre: 12 };

const pad = (n) => String(n).padStart(2, "0");

/** An ISO instant from Colombian wall-clock parts, or null if they are not a real date. */
export function bogotaToIso(year, month, day, hour = 0, minute = 0, second = 0) {
  if (year < 100) year += 2000;
  const iso = `${year}-${pad(month)}-${pad(day)}T${pad(hour)}:${pad(minute)}:${pad(second)}${BOGOTA_OFFSET}`;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  // Reject rollovers like 31/02.
  const back = new Date(d.getTime() - 5 * 3600 * 1000);
  if (back.getUTCDate() !== day || back.getUTCMonth() + 1 !== month) return null;
  return d.toISOString();
}

/** "01/10/2026 10:22:53", "30/09/26 a las 18:16", "30/09/2026 6:16 p.m." */
export function parseNumericDate(dateText, timeText = "") {
  const d = dateText.match(/(\d{1,2})\/(\d{1,2})\/(\d{2,4})/);
  if (!d) return null;
  const t = parseTime(timeText || dateText);
  return bogotaToIso(Number(d[3]), Number(d[2]), Number(d[1]), t?.h ?? 0, t?.m ?? 0, t?.s ?? 0);
}

/** "16 de septiembre de 2026 a las 7:09 p.m" */
export function parseLongDate(text) {
  const d = text.match(/(\d{1,2}) de ([a-záéíóú]+) (?:de|del) (\d{4})/i);
  if (!d) return null;
  const month = MONTHS[d[2].toLowerCase()];
  if (!month) return null;
  const t = parseTime(text.slice(d.index + d[0].length));
  return bogotaToIso(Number(d[3]), month, Number(d[1]), t?.h ?? 0, t?.m ?? 0, t?.s ?? 0);
}

/** "18:16", "10:22:53", "7:09 p.m", "7:09 a. m." */
export function parseTime(text) {
  const m = text.match(/(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(a\.?\s*m\.?|p\.?\s*m\.?)?/i);
  if (!m) return null;
  let h = Number(m[1]);
  const ampm = m[4]?.toLowerCase().replace(/[\s.]/g, "");
  if (ampm === "pm" && h < 12) h += 12;
  if (ampm === "am" && h === 12) h = 0;
  if (h > 23 || Number(m[2]) > 59) return null;
  return { h, m: Number(m[2]), s: m[3] ? Number(m[3]) : 0 };
}
