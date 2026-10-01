/**
 * "Monto: $ 100 Estado: Aprobada Fecha: …" -> { Monto: "$ 100", Estado: "Aprobada", … }.
 * Each value runs up to the next known label (or `stop`), so the order of the labels doesn't matter.
 */
export function labeledFields(text, labels, stop = []) {
  const hits = [];
  for (const label of labels) {
    const re = new RegExp(`${escape(label)}\\s*:`, "i");
    const m = re.exec(text);
    if (m) hits.push({ label, start: m.index, valueStart: m.index + m[0].length });
  }
  for (const s of stop) {
    const i = text.toLowerCase().indexOf(s.toLowerCase());
    if (i !== -1) hits.push({ label: null, start: i, valueStart: i });
  }
  hits.sort((a, b) => a.start - b.start);
  const out = {};
  hits.forEach((h, i) => {
    if (!h.label) return;
    const end = i + 1 < hits.length ? hits[i + 1].start : Math.min(text.length, h.valueStart + 200);
    out[h.label] = text.slice(h.valueStart, end).trim();
  });
  return out;
}

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/[úu]/gi, "[úu]").replace(/[óo]/gi, "[óo]").replace(/[ée]/gi, "[ée]");
