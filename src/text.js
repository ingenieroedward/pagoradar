// Turning a bank email into plain, searchable text, and normalizing names for comparison.

const NAMED = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", iexcl: "¡", iquest: "¿", ntilde: "ñ", Ntilde: "Ñ",
  aacute: "á", eacute: "é", iacute: "í", oacute: "ó", uacute: "ú", Aacute: "Á", Eacute: "É", Iacute: "Í", Oacute: "Ó",
  Uacute: "Ú", uuml: "ü", Uuml: "Ü", deg: "°", bull: "•", middot: "·", ndash: "–", mdash: "—", laquo: "«", raquo: "»" };

export function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === "#") {
      const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : m;
    }
    return NAMED[e] ?? m;
  });
}

/** Visible text of an HTML email, on one line with single spaces. */
export function htmlToText(html) {
  return squash(
    decodeEntities(
      html
        .replace(/<(style|script|head|title)[\s\S]*?<\/\1>/gi, " ")
        .replace(/<!--[\s\S]*?-->/g, " ")
        .replace(/<br\s*\/?>|<\/(p|div|tr|td|th|li|h\d|table)>/gi, " \n ")
        .replace(/<[^>]+>/g, " "),
    ),
  );
}

export function squash(s) {
  return s.replace(/[\s ​‌‍﻿]+/g, " ").trim();
}

/** The text to parse: the plain part when there is a useful one, otherwise the HTML made text. */
export function emailText({ text, html }) {
  const plain = text ? squash(text) : "";
  const fromHtml = html ? htmlToText(html) : "";
  return fromHtml.length > plain.length ? fromHtml : plain || fromHtml;
}

/** "José  Díaz-Pérez " -> "JOSE DIAZ PEREZ": for matching a payer typed by hand against the bank's version. */
export function normalizeName(name) {
  return squash(
    name
      .normalize("NFD")
      .replace(/[̀-ͯ]/g, "")
      .replace(/[^A-Za-z0-9ñÑ ]+/g, " ")
      .toUpperCase(),
  );
}

/** "Ana Maria Perez" from "ANA MARIA PEREZ" — names in banks come in capitals. */
export function titleCase(name) {
  return squash(name)
    .toLowerCase()
    .replace(/(^|[\s-])(\p{L})/gu, (_, sep, ch) => sep + ch.toUpperCase());
}
