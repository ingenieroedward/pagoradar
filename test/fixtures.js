// Synthetic bank emails (made-up people and numbers) signed with a test DKIM key, plus a DNS resolver
// that knows that key. They follow the structure of the real notices, without any real data.
import { generateKeyPairSync } from "node:crypto";
import { dkimSign } from "mailauth";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PRIVATE_PEM = privateKey.export({ type: "pkcs8", format: "pem" });
const PUBLIC_B64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");

export const OWNER = "dueno.prueba@gmail.com";
export const SELECTOR = "test";

/** DNS for the tests: our key at test._domainkey.<any domain in `domains`>. */
export function resolverFor(domains = ["notificaciones.nequi.com.co", "an.notificacionesbancolombia.com", "evil.example", "google.com"]) {
  return async (name, type) => {
    const n = name.toLowerCase();
    if (type === "TXT" && domains.some((d) => n === `${SELECTOR}._domainkey.${d}`)) return [[`v=DKIM1; k=rsa; p=${PUBLIC_B64}`]];
    const err = new Error(`queryTxt ENOTFOUND ${name}`);
    err.code = "ENOTFOUND";
    throw err;
  };
}

export function buildEmail({ from, to = OWNER, subject, html, text, date = "Thu, 01 Oct 2026 15:22:54 +0000", messageId = `<${Math.random().toString(36).slice(2)}@test>`, extraHeaders = "" }) {
  const boundary = "b1_test";
  const parts = [];
  if (text) parts.push(`--${boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${text}\r\n`);
  if (html) parts.push(`--${boundary}\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${html}\r\n`);
  return (
    `From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\nDate: ${date}\r\nMessage-ID: ${messageId}\r\nMIME-Version: 1.0\r\n${extraHeaders}` +
    `Content-Type: multipart/alternative; boundary="${boundary}"\r\n\r\n${parts.join("")}--${boundary}--\r\n`
  );
}

export async function sign(message, domain, { headerList = "From:To:Subject:Date:Message-ID:MIME-Version:Content-Type", bodyLength } = {}) {
  const res = await dkimSign(message, {
    canonicalization: "relaxed/relaxed",
    headerList,
    signatureData: [{ signingDomain: domain, selector: SELECTOR, privateKey: PRIVATE_PEM, ...(bodyLength !== undefined ? { maxBodyLength: bodyLength } : {}) }],
  });
  if (res.errors?.length) throw res.errors[0];
  return Buffer.from(res.signatures + message);
}

export const nequiNegociosHtml = ({ amount = "$ 25.000", payer = "ANA MARIA PRUEBA LOPEZ", status = "Aprobada", tx = "abc123def456" } = {}) => `<!DOCTYPE html><html><head><style>.x{color:red}</style></head><body>
<table><tr><td><img alt="NEQUI"></td></tr>
<tr><td><h1>Venta exitosa por ${amount}</h1></td></tr>
<tr><td>Detalle de la venta</td></tr>
<tr><td><b>Monto:</b></td><td>${amount}</td></tr>
<tr><td><b>Estado:</b></td><td>${status}</td></tr>
<tr><td><b>Fecha:</b></td><td>01/10/2026 10:22:53</td></tr>
<tr><td><b>Pagador:</b></td><td>${payer}</td></tr>
<tr><td><b>Banco:</b></td><td>Banco de Pruebas</td></tr>
<tr><td><b>Referencia:</b></td><td>M00000001</td></tr>
<tr><td><b>N&uacute;mero de transacci&oacute;n:</b></td><td>${tx}</td></tr>
<tr><td><b>M&eacute;todo de pago:</b></td><td>QR Negocios Bre-B</td></tr>
<tr><td>Si tienes dudas escr&iacute;benos al chat dentro de la app Nequi Negocios.</td></tr>
<tr><td>Este es un correo autom&aacute;tico, por favor no lo respondas.</td></tr></table></body></html>`;

export const nequiPersonalHtml = ({ amount = "100.000", payer = "Carlos Andres Prueba Ruiz" } = {}) => `<html><body><table>
<tr><td>&iexcl;Recibiste plata por Bre-B!</td></tr><tr><td>&iexcl;Hola, DUENO PRUEBA!</td></tr>
<tr><td>Recibiste ${amount} de ${payer} el 16 de septiembre de 2026 a las 7:09 p.m, desde el banco Banco Uno.</td></tr>
<tr><td>Revisa el detalle en los movimientos de tu app.</td></tr></table></body></html>`;

export const bancolombiaText = ({ amount = "$4,000.00", payer = "LUISA FERNANDA PRUEBA" } = {}) =>
  `¡Listo! Todo salió bien con tus movimientos\r\nBancolombia: dueno, recibiste una transferencia de ${payer} por ${amount} en tu cuenta *0000 conectada a la llave tienda@ejemplo.com el 30/09/26 a las 18:16. Con llaves es de una y gratis.\r\n`;

export const nequiNegociosEmail = (o = {}, h = {}) =>
  sign(buildEmail({ from: "notificaciones@nequi.com.co", subject: "Detalle de tu venta por Bre-B", html: nequiNegociosHtml(o), ...h }), "notificaciones.nequi.com.co");
export const nequiPersonalEmail = (o = {}, h = {}) =>
  sign(buildEmail({ from: "notificaciones@nequi.com.co", subject: "¡Recibiste plata por Bre-B!", html: nequiPersonalHtml(o), date: "Thu, 17 Sep 2026 00:09:58 +0000", ...h }), "notificaciones.nequi.com.co");
export const bancolombiaEmail = (o = {}, h = {}) =>
  sign(
    buildEmail({ from: "Alertas y Notificaciones <alertasynotificaciones@an.notificacionesbancolombia.com>", subject: "Alertas y Notificaciones", text: bancolombiaText(o), ...h }),
    "an.notificacionesbancolombia.com",
    { headerList: "From:Reply-To:Subject:To:MIME-Version:Content-Type" },
  );

/** Gmail's forwarding confirmation, signed by google.com (as the real one is). */
export const gmailConfirmationEmail = ({ subject = "(#123456789) Confirmación de reenvío de Gmail", text = "Código de confirmación: 123456789\r\nPara permitir...", html, to = "pagos-test@pagos.example.com" } = {}) =>
  sign(buildEmail({ from: "Equipo de Gmail <forwarding-noreply@google.com>", to, subject, text, html }), "google.com", { headerList: "From:To:Subject:Date:Message-ID" });
