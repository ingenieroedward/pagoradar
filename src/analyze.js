import { createHash } from "node:crypto";
import { authenticate } from "mailauth";
import PostalMime from "postal-mime";
import { emailText, normalizeName, titleCase } from "./text.js";
import { BANK_IDS, domainIn, parsersFor } from "./parsers/index.js";

const addr = (s) => String(s || "").trim().toLowerCase();

/**
 * Reads one raw email and decides whether it is a genuine payment notice for this source:
 *
 *  1. A DKIM signature must PASS for a bank's own domain, with the From header in that bank's domain too, covering
 *     the whole body (no `l=`) and the To header. Without this anyone could write "Recibiste $1.000.000".
 *  2. The signed To must be one of the source's `ownerEmails`: a real notice of somebody else's
 *     account, forwarded here, is refused (it is genuine, but not a payment to you).
 *  3. A parser for that bank must understand the text.
 *
 * Returns { ok: true, payment } or { ok: false, reason, ... } — never throws on bad input.
 */
export async function analyzeEmail(raw, { ownerEmails = [], banks = BANK_IDS, resolver, now } = {}) {
  let mail;
  try {
    mail = await PostalMime.parse(raw);
  } catch {
    return { ok: false, reason: "unreadable" };
  }
  const from = addr(mail.from?.address);
  const subject = mail.subject ?? "";
  const text = emailText(mail);
  const base = { from, subject, text, messageId: mail.messageId ?? null };

  if (from === "forwarding-noreply@google.com") {
    const code = text.match(/(?:c[óo]digo de confirmaci[óo]n|confirmation code)\s*:?\s*(\d{6,12})/i)?.[1] ?? null;
    return { ok: false, reason: "gmail_forwarding_confirmation", code, ...base };
  }

  // Exactly one From and one To: with duplicates, what DKIM signed and what a reader sees can differ.
  const headerCount = (name) => mail.headers.filter((h) => h.key === name).length;
  if (headerCount("from") !== 1 || headerCount("to") > 1) return { ok: false, reason: "ambiguous_headers", ...base };

  let auth;
  try {
    auth = await authenticate(raw, {
      trustReceived: false,
      disableArc: true,
      disableDmarc: true,
      disableBimi: true,
      ...(resolver ? { resolver } : {}),
      ...(now ? { curTime: now } : {}),
    });
  } catch {
    return { ok: false, reason: "dkim_error", ...base };
  }
  const fromDomain = from.split("@")[1] ?? "";
  const good = auth.dkim.results.filter(
    (r) =>
      r.status?.result === "pass" &&
      !r.canonBodyLengthLimited &&
      /(^|:\s*)to(:|$)/i.test(String(r.signingHeaders?.keys ?? "").replace(/\s/g, "")),
  );
  const signingDomains = good.map((r) => r.signingDomain.toLowerCase());
  // Relaxed alignment: signer and From both belong to the bank (notificaciones.nequi.com.co signs for nequi.com.co).
  const candidates = parsersFor(signingDomains, banks).filter((p) => domainIn(fromDomain, p.dkimDomains));
  if (candidates.length === 0) {
    const passed = auth.dkim.results.filter((r) => r.status?.result === "pass");
    // A bank signature that doesn't cover To or the whole body is not enough.
    const weak = passed.some((r) => parsersFor([r.signingDomain], banks).some((p) => domainIn(fromDomain, p.dkimDomains)));
    return { ok: false, reason: weak ? "weak_signature" : passed.length ? "not_a_bank" : "dkim_failed", signingDomains, ...base };
  }

  const to = (mail.to ?? []).map((t) => addr(t.address));
  const owners = ownerEmails.map(addr);
  if (owners.length > 0 && !to.some((t) => owners.includes(t))) {
    return { ok: false, reason: "not_owner", ...base };
  }

  const parser = candidates.find((p) => p.matches(text));
  const parsed = parser?.parse(text);
  if (!parser || !parsed) return { ok: false, reason: "unrecognized", bank: candidates[0].id, ...base };
  if (!parsed.approved) return { ok: false, reason: "not_approved", bank: parser.id, ...base };

  const paidAt = parsed.paidAt ?? (mail.date ? new Date(mail.date).toISOString() : new Date().toISOString());
  const payerName = titleCase(parsed.payerName);
  const fingerprint = parsed.transactionId
    ? `tx:${parsed.transactionId}`
    : mail.messageId
      ? `msg:${mail.messageId}`
      : `sum:${parsed.amountCents}|${normalizeName(payerName)}|${paidAt}`;
  return {
    ok: true,
    ...base,
    payment: {
      bank: parser.id,
      bankName: parser.name,
      method: parsed.method,
      methodText: parsed.methodText,
      amountCents: parsed.amountCents,
      currency: "COP",
      payerName,
      payerNameNormalized: normalizeName(payerName),
      payerBank: parsed.payerBank,
      reference: parsed.reference,
      transactionId: parsed.transactionId,
      accountHint: parsed.accountHint,
      paidAt,
      dkimDomain: signingDomains.find((d) => domainIn(d, parser.dkimDomains)),
      dedupeKey: createHash("sha256").update(`${parser.id}|${fingerprint}`).digest("hex").slice(0, 32),
    },
  };
}
