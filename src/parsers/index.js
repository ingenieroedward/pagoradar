import { nequiNegocios } from "./nequiNegocios.js";
import { nequi } from "./nequi.js";
import { bancolombia } from "./bancolombia.js";

/** Every bank email format pagoradar understands. Order matters: the first one that matches wins. */
export const PARSERS = [nequiNegocios, nequi, bancolombia];

export const BANK_IDS = PARSERS.map((p) => p.id);

/** Is `domain` the same as, or a subdomain of, one of `allowed`? */
export function domainIn(domain, allowed) {
  const d = String(domain || "").toLowerCase().replace(/\.$/, "");
  return allowed.some((a) => d === a || d.endsWith(`.${a}`));
}

/** The parsers whose bank could have signed a message from `signingDomains`. */
export function parsersFor(signingDomains, banks = BANK_IDS) {
  return PARSERS.filter((p) => banks.includes(p.id) && signingDomains.some((d) => domainIn(d, p.dkimDomains)));
}
