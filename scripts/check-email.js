// Usage: npm run check-email -- path/to/aviso.eml [tu-correo@gmail.com]
// Tells you whether pagoradar would accept that email and what it would read from it. Nothing is stored.
import { readFileSync } from "node:fs";
import { analyzeEmail } from "../src/analyze.js";

const [file, owner] = process.argv.slice(2);
if (!file) {
  console.error("Uso: npm run check-email -- aviso.eml [tu-correo@gmail.com]");
  process.exit(2);
}
const r = await analyzeEmail(readFileSync(file), { ownerEmails: owner ? [owner] : [] });
delete r.text;
console.log(JSON.stringify(r, null, 2));
process.exit(r.ok ? 0 : 1);
