# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

pagoradar reads bank payment-notice emails (Nequi Negocios, Nequi, Bancolombia) forwarded from Gmail, verifies them (DKIM), and notifies client apps with signed webhooks. It also works as a payment gateway: apps create **charges** (`/v1/charges`) and customers pay on a public checkout page. Everything is configured in a server-rendered admin panel; the README (in Spanish) is the user-facing spec.

## Commands

```bash
npm install
npm test                                              # all tests (node:test), test/**/*.test.js
node --disable-warning=ExperimentalWarning --test test/charges.test.js        # one file
node --disable-warning=ExperimentalWarning --test --test-name-pattern="cobro" test/charges.test.js  # one test
INGEST_SECRET=$(openssl rand -hex 32) MASTER_KEY=$(openssl rand -hex 32) INBOUND_DOMAIN=pagos.localhost npm start
# then open the /setup?token=… link printed in the console to create the first admin
npm run check-email -- aviso.eml owner@gmail.com     # would this .eml be accepted, and what's parsed (stores nothing)
```

No build step, no linter, no TypeScript (only `sdk/pagoradar.d.ts` for SDK consumers). CI (`.github/workflows/test.yml`) runs the tests, then builds and starts the Docker image; anything the image needs at runtime must also pass `.dockerignore`. Requires Node ≥ 22.5 (`node:sqlite`). Runtime deps are only `mailauth`, `postal-mime`, `qrcode` — keep it that way.

## Architecture

```
Bank → Gmail → forward filter → pagos-xxx@<inbound domain> → Cloudflare Email Routing (catch-all)
  → worker/src/index.js (forwards raw bytes, HMAC-signed with INGEST_SECRET or its Cloudflare account's secret) → POST /ingest
  → ingest.js → analyze.js (DKIM + owner + parser) → store → charges.matchPayment → webhooks queue
```

- **`src/server.js`** is the process entry: loads config, opens the store, prints the setup link when there are no admins, and runs a 15 s loop (`expireCharges` + `deliverDue` webhook retries) and hourly retention cleanup.
- **`src/app.js`** is a plain `(req, res)` router, no framework: `/health`, `/ingest`, then `handleApi` (`/v1/*`, Bearer API key), `handleCheckout` (`/c/<id>`), `handleDocs` (`/docs`, static `public/docs.html` with `{{BASE}}` substitution), and everything else falls through to `admin/routes.js`. Each handler returns truthy if it handled the request.
- **`src/analyze.js`** is the security core. A notice counts only if: a DKIM signature passes for the bank's domain, the From is in that domain (relaxed alignment), the signature covers the whole body (no `l=`) and the `To` header; the signed To is one of the account's `ownerEmails`; and a parser understands it and it's approved. Exactly one From/To header, or `ambiguous_headers`. It never throws; it returns `{ ok, reason }`. Rejection `reason` codes are user-visible (README, `REASON_LABEL` in admin/ui.js); keep them in sync. Gmail forwarding-confirmation emails (DKIM-signed by google.com) are a special path that records the code on the account.
- **`src/parsers/`**: one object per bank `{ id, name, dkimDomains, matches(text), parse(text) }`, registered in `parsers/index.js` (order matters, first match wins) plus its sender in `BANK_SENDERS`. Dedup is by `dedupeKey` (transaction id → Message-ID → amount/payer/time hash).
- **`src/store.js`**: a single SQLite DB through `node:sqlite` `DatabaseSync`, exposing namespaced repos (`store.apps`, `accounts`, `payments`, `charges`, `deliveries`, `inbox`, `admins`, `settings`…) that map snake_case rows to camelCase objects. Migrations are SQL strings `V1`, `V2`… applied by `PRAGMA user_version`. To change the schema, add a new `V<n>` and append it to the migration list; never edit earlier ones (production DBs exist). Webhook and TOTP secrets are encrypted with `MASTER_KEY`; API keys are stored only as hashes.
- **Domain model:** an **app** (a client project with webhook URL/secret and API keys) has many **accounts** (receiving bank accounts, each with a generated inbound address, `ownerEmails`, `banks`, and an optional `tenantRef` that is the app's own customer id). In the DB, the `source` column in payments, deliveries and inbox is the app id (a legacy name from v1).
- **Receiving domains** (`store.domains`): an account's address is stored in full, so ingest looks it up by address alone. A domain lives either in the operator's Cloudflare (`cf_account_id` null, served by the Worker that signs with `INGEST_SECRET`) or in a customer's (`store.cfAccounts`: one Worker and one encrypted secret per Cloudflare account, shared by all its domains). `ingestAuth` (ingest.js) accepts `INGEST_SECRET` for any address, and a Cloudflare account's secret only for addresses on that account's domains. A domain's optional app allow-list (`app_ids`, null = every app) applies only when an account is created (`chooseDomain` in api.js). The default domain is still the `inbound_domain` setting; `domains.list()` creates its row lazily.
- **People and access:** `admins.role` is `admin` (sees everything) or `client`, whose per-app access (`admin_apps`: `view` | `manage`) is turned into `s.scope` by `scopeFor` in admin/routes.js on every request. Every panel handler must check `s.scope.can(appId, level)` on the resource it touches and return `notFound` otherwise. List queries take `appIds` (undefined = all, an empty list matches nothing). `/settings`, `/domains`, `/audit` and creating apps are admin-only.
- **Passkeys** (`src/webauthn.js`, `store.passkeys`, routes under `/login/passkey` and `/me/passkeys`): WebAuthn with `node:crypto` only. Attestation is `none`, so there's no CBOR: the browser hands over the SPKI key via `getPublicKey()`. A sign-in replaces password + TOTP, so user verification is always required, and adding a passkey requires a current TOTP code. The rpId and origin come from `PUBLIC_URL` (`relyingParty` in admin/routes.js). One-time challenges live in memory, tied to the login form's cookie or to the person.
- **Silent accounts:** `accounts.silent` is computed when reading (`status` active, `last_email_at` older than `silent_after_hours`, 0 = never). `alertSilentAccounts` (webhooks.js) runs hourly from server.js and queues `account.silent` once per silence; `markActive` clears it. There's no outbound email: alerts are the panel and the webhook.
- **Invitations:** people are created with an unusable password and a one-use link (`/invite/<token>`, 7 days, only its hash is stored); they choose a password and then go through the normal TOTP setup. `must_change_password` only remains for people created before this.
- **`src/charges.js`**: charges are created by the API and by the panel (`/charges/new`), both through `createCharge`. Each open charge on an account gets a unique amount (base ± 1..999 pesos, `uniqueAmount` up/down/off). `matchPayment` pays an exact match, or an "approximate" match when exactly one open charge asked for the round amount. Otherwise it never guesses and leaves the charge for manual association. Expired charges keep their amount reserved for `LATE_GRACE_MS`.
- **`src/webhooks.js`**: events are queued in `deliveries` and sent by `deliverDue`, using the app's *current* URL and secret, with a Stripe-style `Pagoradar-Signature: t=…,v1=HMAC(secret, "t.body")` header and a fixed retry schedule (`RETRY_DELAYS_MS`). The SDK (`sdk/pagoradar.js`, zero deps, single file) duplicates the verification logic for consumers. Keep both, plus the README and `public/docs.html`, in sync when changing event shapes or the API.
- **Admin panel** (`src/admin/`): server-rendered HTML. `ui.js`'s `html` tagged template auto-escapes every interpolation unless it's `html`/`raw()` output, so use it for all markup. Auth is scrypt password + mandatory TOTP (or a passkey), session cookie, a CSRF token on every form, and an origin check. Static assets in `public/` are served with a content-hash `?v=` for cache busting. `public/sw.js` is a PWA service worker that caches only CSS and icons.
- **`src/importLegacy.js`** + `config.validateSources`: a one-time import of the old `PAGORADAR_SOURCES` JSON config into apps/accounts at startup.
- **`worker/`** is a separate Cloudflare Email Worker (`wrangler.toml`). It must pass the raw bytes untouched so DKIM still verifies. Tests import its `deliver` function directly.

## Testing conventions

- Tests use `node:test` + `node:assert/strict`, with an in-memory store (`openStore(":memory:", { masterKey })`) and a real HTTP server on port 0 (see `test/server.test.js`).
- `test/fixtures.js` builds synthetic bank emails and DKIM-signs them with a throwaway RSA key; pass `resolverFor()` as `resolver` so DKIM lookups hit that key instead of DNS. Use **made-up data only**; never commit real notices (`*.eml` is gitignored).
- To add a bank: create the parser, register it, check it against a real `.eml` with `npm run check-email`, and add a synthetic case to `test/parsers.test.js`.

## Conventions

- User-facing strings (panel, API error messages, logs, README, docs) are in **Spanish** (Colombian). Code identifiers and code comments are in English.
- Amounts are stored as integer cents (`amountCents`); the API takes and returns whole pesos too. Dates parsed from notices are in Colombia time (`src/dates.js`).
- Plain ESM JavaScript with JSDoc-style comments that explain *why*; match the existing compact style.
- Deployment is Docker Compose on Dokploy. The data volume is pinned to the name `pagoradar-data` (`/app/data/pagoradar.db`); don't rename it.
