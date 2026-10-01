# pagoradar

Lee los **avisos de pago que te mandan los bancos por correo** (Nequi Negocios, Nequi,
Bancolombia), comprueba que sean **auténticos** y le avisa a tus apps con un **webhook
firmado**: "entró un pago de $25.000 de Ana María Pérez por Bre-B a las 10:22".

Sirve para cualquier proyecto: una rifa, una tienda, un sistema de reservas. Cada app es una
**fuente** con su dirección de recepción, sus webhooks y su API key. La app nunca toca tu correo.

```
Banco ──correo──▶ tu Gmail ──filtro de reenvío──▶ pagos-xxxx@pagos.tudominio.com
                                                         │  Cloudflare Email Routing
                                                         ▼
                                              Worker "pagoradar-email"  (no lee ni guarda nada)
                                                         │  POST /ingest, firmado
                                                         ▼
                                     pagoradar (Dokploy): DKIM ✔ · dueño ✔ · lee el aviso
                                                         │  webhook firmado (con reintentos)
                                                         ▼
                                                 tus apps (Ibirifas, …)
```

## ¿Por qué no se puede engañar con un correo falso?

Cada aviso pasa por tres filtros antes de contar como pago:

1. **Firma DKIM del banco.** El correo debe venir firmado por el dominio del banco
   (`nequi.com.co`, `notificacionesbancolombia.com`…) y el remitente debe ser de ese mismo dominio.
   La firma tiene que cubrir **todo** el cuerpo (se rechaza `l=`) y la cabecera `To`. Si alguien
   escribe "Recibiste $1.000.000" desde otro lado, o cambia una cifra de un aviso real, la firma
   no cuadra y se rechaza. El reenvío de Gmail conserva la firma original, por eso funciona.
2. **Que sea para ti.** El `To` firmado debe ser uno de tus correos (`ownerEmails`). Así, un aviso
   **real** de la cuenta de otra persona (por ejemplo, alguien que reenvía el suyo) no cuenta.
3. **Que se entienda.** Un lector por banco saca monto, pagador, banco de origen, referencia y
   fecha. Las ventas que no están "Aprobada" no cuentan.

Además: cada aviso se registra una sola vez (por número de transacción o Message-ID), aunque llegue
dos veces.

**Qué se guarda:** solo los datos del pago (monto, nombre del pagador, banco, referencia, fecha).
El correo completo **no** se guarda. Los correos rechazados quedan 7 días (remitente, asunto y
motivo; el texto solo si era un aviso real del banco con un formato que no entendimos, para poder
arreglar el lector). Los pagos se borran a los `RETENTION_DAYS` días (180 por defecto).

## Bancos soportados

| `bank`           | Correo                                   | Lo que se lee |
|------------------|------------------------------------------|---------------|
| `nequi_negocios` | "Detalle de tu venta por Bre-B"          | monto, estado, fecha, pagador, banco, referencia, número de transacción, método (QR/llave) |
| `nequi`          | "¡Recibiste plata por Bre-B!"            | monto, pagador, banco de origen, fecha |
| `bancolombia`    | "Alertas y Notificaciones" (transferencia recibida) | monto, pagador, cuenta (`*1234`), llave, fecha |

Montos en cualquier formato (`$ 100`, `100.000`, `$4,000.00`); fechas en hora de Colombia.
¿Otro banco o un formato nuevo? Ver "Agregar un banco".

## 1. Desplegar en Dokploy

1. Dokploy → *Create Service* → **Docker Compose** → este repositorio (rama `main`).
2. *Environment* (ver `.env.example`):

   | Variable | Qué es |
   |---|---|
   | `INGEST_SECRET` | Secreto compartido con el Worker. `openssl rand -hex 32` |
   | `ADMIN_TOKEN` | Para ver correos rechazados y entregas. `openssl rand -hex 24` |
   | `PAGORADAR_SOURCES` | Las fuentes, JSON en una línea (abajo) |
   | `RETENTION_DAYS` | Días que se guardan los pagos (180) |

3. *Domains*: `pagoradar.tudominio.com` → servicio `pagoradar`, puerto **3000**, HTTPS.
4. Deploy. Comprobar: `https://pagoradar.tudominio.com/health` → `{"ok":true}`.
5. (Recomendado) Respaldo del volumen `pagoradar-data` como el de las otras apps, y un monitor
   en UptimeRobot a `/health`.

### Fuentes (`PAGORADAR_SOURCES`)

```json
[{
  "id": "ibirifas",
  "addresses": ["pagos-ibirifas-k3x9@pagos.edwsystem.com"],
  "ownerEmails": ["tu-correo@gmail.com"],
  "banks": ["nequi_negocios", "nequi", "bancolombia"],
  "apiKey": "<openssl rand -hex 24>",
  "webhooks": [{ "url": "https://rifas.edwsystem.com/api/pagoradar/webhook", "secret": "<openssl rand -hex 24>" }]
}]
```

- `addresses`: a dónde reenviará Gmail. Pon algo difícil de adivinar (`pagos-ibirifas-k3x9`).
- `ownerEmails`: el/los correos donde **el banco** te escribe (el de Nequi Negocios puede ser
  distinto al personal: pon los dos).
- `banks`: opcional; por defecto todos.
- Varias apps = varias fuentes, cada una con su dirección. Una fuente puede tener varios webhooks.

## 2. Cloudflare: recibir correo y pasarlo al Worker

> Se usa un **subdominio** (`pagos.edwsystem.com`) para no tocar el correo del dominio principal.

1. **Worker**: Cloudflare → *Workers & Pages* → *Create* → *Hello World* → nombre
   `pagoradar-email` → *Edit code*: pega `worker/src/index.js` → *Deploy*.
   - *Settings → Variables and Secrets*: `PAGORADAR_URL` = `https://pagoradar.tudominio.com`
     (texto) e `INGEST_SECRET` = el mismo de Dokploy (**Secret**).
   - Opcional `FALLBACK_FORWARD`: un correo verificado que recibe el aviso si pagoradar está caído.
   - (O desde la carpeta `worker/`: `npx wrangler deploy` y `npx wrangler secret put INGEST_SECRET`.)
2. **Email Routing**: en la zona `edwsystem.com` → *Email* → *Email Routing* → *Settings* →
   **Subdomains → Add subdomain** `pagos` (crea los MX y SPF solo para `pagos.edwsystem.com`).
3. *Routing rules* → *Custom address* `pagos-ibirifas-k3x9@pagos.edwsystem.com` → acción
   **Send to a Worker** → `pagoradar-email`. Una regla por dirección de cada fuente.

## 3. Gmail: reenviar solo los avisos del banco

1. Gmail → ⚙️ *Ver toda la configuración* → **Reenvío y correo POP/IMAP** → *Agregar una
   dirección de reenvío* → `pagos-ibirifas-k3x9@pagos.edwsystem.com`.
2. Gmail manda un **código de confirmación** a esa dirección. pagoradar lo atrapa: aparece en los
   logs de Dokploy (`Gmail pide confirmar el reenvío … Código: 123456789`) y en
   `GET /admin/inbox`. Escríbelo en Gmail. **No actives el reenvío de todo el correo.**
3. Crea un **filtro** (buscador → opciones):
   - *De*: `notificaciones@nequi.com.co OR alertasynotificaciones@an.notificacionesbancolombia.com`
   - *Crear filtro* → **Reenviarlo a** `pagos-ibirifas-k3x9@…`.
4. Repite en cada Gmail que reciba avisos (el de Nequi Negocios, el personal…).

El filtro solo aplica a correos **nuevos**. Para probar, pide un pago pequeño (o reenvía a mano un
aviso reciente: también vale, porque la firma del banco se conserva).

## 4. Comprobar

```bash
# ¿Este aviso lo aceptaría pagoradar? (en tu computador; no guarda nada)
npm install && npm run check-email -- aviso.eml tu-correo@gmail.com

# Enviar un evento de prueba a los webhooks de la fuente
curl -X POST -H "Authorization: Bearer <apiKey>" https://pagoradar.tudominio.com/v1/webhooks/test

# Correos rechazados (y por qué) y estado de las entregas
curl -H "Authorization: Bearer <ADMIN_TOKEN>" https://pagoradar.tudominio.com/admin/inbox
curl -H "Authorization: Bearer <ADMIN_TOKEN>" "https://pagoradar.tudominio.com/admin/deliveries?status=failed"
curl -X POST -H "Authorization: Bearer <ADMIN_TOKEN>" https://pagoradar.tudominio.com/admin/deliveries/<id>/retry
```

Motivos de rechazo: `dkim_failed` (sin firma válida), `weak_signature` (firma del banco que no
cubre `To` o todo el cuerpo), `not_a_bank`, `not_owner` (aviso de otra cuenta), `unrecognized`
(formato nuevo: mira el texto en `/admin/inbox`), `not_approved`, `unknown_address`,
`ambiguous_headers`, `gmail_forwarding_confirmation`.

## Para tus apps

### Webhook

`POST` a cada URL de la fuente, `Content-Type: application/json`:

```json
{
  "id": "evt_mg7x2k1a9f3c…",
  "type": "payment.received",
  "createdAt": "2026-10-01T15:22:55.120Z",
  "source": "ibirifas",
  "data": {
    "id": "pay_mg7x2k1a9f3c…",
    "source": "ibirifas",
    "bank": "nequi_negocios",
    "method": "breb_qr",
    "methodText": "QR Negocios Bre-B",
    "amount": 25000,
    "amountCents": 2500000,
    "currency": "COP",
    "payerName": "Ana Maria Perez Lopez",
    "payerNameNormalized": "ANA MARIA PEREZ LOPEZ",
    "payerBank": "Banco Uno",
    "reference": "M00000001",
    "transactionId": "a1b2c3…",
    "accountHint": null,
    "paidAt": "2026-10-01T15:22:53.000Z",
    "receivedAt": "2026-10-01T15:22:55.118Z"
  }
}
```

- `type`: `payment.received`, o `payment.test` para la prueba (no lo tomes como pago real).
- `method`: `breb_qr`, `breb`, `transfer` u `other`. `accountHint`: la cuenta que recibió (`*0000`)
  cuando el banco la dice.
- Cabeceras: `Pagoradar-Event-Id` (el mismo `id`; úsalo para no procesar dos veces) y
  `Pagoradar-Signature: t=<unix>,v1=<hex>`, donde `v1 = HMAC-SHA256(secret, "<t>.<cuerpo>")`.
- Responde **2xx** para confirmar. Si no, se reintenta a los 30 s, 2 min, 10 min, 30 min, 1 h,
  3 h, 6 h, 12 h y 24 h.

Verificar la firma (Node):

```js
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyPagoradar(secret, header, rawBody, toleranceSec = 300) {
  const parts = Object.fromEntries(String(header).split(",").map((p) => p.trim().split("=", 2)));
  const t = Number(parts.t);
  if (!t || !parts.v1 || Math.abs(Date.now() / 1000 - t) > toleranceSec) return false;
  const expected = Buffer.from(createHmac("sha256", secret).update(`${t}.${rawBody}`).digest("hex"));
  const given = Buffer.from(parts.v1);
  return expected.length === given.length && timingSafeEqual(expected, given);
}
```

Usa el **cuerpo crudo** (antes de `JSON.parse`).

### API de respaldo

Por si un webhook se perdió: `GET /v1/payments?since=<ISO>&limit=100` con
`Authorization: Bearer <apiKey>` → `{ "payments": [...], "next": "<receivedAt del último>" }`,
en orden de llegada. Pide de nuevo con `since=next` hasta que venga vacío.

## Agregar un banco

1. Consigue un aviso real (`.eml`: en Gmail, ⋮ → *Descargar mensaje*).
2. Crea `src/parsers/<banco>.js` con `id`, `name`, `dkimDomains` (los dominios que firman),
   `matches(text)` y `parse(text)` (mira `nequi.js`). Agrégalo en `src/parsers/index.js`.
3. Prueba con `npm run check-email -- aviso.eml tu@correo` y agrega una prueba en
   `test/parsers.test.js` con datos **inventados** (nunca subas avisos reales al repo:
   `*.eml` está en `.gitignore`).

## Desarrollo

```bash
npm install
npm test        # lectores, DKIM con llaves de prueba, servidor + webhooks + Worker de punta a punta
INGEST_SECRET=$(openssl rand -hex 32) PAGORADAR_SOURCES='[]' npm start
```

Node 22 (usa `node:sqlite`, sin dependencias nativas). Dependencias: `mailauth` (DKIM) y
`postal-mime` (leer el correo).

## Si cambias de dominio

- **La dirección que recibe** (`pagos-…@pagos.edwsystem.com`) puede quedarse igual aunque tus apps
  cambien de dominio: nadie la ve y así no hay que tocar los filtros de Gmail.
- Si cambias **el dominio de pagoradar**: Dokploy → *Domains*, y en el Worker la variable
  `PAGORADAR_URL`.
- Si cambias **el dominio de una app**: actualiza la `url` de su webhook en `PAGORADAR_SOURCES`
  y redespliega.
- Si cambias **la dirección de recepción**: Email Routing (subdominio + regla hacia el Worker) en
  el dominio nuevo, `addresses` de la fuente, y en cada Gmail una dirección de reenvío nueva
  (con su código) y el filtro editado.
