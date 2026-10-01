# pagoradar

Lee los **avisos de pago que te mandan los bancos por correo** (Nequi Negocios, Nequi,
Bancolombia), comprueba que sean **auténticos** y le avisa a tus apps con un **webhook
firmado**: "entró un pago de $25.000 de Ana María Pérez por Bre-B a las 10:22".

Sirve para cualquier proyecto: una rifa, una tienda, un sistema de reservas. Todo se configura desde
un **panel web** (con contraseña y código de 2 pasos): cada proyecto es una **app** con su webhook y
sus API keys, y cada cuenta bancaria es una **cuenta receptora** con su propia dirección. Tus apps
nunca tocan tu correo.

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
2. *Environment* (ver `.env.example`). Solo lo que no puede vivir en la base de datos:

   | Variable | Qué es |
   |---|---|
   | `INGEST_SECRET` | Secreto compartido con el Worker. `openssl rand -hex 32` |
   | `MASTER_KEY` | Cifra en la base de datos los secretos de webhook y de 2 pasos. `openssl rand -hex 32`. **Guárdala.** |
   | `PUBLIC_URL` | `https://pagoradar.tudominio.com` (cookies seguras y enlaces) |
   | `INBOUND_DOMAIN` | Dominio de las direcciones de recepción, ej. `pagos.tudominio.com` (editable en Ajustes) |
   | `SETUP_TOKEN` | Opcional: token para crear el primer administrador |

3. *Domains*: `pagoradar.tudominio.com` → servicio `pagoradar`, puerto **3000**, HTTPS.
4. Deploy. En los logs aparece `No hay administrador. Créalo en: https://…/setup?token=…`: ábrelo,
   crea tu usuario (correo + contraseña) y configura el **código de 2 pasos** con Google
   Authenticator, Microsoft Authenticator, 1Password o similar.
5. Respaldo del volumen `pagoradar-data` (como las otras apps) y un monitor de UptimeRobot a `/health`.

### Datos y volumen

Todo (administradores, apps, cuentas, pagos) vive en `/app/data/pagoradar.db`, en el volumen Docker
llamado exactamente **`pagoradar-data`** (nombre fijo en `docker-compose.yml`, así redesplegar o
cambiar el nombre del proyecto en Dokploy no crea uno nuevo). Si al arrancar el log dice
`AVISO: base de datos nueva` y ya tenías datos, o el panel vuelve a pedir el primer administrador,
**no lo crees todavía**: tus datos están en otro volumen. Para recuperarlos, en la terminal del servidor:

```sh
# 1. Ver qué volumen tiene los datos (el que tenga pagoradar.db más grande / más antiguo)
for v in $(docker volume ls -q | grep -i pagoradar); do echo "== $v"; docker run --rm -v "$v":/d alpine ls -la /d; done
# 2. Detén pagoradar en Dokploy (Stop) y copia ese volumen al de nombre fijo
docker run --rm -v VOLUMEN_VIEJO:/from -v pagoradar-data:/to alpine sh -c 'rm -f /to/pagoradar.db*; cp -a /from/. /to/ && chown -R 1000:1000 /to'
# 3. Deploy de nuevo: el log ya no dice "No hay administrador"
```

(`chown 1000:1000`: pagoradar corre como el usuario `node` y necesita poder escribir en la carpeta.)

Si el servicio se creó como **Application** (no Docker Compose), el `docker-compose.yml` no aplica: agrega en
*Advanced → Volumes* un **Volume Mount** `pagoradar-data` → `/app/data`. Sin él, los datos viven dentro del
contenedor y se borran en cada despliegue.

Los volúmenes viejos se pueden borrar (`docker volume rm …`) cuando confirmes que todo está bien.

### Actualizar desde la primera versión (`PAGORADAR_SOURCES`)

Agrega `MASTER_KEY`, `PUBLIC_URL` e `INBOUND_DOMAIN` y redespliega **sin quitar**
`PAGORADAR_SOURCES`: al arrancar, cada fuente se importa a la base de datos como una **app** (mismo id,
misma URL y secreto de webhook, misma API key) con su **cuenta receptora** (misma dirección), y los
pagos guardados quedan unidos a ella. Tus apps no notan nada. Desde ahí todo se edita en el panel y
la variable se puede borrar (se ignora).

## El panel

| Sección | Para qué |
|---|---|
| **Inicio** | Lo recibido hoy y en 7 días, cuentas esperando, entregas fallidas, últimos pagos |
| **Apps** | Cada proyecto (Ibirifas, otro SaaS…): URL del webhook, secreto para verificar la firma (mostrar / cambiar), **evento de prueba**, **API keys** (se muestran una sola vez y se pueden revocar), sus cuentas y el historial de **entregas** con **Reintentar** |
| **Cuentas** | Cada cuenta bancaria que reenvía sus avisos: dirección generada sola, correos dueños, bancos, "id del cliente en tu app", **guía paso a paso** para el Gmail del dueño con el **código de confirmación de Gmail** en pantalla, estado (*Esperando primer aviso* → *Activa*), **probar un aviso (.eml)**, desactivar |
| **Pagos** | Buscar por app, cuenta, banco, pagador o referencia y fechas; descargar CSV |
| **Correos** | Lo que llegó y no contó como pago, con el motivo (7 días) |
| **Ajustes** | Dominio de recepción, días que se guardan los pagos, administradores, registro de cambios |

**Seguridad del panel:** contraseña (scrypt) + código de 2 pasos obligatorio para todos (un código no
sirve dos veces), bloqueo tras intentos fallidos, sesiones de 12 h en cookie `HttpOnly` +
`SameSite=Strict` (+ `Secure` con HTTPS), token CSRF en cada formulario, se rechazan envíos desde otros
sitios, cabeceras CSP / `X-Frame-Options`, y un **registro de cambios** de quién hizo qué. Los
secretos de webhook y de 2 pasos se guardan **cifrados** con `MASTER_KEY`; las API keys, solo su huella.
Otro administrador recibe una contraseña temporal y al entrar debe cambiarla y configurar sus 2 pasos.

## 2. Cloudflare: recibir correo y pasarlo al Worker

> Se usa un **subdominio** (`pagos.tudominio.com`) para no tocar el correo del dominio principal.

1. **Worker**: Cloudflare → *Workers & Pages* → *Create* → *Hello World* → nombre
   `pagoradar-email` → *Edit code*: pega `worker/src/index.js` → *Deploy*.
   - *Settings → Variables and Secrets*: `PAGORADAR_URL` = `https://pagoradar.tudominio.com`
     (texto) e `INGEST_SECRET` = el mismo de Dokploy (**Secret**).
   - Opcional `FALLBACK_FORWARD`: un correo verificado que recibe el aviso si pagoradar está caído.
2. **Email Routing** de tu dominio → *Settings* → **Subdomains → Add subdomain** `pagos`.
3. *Routing rules* → **Catch-all address** → acción **Send to a Worker** → `pagoradar-email`.
   Con el catch-all, cada cuenta nueva que crees en el panel funciona al instante, sin tocar
   Cloudflare. (Las reglas por dirección que ya tengas siguen sirviendo.)

## 3. Por cada cuenta receptora

En el panel: **Cuentas → Nueva cuenta** (app, nombre, el Gmail donde el banco avisa, bancos). La
página de la cuenta trae la guía con todo para copiar:

1. En ese Gmail: **Reenvío y correo POP/IMAP → Agregar una dirección de reenvío** con la dirección
   de la cuenta.
2. El **código de confirmación** de Gmail aparece solo en la página de la cuenta (se actualiza sola).
   Deja marcado "Inhabilitar reenvío".
3. Un **filtro** con los remitentes de los bancos elegidos (la página te da el texto) → **Reenviarlo a**
   la dirección.
4. Un pago pequeño de prueba: con el primer aviso válido la cuenta pasa a **Activa**.

¿Un aviso que no se entiende o se rechaza? Súbelo en **Probar un aviso (.eml)** de la cuenta (en
Gmail, ⋮ → *Descargar mensaje*) o mira el motivo en **Correos**. Motivos: `dkim_failed` (sin firma
válida), `weak_signature`, `not_a_bank`, `not_owner` (aviso de otra cuenta), `unrecognized` (formato
nuevo), `not_approved`, `unknown_address`, `account_disabled`, `ambiguous_headers`.

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
    "receivedAt": "2026-10-01T15:22:55.118Z",
    "accountId": "acc_k3m9x2p7q4wz",
    "account": { "id": "acc_k3m9x2p7q4wz", "name": "Nequi Negocios de Ana", "tenantRef": "org_42" }
  }
}
```

- `type`:
  - `payment.received`: un pago (en `data`; `data.account.tenantRef` dice de cuál de tus clientes es);
  - `payment.test`: el evento de prueba (no lo tomes como pago real);
  - `account.confirmation_code`: llegó el código de Gmail de una cuenta (`data.code`, `data.link`),
    para mostrárselo a tu cliente;
  - `account.activated`: llegó el primer aviso válido de una cuenta.
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

### Cuentas receptoras por API (para tus clientes)

Si tu app es un SaaS (por ejemplo, cada organizador de Ibirifas cobra con su propia cuenta), tu app
crea la cuenta receptora de cada cliente y le muestra las instrucciones; el cliente nunca entra a
pagoradar. Todas con `Authorization: Bearer <API key de la app>`:

| | |
|---|---|
| `POST /v1/accounts` | `{ "name": "Tienda de Ana", "ownerEmails": ["ana@gmail.com"], "banks": ["nequi_negocios"], "tenantRef": "org_42" }` → `201` con la cuenta |
| `GET /v1/accounts?tenantRef=org_42` | Las cuentas de la app (o de un cliente) |
| `GET /v1/accounts/<id>` | Una cuenta: `status` (`pending` → `active`, o `disabled`), `confirmationCode` / `confirmationLink` de Gmail, `lastPaymentAt`… |
| `PATCH /v1/accounts/<id>` | Cambiar `name`, `ownerEmails`, `banks`, `tenantRef` o `active` |
| `DELETE /v1/accounts/<id>` | La elimina; si ya tiene pagos, solo la desactiva |

La cuenta trae `address` y `setup` (`forwardTo` y `gmailFilterFrom`, el texto para el filtro de
Gmail): con eso tu app arma la guía para su cliente. Los eventos `account.confirmation_code` y
`account.activated` te avisan cuándo mostrar el código y cuándo quedó lista. `banks` es opcional
(todos por defecto); `tenantRef` llega en cada pago (`data.account.tenantRef`) para saber de qué
cliente es. Una app solo ve sus propias cuentas.

### API de respaldo

Por si un webhook se perdió: `GET /v1/payments?since=<ISO>&limit=100` (opcional `&account=<id>` o
`&tenantRef=<id>`) con
`Authorization: Bearer <API key de la app>` → `{ "payments": [...], "next": "<receivedAt del último>" }`,
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
INGEST_SECRET=$(openssl rand -hex 32) MASTER_KEY=$(openssl rand -hex 32) INBOUND_DOMAIN=pagos.localhost npm start
# y abre el enlace /setup?token=… que aparece en la consola
```

Node 22 (usa `node:sqlite`, sin dependencias nativas). Dependencias: `mailauth` (DKIM) y
`postal-mime` (leer el correo).

## Si cambias de dominio

- **La dirección que recibe** (`pagos-…@pagos.edwsystem.com`) puede quedarse igual aunque tus apps
  cambien de dominio: nadie la ve y así no hay que tocar los filtros de Gmail.
- Si cambias **el dominio de pagoradar**: Dokploy → *Domains* y `PUBLIC_URL`, y en el Worker la
  variable `PAGORADAR_URL`.
- Si cambias **el dominio de una app**: en el panel, **Apps → la app → URL del webhook**. Sin redesplegar.
- Si cambias **el dominio de recepción**: Email Routing (subdominio + catch-all hacia el Worker) en el
  dominio nuevo y **Ajustes → Dominio de recepción** (aplica a las cuentas nuevas). Las cuentas que
  ya existen conservan su dirección; para moverlas, crea cuentas nuevas y repite en cada Gmail la
  dirección de reenvío (con su código) y el filtro.
