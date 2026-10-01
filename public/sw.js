// pagoradar's service worker: makes the panel installable and keeps its look (styles, script, icons) cached.
// Pages with payment data are never stored: they always come from the network, and when there is no
// connection a small "sin conexión" page is shown instead.
const CACHE = "pagoradar-static-v1";
const PRECACHE = ["/icons/icon-192.png", "/icons/icon.svg", "/favicon.svg"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

const OFFLINE = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sin conexión · pagoradar</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a1013;color:#e8f2f4;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;text-align:center;padding:24px}
img{width:72px;height:72px;margin-bottom:16px}h1{font-size:20px;margin:0 0 6px}p{color:#8ca3aa;margin:0 0 20px}
button{min-height:44px;padding:0 20px;border:0;border-radius:10px;background:#2dd4bf;color:#032321;font:inherit;font-weight:700;cursor:pointer}
</style></head><body><main><img src="/icons/icon-192.png" alt=""><h1>Sin conexión</h1><p>pagoradar necesita internet para mostrar tus pagos.</p>
<button onclick="location.reload()">Reintentar</button></main></body></html>`;

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Styles, scripts and icons: from the cache, refreshed in the background (their URLs change on each release).
  if (url.pathname.startsWith("/static/") || url.pathname.startsWith("/icons/") || url.pathname === "/favicon.svg") {
    event.respondWith(
      caches.open(CACHE).then(async (cache) => {
        const hit = await cache.match(req);
        const fresh = fetch(req)
          .then((res) => {
            if (res.ok) cache.put(req, res.clone());
            return res;
          })
          .catch(() => hit);
        return hit || fresh;
      }),
    );
    return;
  }

  // Pages: always the network (never cached); a friendly page when offline.
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req).catch(() => new Response(OFFLINE, { status: 503, headers: { "Content-Type": "text/html; charset=utf-8" } })),
    );
  }
});
