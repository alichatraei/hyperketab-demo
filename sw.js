// Hyper Ketab PWA service worker.
// App shell: cache-first. Books: only the ENCRYPTED payload is ever cached (by the reader, in IndexedDB).
// Licence/key requests are never cached.
const SHELL = 'hk-shell-v1';
self.addEventListener('install', (e) => { self.skipWaiting(); });
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  if (url.pathname.includes('/license/') || url.pathname.includes('/books/')) return; // network only
  e.respondWith(caches.open(SHELL).then(async (c) => {
    const hit = await c.match(e.request);
    const net = fetch(e.request).then((r) => { if (r.ok) c.put(e.request, r.clone()); return r; }).catch(() => hit);
    return hit || net;
  }));
});
