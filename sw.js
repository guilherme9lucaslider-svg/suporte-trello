const CACHE = 'painel-v1';
const ASSETS = [
  '/painel',
  '/static/manifest.json'
  // adicione aqui outros estáticos que quiser cachear
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
});

self.addEventListener('fetch', e => {
  const req = e.request;
  e.respondWith(
    caches.match(req).then(cached => cached || fetch(req))
  );
});
