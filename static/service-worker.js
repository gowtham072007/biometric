const CACHE_NAME = 'fxec-biometric-app-shell-v4';
const ASSETS = [
  '/',
  '/index.html',
  '/login.html',
  '/register.html',
  '/dashboard.html',
  '/authenticate.html',
  '/history.html',
  '/users.html',
  '/admin.html',
  '/location.html',
  '/logs.html',
  '/late_form.html',
  '/privacy.html',
  '/css/main.css',
  '/css/components.css',
  '/js/app.js',
  '/js/api.js',
  '/js/geo.js',
  '/js/webauthn.js',
  '/js/admin.js',
  '/manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[Service Worker] Caching App Shell v2');
      return cache.addAll(ASSETS);
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('[Service Worker] Purging old cache:', key);
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // Never cache API endpoints (always live for security & data accuracy)
  if (event.request.url.includes('/api/')) {
    return;
  }

  // Network-First for JS, CSS, and HTML so updates are instantly loaded
  if (
    event.request.url.includes('/js/') ||
    event.request.url.includes('/css/') ||
    event.request.headers.get('accept')?.includes('text/html')
  ) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response && response.status === 200) {
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseClone);
            });
          }
          return response;
        })
        .catch(() => {
          return caches.match(event.request);
        })
    );
    return;
  }

  // Cache-First for other static assets (images, icons, fonts)
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }
      return fetch(event.request);
    })
  );
});
