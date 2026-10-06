// FleetWatch service worker: it shows alert notifications and caches nothing.
self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });

self.addEventListener('push', function (e) {
  var d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) {}
  e.waitUntil(self.registration.showNotification(d.title || 'FleetWatch', {
    body: d.body || '',
    tag: d.tag || undefined,
    // A newer message for the same alert replaces the older one and still alerts.
    renotify: !!d.tag,
    icon: '/static/icon-192.png',
    data: { url: d.url || '/' }
  }));
});

// A click focuses an open FleetWatch window and shows the alert there; the
// login cookie is SameSite=Strict, and an existing window already carries it.
self.addEventListener('notificationclick', function (e) {
  e.notification.close();
  var url = new URL((e.notification.data && e.notification.data.url) || '/', self.location.origin).href;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (list) {
    for (var i = 0; i < list.length; i++) {
      var c = list[i];
      if (new URL(c.url).origin === self.location.origin && 'focus' in c) {
        // navigate() refuses a window this worker does not control (opened
        // before it, or with a forced reload); a new window still shows the alert.
        return c.focus().then(function (f) { return f && f.navigate ? f.navigate(url) : f; })
          .catch(function () { return self.clients.openWindow(url); });
      }
    }
    return self.clients.openWindow(url);
  }));
});
