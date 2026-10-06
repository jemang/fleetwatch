// Notifications on this device: Settings turns them on or off and sends a
// test. The Hub stores the browser's subscription; the service worker shows
// what the Hub pushes.
(function () {
  var box = document.getElementById('push');
  if (!box) return;
  var state = document.getElementById('push-state');
  var on = document.getElementById('push-on'), off = document.getElementById('push-off'), test = document.getElementById('push-test');
  var msg = document.getElementById('push-msg');

  function show(text, mode) {
    state.textContent = text;
    on.hidden = mode !== 'off';
    off.hidden = test.hidden = mode !== 'on';
  }
  function say(text, bad) { msg.textContent = text; msg.className = 'testresult ' + (bad ? 'bad' : 'ok'); }
  async function post(url, body) {
    var r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error((await r.text()).trim() || ('HTTP ' + r.status));
    return r;
  }
  function key(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    var bin = atob(s + '==='.slice((s.length + 3) % 4)), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function sameKey(sub) {
    var k = sub.options && sub.options.applicationServerKey;
    if (!k) return true;
    var a = new Uint8Array(k), b = key(box.dataset.key);
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  function label() {
    var ua = navigator.userAgent;
    var os = /Android/.test(ua) ? 'Android' : /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Mac OS X/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'this device';
    var b = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
    return b + ' on ' + os;
  }

  if (!window.isSecureContext) { show('Notifications need the Hub on HTTPS; this Hub\'s address is ' + box.dataset.url + '.'); return; }
  if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) {
    show('This browser cannot show FleetWatch notifications. On iPhone, open FleetWatch from the Home Screen.');
    return;
  }

  var reg;
  async function refresh() {
    if (Notification.permission === 'denied') { show('Notifications are blocked for FleetWatch in this browser\'s settings.'); return; }
    var sub = await reg.pushManager.getSubscription();
    // A subscription made with another Hub key (a new database) cannot be
    // delivered to, so it counts as off.
    if (sub && sameKey(sub) && (await (await post('/push/state', { endpoint: sub.endpoint })).json()).stored) { show('On for this device.', 'on'); return; }
    show('Off for this device.', 'off');
  }

  navigator.serviceWorker.register('/sw.js').then(function () { return navigator.serviceWorker.ready; }).then(function (r) { reg = r; return refresh(); })
    .catch(function (e) { show('Notifications cannot start here: ' + (e.message || e)); });

  on.addEventListener('click', async function () {
    on.disabled = true;
    try {
      if (await Notification.requestPermission() !== 'granted') { await refresh(); return; }
      // A subscription made with an older Hub key cannot be reused.
      var old = await reg.pushManager.getSubscription();
      if (old) {
        await post('/push/unsubscribe', { endpoint: old.endpoint });
        await old.unsubscribe();
      }
      var sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key(box.dataset.key) });
      var j = sub.toJSON();
      await post('/push/subscribe', { endpoint: j.endpoint, keys: j.keys, label: label() });
      location.reload();
    } catch (e) {
      say(e.message || String(e), true);
    } finally {
      on.disabled = false;
    }
  });

  off.addEventListener('click', async function () {
    off.disabled = true;
    try {
      var sub = await reg.pushManager.getSubscription();
      if (sub) {
        await post('/push/unsubscribe', { endpoint: sub.endpoint });
        await sub.unsubscribe();
      }
      location.reload();
    } catch (e) {
      say(e.message || String(e), true);
      off.disabled = false;
    }
  });

  test.addEventListener('click', async function () {
    test.disabled = true;
    say('Sending…');
    try {
      var sub = await reg.pushManager.getSubscription();
      var html = await (await post('/push/test', { endpoint: sub.endpoint })).text();
      msg.className = 'testresult';
      msg.innerHTML = html;
    } catch (e) {
      say(e.message || String(e), true);
    } finally {
      test.disabled = false;
    }
  });
})();
