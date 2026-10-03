// Passkeys: register from Settings, log in from the login page. The Hub
// speaks the WebAuthn JSON forms; this file only converts the binary fields.
(function () {
  function toBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    var bin = atob(s + '==='.slice((s.length + 3) % 4));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function fromBuf(buf) {
    var bin = '';
    new Uint8Array(buf).forEach(function (b) { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  async function post(url, body) {
    var r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? '' : JSON.stringify(body) });
    if (!r.ok) throw new Error((await r.text()).trim() || ('HTTP ' + r.status));
    return r.status === 204 ? null : r.json();
  }
  var msg = document.getElementById('passkey-msg');
  function say(text, bad) {
    msg.textContent = text;
    msg.hidden = !text;
    msg.className = bad ? (msg.classList.contains('testresult') ? 'testresult bad' : 'error') : (msg.classList.contains('testresult') ? 'testresult ok' : 'error');
  }
  var supported = !!(window.PublicKeyCredential && navigator.credentials);

  var reg = document.getElementById('passkey-register');
  if (reg) reg.addEventListener('click', async function () {
    if (!supported) { say('This browser does not support passkeys.', true); return; }
    var name = document.getElementById('passkey-name').value.trim();
    if (!name) { say('Give the passkey a name first.', true); return; }
    reg.disabled = true;
    try {
      var opts = (await post('/passkeys/register/begin', { name: name })).publicKey;
      opts.challenge = toBuf(opts.challenge);
      opts.user.id = toBuf(opts.user.id);
      (opts.excludeCredentials || []).forEach(function (c) { c.id = toBuf(c.id); });
      var cred = await navigator.credentials.create({ publicKey: opts });
      await post('/passkeys/register/finish', {
        id: cred.id, rawId: fromBuf(cred.rawId), type: cred.type,
        response: {
          clientDataJSON: fromBuf(cred.response.clientDataJSON),
          attestationObject: fromBuf(cred.response.attestationObject),
          transports: cred.response.getTransports ? cred.response.getTransports() : []
        },
        clientExtensionResults: cred.getClientExtensionResults()
      });
      location.reload();
    } catch (e) {
      say(e.message || String(e), true);
      reg.disabled = false;
    }
  });

  var login = document.getElementById('passkey-login');
  if (login) {
    if (!supported) login.hidden = true;
    login.addEventListener('click', async function () {
      login.disabled = true;
      say('');
      try {
        var opts = (await post('/login/passkey/begin')).publicKey;
        opts.challenge = toBuf(opts.challenge);
        (opts.allowCredentials || []).forEach(function (c) { c.id = toBuf(c.id); });
        var cred = await navigator.credentials.get({ publicKey: opts });
        await post('/login/passkey/finish', {
          id: cred.id, rawId: fromBuf(cred.rawId), type: cred.type,
          response: {
            clientDataJSON: fromBuf(cred.response.clientDataJSON),
            authenticatorData: fromBuf(cred.response.authenticatorData),
            signature: fromBuf(cred.response.signature),
            userHandle: cred.response.userHandle ? fromBuf(cred.response.userHandle) : null
          },
          clientExtensionResults: cred.getClientExtensionResults()
        });
        location.href = '/';
      } catch (e) {
        say(e.message || String(e), true);
        login.disabled = false;
      }
    });
  }
})();
