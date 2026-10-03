// Adds a virtual WebAuthn authenticator to the page at the given URL prefix
// over Chrome DevTools, then stays attached until killed.
const [wsURL, prefix] = process.argv.slice(2);
const ws = new WebSocket(wsURL);
let id = 0; const waiting = new Map();
const send = (method, params = {}, sessionId) => new Promise((res, rej) => {
  const msgId = ++id; waiting.set(msgId, { res, rej });
  ws.send(JSON.stringify({ id: msgId, method, params, sessionId }));
});
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && waiting.has(m.id)) { const w = waiting.get(m.id); waiting.delete(m.id); m.error ? w.rej(new Error(JSON.stringify(m.error))) : w.res(m.result); }
};
ws.onopen = async () => {
  try {
    const { targetInfos } = await send('Target.getTargets');
    const page = targetInfos.find(t => t.type === 'page' && t.url.startsWith(prefix));
    if (!page) throw new Error('no page with prefix ' + prefix + ': ' + targetInfos.map(t => t.url).join(', '));
    const { sessionId } = await send('Target.attachToTarget', { targetId: page.targetId, flatten: true });
    await send('WebAuthn.enable', {}, sessionId);
    const { authenticatorId } = await send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true } }, sessionId);
    console.log('ready ' + authenticatorId);
    setInterval(async () => {
      const { credentials } = await send('WebAuthn.getCredentials', { authenticatorId }, sessionId);
      console.log('credentials ' + credentials.length + ' signCount ' + credentials.map(c => c.signCount).join(','));
    }, 5000);
  } catch (e) { console.error('cdp: ' + e.message); process.exit(1); }
};
