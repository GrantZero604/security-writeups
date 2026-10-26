// Challenge 2: "Close enough"  (medium)
// A mini identity provider hosts a public OAuth client with no PKCE. A victim who is already signed in
// clicks links they are sent. Goal: capture the victim's authorization code, trade it for a token and
// call GET /api/me to read the flag. The attacker's listener is built in at the "attacker" port.
// Local lab only: binds 127.0.0.1, holds no real data, simulates the flaw class, not Entra itself.
import { rand, readBody, send, listen } from './lib.mjs';

export async function start({ port = 4102, attackerPort = 4103, fixed = false } = {}) {
  const base = `http://localhost:${port}`;
  const CLIENT_ID = 'notes-spa';
  const REGISTERED = `${base}/cb`;
  const flag = `FLAG{redirect-prefix-${rand(6)}}`;
  const codes = new Map(); // code -> user
  const tokens = new Map(); // token -> user
  const captured = []; // what the attacker listener has seen
  const VICTIM = { name: 'victim', secret_note: flag };

  const redirectOk = (uri) => {
    if (fixed) return uri === REGISTERED; // exact match, the rule Entra applies
    return uri.startsWith(`${base}`); // "starts with our origin" -- looks fine, is not
  };

  const idp = await listen(async (req, res) => {
    const url = new URL(req.url, base);
    const path = url.pathname;
    if (path === '/authorize') {
      // Victim's browser session cookie is how the IdP knows who is clicking.
      const cookie = req.headers.cookie ?? '';
      if (!cookie.includes('sid=victim-session')) return send(res, 401, 'not signed in (the victim bot sends a session cookie; you do not)');
      const q = url.searchParams;
      if (q.get('client_id') !== CLIENT_ID) return send(res, 400, { error: 'unknown client' });
      const ru = q.get('redirect_uri') ?? '';
      if (!redirectOk(ru)) return send(res, 400, { error: 'redirect_uri not registered for this client' });
      const code = rand(12);
      codes.set(code, VICTIM);
      const target = new URL(ru);
      target.searchParams.set('code', code);
      if (q.get('state')) target.searchParams.set('state', q.get('state'));
      return send(res, 302, '', { location: target.toString() });
    }
    if (path === '/token' && req.method === 'POST') {
      const b = await readBody(req);
      if (b.client_id !== CLIENT_ID) return send(res, 400, { error: 'unknown client' });
      const u = codes.get(b.code);
      if (!u) return send(res, 400, { error: 'invalid or used code' });
      codes.delete(b.code);
      const t = rand(16);
      tokens.set(t, u);
      return send(res, 200, { access_token: t, token_type: 'Bearer' });
    }
    if (path === '/api/me') {
      const t = (req.headers.authorization ?? '').replace(/^Bearer /, '');
      const u = tokens.get(t);
      if (!u) return send(res, 401, { error: 'bearer token required' });
      return send(res, 200, { name: u.name, note: u.secret_note });
    }
    // The victim bot: "send the victim a link". It opens the link with the victim's cookie and follows
    // at most one redirect, like a browser would.
    if (path === '/victim/visit' && req.method === 'POST') {
      const { url: link } = await readBody(req);
      let u;
      try { u = new URL(link); } catch { return send(res, 400, { error: 'give a full URL' }); }
      if (u.origin !== base) return send(res, 400, { error: 'the victim only opens links on the identity provider' });
      const r1 = await fetch(u, { redirect: 'manual', headers: { cookie: 'sid=victim-session' } });
      const loc = r1.headers.get('location');
      if (loc) {
        // A browser drops user:password@ from the URL before connecting; fetch() refuses it, so do the same by hand.
        const t = new URL(loc);
        await fetch(`${t.protocol}//${t.host}${t.pathname}${t.search}`, { redirect: 'manual' }).catch(() => {});
      }
      return send(res, 200, { visited: u.toString(), status: r1.status });
    }
    if (path === '/flag-check') return send(res, 200, { correct: url.searchParams.get('flag') === flag });
    if (path === '/') return send(res, 200, `Notes app identity provider (lab).\nClient: ${CLIENT_ID} (public, no PKCE), registered redirect URI: ${REGISTERED}\nEndpoints: GET /authorize, POST /token, GET /api/me, POST /victim/visit {url}\nAttacker listener: http://127.0.0.1:${attackerPort}/ (GET /log shows what it received)\nGoal: read the victim's note via /api/me.\n`);
    return send(res, 404, { error: 'not found' });
  }, port);

  const attacker = await listen(async (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${attackerPort}`);
    if (url.pathname === '/log') return send(res, 200, { captured });
    captured.push({ path: url.pathname, query: Object.fromEntries(url.searchParams) });
    return send(res, 200, 'nothing to see here');
  }, attackerPort);

  return { port, attackerPort, flag, base, close: () => Promise.all([new Promise((r) => idp.close(r)), new Promise((r) => attacker.close(r))]) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 4102);
  const attackerPort = Number(process.env.ATTACKER_PORT ?? 4103);
  await start({ port, attackerPort, fixed: process.argv.includes('--fixed') });
  console.log(`redirect-prefix lab on http://localhost:${port}/ , attacker listener on http://127.0.0.1:${attackerPort}/  (${process.argv.includes('--fixed') ? 'FIXED build' : 'vulnerable build'})`);
}
