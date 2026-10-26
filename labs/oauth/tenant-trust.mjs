// Challenge 1: "Whose email is it?"  (easy)
// A fictional multi-tenant expense app signs people in with tokens from a mini identity provider.
// Anyone can create their own tenant at this provider and give their users any email they like,
// the same way any Entra tenant admin controls the `email` claim of their own users.
// Goal: reach GET /admin on the app as the Contoso administrator without having a Contoso account.
// Local lab only: binds 127.0.0.1, holds no real data, simulates the flaw class, not Entra itself.
import { makeKeys, signJwt, verifyJwt, rand, readBody, send, listen } from './lib.mjs';

export async function start({ port = 4101, fixed = false } = {}) {
  const keys = makeKeys();
  const jwks = { keys: [keys.jwk] };
  const flag = `FLAG{tenant-trust-${rand(6)}}`;
  const base = `http://localhost:${port}`;
  const CLIENT_ID = 'expense-app';
  const users = new Map(); // `${tid}/${username}` -> { oid, email, name }
  const sessions = new Map();
  const HOME_TID = 'contoso';
  users.set(`${HOME_TID}/admin`, { oid: rand(8), email: 'admin@contoso.test', name: 'Contoso Admin', tid: HOME_TID });

  // The app's own account table, keyed by what the app chose to trust.
  const accounts = fixed
    ? new Map([[`${HOME_TID}:${users.get(`${HOME_TID}/admin`).oid}`, { role: 'admin' }]])
    : new Map([['admin@contoso.test', { role: 'admin' }]]);

  const server = await listen(async (req, res) => {
    const url = new URL(req.url, base);
    const path = url.pathname;
    const body = req.method === 'POST' ? await readBody(req) : {};

    // ---- the identity provider (any tenant, open registration) ----
    if (path === '/idp/jwks') return send(res, 200, jwks);
    let m = path.match(/^\/idp\/([a-z0-9.-]+)\/users$/);
    if (m && req.method === 'POST') {
      const tid = m[1];
      if (tid === HOME_TID) return send(res, 403, { error: 'tenant contoso is not open for registration' });
      const { username, email, name } = body;
      if (!username) return send(res, 400, { error: 'username required' });
      users.set(`${tid}/${username}`, { oid: rand(8), email: email ?? `${username}@${tid}.test`, name: name ?? username, tid });
      return send(res, 201, { created: `${tid}/${username}` });
    }
    m = path.match(/^\/idp\/([a-z0-9.-]+)\/token$/);
    if (m && req.method === 'POST') {
      const tid = m[1];
      const u = users.get(`${tid}/${body.username}`);
      if (!u) return send(res, 404, { error: 'no such user in this tenant' });
      if (tid === HOME_TID) return send(res, 403, { error: 'contoso sign-in needs credentials you do not have' });
      const now = Math.floor(Date.now() / 1000);
      const id_token = signJwt({ iss: `${base}/idp/${tid}/v2.0`, tid, oid: u.oid, aud: CLIENT_ID, email: u.email, name: u.name, iat: now, exp: now + 600 }, keys.privateKey);
      return send(res, 200, { id_token });
    }

    // ---- the expense app (relying party) ----
    if (path === '/login' && req.method === 'POST') {
      let claims;
      try { claims = verifyJwt(body.id_token, jwks); } catch (e) { return send(res, 401, { error: `token rejected: ${e.message}` }); }
      if (claims.aud !== CLIENT_ID) return send(res, 401, { error: 'wrong audience' });
      let key;
      if (fixed) {
        if (claims.tid !== HOME_TID || claims.iss !== `${base}/idp/${HOME_TID}/v2.0`) return send(res, 403, { error: 'tenant not allowed' });
        key = `${claims.tid}:${claims.oid}`;
      } else {
        key = claims.email; // the app looks people up by email
      }
      const acct = accounts.get(key) ?? { role: 'user' };
      const sid = rand(16);
      sessions.set(sid, { key, role: acct.role });
      return send(res, 200, { session: sid, role: acct.role });
    }
    if (path === '/admin') {
      const s = sessions.get(req.headers['x-session'] ?? '');
      if (!s) return send(res, 401, { error: 'send your session in the X-Session header' });
      if (s.role !== 'admin') return send(res, 403, { error: 'admins only' });
      return send(res, 200, { message: 'Welcome, administrator.', flag });
    }
    if (path === '/flag-check') return send(res, 200, { correct: url.searchParams.get('flag') === flag });
    if (path === '/') return send(res, 200, `Expense app (lab). Identity provider JWKS: ${base}/idp/jwks\nEndpoints: POST /idp/<tenant>/users, POST /idp/<tenant>/token, POST /login, GET /admin\nGoal: read the flag from /admin as the Contoso administrator.\n`);
    return send(res, 404, { error: 'not found' });
  }, port);
  return { server, port, flag, base, close: () => new Promise((r) => server.close(r)) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 4101);
  const lab = await start({ port, fixed: process.argv.includes('--fixed') });
  console.log(`tenant-trust lab on http://localhost:${port}/  (${process.argv.includes('--fixed') ? 'FIXED build' : 'vulnerable build'})`);
}
