// Tiny shared helpers for the lab servers. Zero dependencies: node:http and node:crypto only.
import { createServer } from 'node:http';
import { generateKeyPairSync, createSign, createVerify, randomBytes, createPublicKey } from 'node:crypto';

export const b64u = (b) => Buffer.from(b).toString('base64url');
export const fromB64u = (s) => Buffer.from(s, 'base64url');

export function makeKeys() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'lab-key-1', alg: 'RS256', use: 'sig' };
  return { publicKey, privateKey, jwk };
}

export function signJwt(claims, privateKey, kid = 'lab-key-1') {
  const head = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid }));
  const body = b64u(JSON.stringify(claims));
  const sig = createSign('RSA-SHA256').update(`${head}.${body}`).sign(privateKey);
  return `${head}.${body}.${b64u(sig)}`;
}

/** Verify signature and exp only. What else gets checked is up to the caller (that is the lab). */
export function verifyJwt(token, jwks) {
  const [h, b, s] = String(token).split('.');
  if (!h || !b || !s) throw new Error('malformed token');
  const head = JSON.parse(fromB64u(h));
  if (head.alg !== 'RS256') throw new Error('only RS256 accepted');
  const jwk = jwks.keys.find((k) => k.kid === head.kid);
  if (!jwk) throw new Error('unknown kid');
  const ok = createVerify('RSA-SHA256').update(`${h}.${b}`).verify(createPublicKey({ key: jwk, format: 'jwk' }), fromB64u(s));
  if (!ok) throw new Error('bad signature');
  const claims = JSON.parse(fromB64u(b));
  if (claims.exp && claims.exp < Date.now() / 1000) throw new Error('expired');
  return claims;
}

export const rand = (n = 8) => randomBytes(n).toString('hex');

export async function readBody(req) {
  let data = '';
  for await (const c of req) { data += c; if (data.length > 1e5) throw new Error('body too large'); }
  const type = req.headers['content-type'] ?? '';
  if (type.includes('application/json')) return data ? JSON.parse(data) : {};
  return Object.fromEntries(new URLSearchParams(data));
}

export const send = (res, status, body, headers = {}) => {
  const isObj = typeof body === 'object';
  res.writeHead(status, { 'content-type': isObj ? 'application/json' : 'text/plain; charset=utf-8', ...headers });
  res.end(isObj ? JSON.stringify(body, null, 2) : body);
};

export function listen(handler, port) {
  const server = createServer((req, res) => {
    Promise.resolve(handler(req, res)).catch((e) => send(res, 500, { error: String(e.message ?? e) }));
  });
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve(server)));
}
