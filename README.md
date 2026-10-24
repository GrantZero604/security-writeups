# Security Research & CTF Writeups

Writeups from CTF challenges and lab-based security research, focused on web exploitation and identity/cloud attack paths.

**Author:** Bram Brinkmeier — `grantzero` ([LinkedIn](https://www.linkedin.com/in/brambrinkmeier/)) — Cloud & Identity Security Engineer. I work on Microsoft identity and detection-and-response by day (Entra ID, Defender XDR, Sentinel, Intune); these are offensive-side exercises, always authorized and run against CTF or personal-lab targets.

## Writeups

| Challenge | Event | Category | Techniques |
|---|---|---|---|
| [Critter Gallery](./critter-gallery-intigriti-0926.md) | Intigriti CTF 0926 | Web / SQL Injection | Base64-wrapped injection point · union-based SQLi · blank-response error oracle · MySQL hex literals · `group_concat()` schema dump |
| [Halloween Store](./halloween-store-intigriti-1026.md) ([interactive edition](https://grantzero604.github.io/security-writeups/halloween-store/)) | Intigriti CTF 1026 | Web / Business Logic | Impossible-rendered-state tell · stale `cart.last_coupon` comparison vs a toggling coupon pair · reconstructed server model validated against 6 live observations, re-checked live in the browser · real captured request/response replay · percentage-stack floor at 0, not a refund |
| [Bad Reception](./bad-reception-intigriti-0826.md) | Intigriti CTF 0826 | Web / XSS | DOMPurify `ADD_TAGS` bypass · CSP `script-src 'self'` same-origin bypass · JSONP gadget |

## Methodology

| Guide | Category | What it covers |
|---|---|---|
| [OAuth2 / OIDC Discovery Playbook](./oauth-oidc-discovery-playbook.md) | Web / Identity | Reading the discovery document · provider fingerprinting (Entra ID, Okta, Keycloak, Auth0, Duende, Cognito) · flow classification · PKCE · `redirect_uri` and `state` misconfigurations · reporting |

---

*Everything here is CTF or authorized-lab work. No real-world targets, credentials, or findings are published.*

*Writeups licensed [CC BY 4.0](./LICENSE) — quote and share freely with attribution.*
