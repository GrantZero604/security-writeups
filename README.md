# Security Research & CTF Writeups

Writeups from CTF challenges and lab-based security research, focused on web exploitation and identity/cloud attack paths.

**Author:** Bram Brinkmeier — `grantzero` ([LinkedIn](https://www.linkedin.com/in/brambrinkmeier/)) — Cloud & Identity Security Engineer. I work on Microsoft identity and detection-and-response by day (Entra ID, Defender XDR, Sentinel, Intune); these are offensive-side exercises, always authorized and run against CTF or personal-lab targets.

## Writeups

| Challenge | Event | Category | Techniques |
|---|---|---|---|
| [Bad Reception](./bad-reception-intigriti-0826.md) | Intigriti CTF 0826 | Web / XSS | DOMPurify `ADD_TAGS` bypass · CSP `script-src 'self'` same-origin bypass · JSONP gadget |

## Methodology

| Guide | Category | What it covers |
|---|---|---|
| [OAuth2 / OIDC Discovery Playbook](./oauth-oidc-discovery-playbook.md) | Web / Identity | Reading the discovery document · provider fingerprinting (Entra ID, Okta, Keycloak, Auth0, Duende, Cognito) · flow classification · PKCE · `redirect_uri` and `state` misconfigurations · reporting |

---

*Everything here is CTF or authorized-lab work. No real-world targets, credentials, or findings are published.*

*Writeups licensed [CC BY 4.0](./LICENSE) — quote and share freely with attribution.*
