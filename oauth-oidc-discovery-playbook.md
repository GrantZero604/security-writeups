# OAuth2 / OIDC Discovery Playbook

**Author:** Bram Brinkmeier (`grantzero`)  ·  **Type:** Methodology  ·  **Category:** Web / Identity

> Read-only reconnaissance and methodical testing of OAuth2 and OpenID Connect flows.
> The aim is to map the flow and its trust decisions *before* touching a single
> parameter. Most high-impact OAuth bugs — the ones that end in account takeover —
> come from weak `redirect_uri` validation, a missing or unverified `state`, or a
> public client with no PKCE. Only the third is usually visible in the discovery
> document — the first two are runtime behaviours you have to confirm by testing. What
> discovery gives you is where to look.

**Scope and conduct.** Everything below is for systems you are authorised to test: a
bug bounty programme's in-scope hosts, a client engagement with a signed contract, or
your own lab. Use your own test accounts, never a real user's. Keep request rates
within the programme's limits. Never attempt code theft, token replay against
production, or use of a discovered client secret — if you find one, report it, don't
exercise it.

---

## 1. Map the provider — metadata first

Fetch the discovery document and read it as a specification of the server's own
behaviour. It will tell you more in one request than an hour of clicking:

```bash
curl -s "https://TARGET/.well-known/openid-configuration" -o oidc.json

# Some Entra ID and Keycloak deployments use a tenant- or realm-specific issuer:
curl -s "https://TARGET/realms/REALM/.well-known/openid-configuration"
curl -s "https://TARGET/.well-known/oauth-authorization-server"
```

Each field maps to a test:

| Field | Why it matters |
|-------|----------------|
| `issuer` | Must match the token's `iss`; a mismatch is confused-deputy territory |
| `authorization_endpoint` / `token_endpoint` | Where authorisation and code exchange happen |
| `jwks_uri` | Key set used for `id_token` signature validation |
| `end_session_endpoint` | Logout — check `post_logout_redirect_uri` handling |
| `registration_endpoint` | Dynamic client registration; open DCR means anyone can register a client |
| `grant_types_supported` | Is `password` (ROPC), `implicit` or `client_credentials` enabled? |
| `response_types_supported` | `code` versus `token` / `id_token` — implicit and hybrid flows |
| `code_challenge_methods_supported` | Is `S256` present, absent, or is `plain` the only option? |
| `token_endpoint_auth_methods_supported` | `none` in this list means the server *supports* public clients; the per-client `token_endpoint_auth_method` is what makes a given client public |
| `scopes_supported` / `claims_supported` | Scope escalation and claim over-sharing |
| `request_parameter_supported` | JAR support — signed request objects |
| `frontchannel_logout_supported` | Front-channel and iframe logout surface |

If the metadata endpoint 404s, fall back to the application's own login redirect —
`/oauth2/authorize`, `/authorize`, `/connect/authorize` — and its JavaScript. Those
become your source of truth.

## 2. Fingerprint the provider

Correlate signals across the login page HTML and JS, redirect `Location` headers,
response headers, cookies, and the shape of well-known paths:

- **Entra ID (Azure AD)** — host `login.microsoftonline.com`, paths
  `/common|organizations|<tenant>/oauth2/v2.0/authorize`, and `x-ms-request-id` /
  `x-ms-ests-server` response headers. An unauthenticated authorize request sets
  `buid`, `esctx`, `fpc` and `stsservicecookie`; the `ESTSAUTH` family appears only
  after sign-in, so don't expect it during passive discovery. Watch for `client_info`
  and `claims` parameters on the authorize URL.
- **Okta** — `*.okta.com`, `/oauth2/default/v1/authorize`, `/oauth2/v1/token`, cookies
  `okta-oauth-state`, `okta-oauth-nonce`, `DT`, and an `x-okta-request-id` header.
- **Keycloak** — `/realms/<realm>/protocol/openid-connect/auth|token|userinfo`, admin
  console at `/admin/`, cookies `AUTH_SESSION_ID`, `KEYCLOAK_IDENTITY`, `KC_RESTART`.
- **Auth0** — `login.<tenant>` or `*.auth0.com`, `cdn.auth0.com`, `lock.js`, cookies
  `auth0` (session) and `did` (device id), and a `connection=` parameter on the
  authorize URL. Transaction state usually lives in web storage as
  `com.auth0.auth.<state>` rather than in a cookie.
- **Duende IdentityServer** — cookies `idsrv`, `idsrv.session`, login at
  `/Account/Login`, endpoints `/connect/authorize|token|userinfo`; the error page names
  "Duende IdentityServer" (older builds: "IdentityServer4").
- **Amazon Cognito** — hosted UI at `*.auth.<region>.amazoncognito.com/oauth2/authorize|token`,
  `cognito-idp.<region>.amazonaws.com`, JWKS at
  `https://cognito-idp.<region>.amazonaws.com/<pool>/.well-known/jwks.json`, and
  `identity_provider` / `client_id` parameters.

The fingerprint only tells you which defaults are likely. The metadata and the observed
flow decide.

## 3. Classify the flow

- **`authorization_code`** — `/authorize` returns `?code=`, which the client exchanges
  at `/token`. The question that matters: is the exchange server-side, using a secret,
  or in-page from a public client?
- **`authorization_code` + PKCE** — `/authorize` carries `code_challenge` and
  `code_challenge_method`; `/token` carries `code_verifier`. `S256` only is the strong
  configuration. A public client without PKCE is exposed to code interception.
- **implicit / hybrid** — `response_type=token` or `id_token` (or `code id_token`) puts
  tokens in the URL fragment, exposing them to browser history, in-page JavaScript and
  anything else with DOM access. Fragments are never transmitted to the server, so they
  appear in neither server logs nor the `Referer` header — which closes off some leak
  paths, but also means server-side logs will not show you that exposure happened.
- **password / ROPC** — the client collects the password directly and posts
  `grant_type=password`. Bad practice on its own; the impact depends on whether MFA and
  risk-based checks are bypassed along with it.
- **`client_credentials` / `refresh_token`** — machine-to-machine and long-lived
  sessions. Check whether refresh tokens rotate, and whether an old one still works
  after rotation.

Determine which grants are actually enabled by comparing the metadata against a normal
login. Don't brute-force the token endpoint to find out.

## 4. PKCE — presence and implications

- `code_challenge_methods_supported: ["S256"]` is the good case — but verify the client
  actually *sends* it. Advertised support and real use are different things.
- `["plain"]`, or the field missing entirely, is weak. On mobile and SPA clients an
  attacker who captures the redirect can redeem the authorisation code.
- PKCE is not a substitute for exact `redirect_uri` validation. Its relationship to
  `state` is more nuanced than it is often taught: RFC 9700, the OAuth 2.0 Security
  Best Current Practice, holds that PKCE also provides CSRF protection, so a client may
  legitimately rely on it instead of `state`. Don't assume a missing `state` is
  deliberate, though — confirm the client is sending and checking *something*.

## 5. Common misconfigurations

Test one variable at a time. Changing two things and seeing a different result tells
you nothing about which one mattered.

**Redirect handling** — one of the largest sources of account takeover:

- Does `redirect_uri` require an exact match? Try path append (`/cb/../evil`), a
  trailing slash, a case change, an explicit default port, `http` versus `https`, and
  an extra subdomain.
- Open-redirect chaining: an allowed origin that itself contains a redirect.
- Parser confusion: `https://allowed.com@evil.com`, `https://allowed.com.evil.com`,
  `//evil.com`, `https:evil.com`, backslashes, `%2f`, CRLF, and Unicode or dot
  normalisation.
- Parameter pollution — two `redirect_uri` values — and `response_mode` overrides.
- Fragment smuggling: injecting `#` or `?` into the allowed URI.

**State and nonce:**

- Is `state` present, per-session random, and *actually verified* on return? A static or
  missing `state` enables login CSRF and account-linking attacks. Presence is not
  verification — change it and see whether the flow still completes.
- Is `nonce` present for `id_token` flows and bound to the session? A replayable nonce
  means a stolen `id_token` can be accepted.

**Response type and mode:**

- `response_mode=query` can leak `code` or `token` into `Referer` headers, proxy logs
  and analytics pipelines.
- `response_mode=form_post` auto-submitting to an unvalidated URI.

**Token endpoint client authentication:**

- `token_endpoint_auth_method=none` means a public client. Confirm no secret is embedded
  in the JavaScript bundle anyway — it happens.
- A `client_secret` in an SPA or mobile bundle, or `client_secret_post` where a public
  client should be using `none` plus PKCE.

**Logout:**

- `post_logout_redirect_uri` and `id_token_hint` — is the redirect validated? An open
  redirect here chains into token theft or convincing phishing.

**Account binding and scopes:**

- `login_hint`, `prompt=none` and `domain_hint` can enable account or tenant
  enumeration.
- Over-broad `scope` acceptance, consent bypass, and account linking on an unverified
  email address. That last one leads to pre-account-takeover: an attacker registers a
  local account against an email they don't control, and when the real owner later
  signs in through a federated provider, the service links that login to the
  attacker's pre-existing account rather than creating a new one.

## 6. Server-side code exchange

- Where is the code exchanged — a backend `/callback` (good) or in the browser
  (exposed)?
- Is the code single-use, short-lived, and bound to both `client_id` and
  `redirect_uri`? Try redeeming it twice.
- Is the session that *started* the flow the same one that redeems it? If not, that's
  login CSRF.
- Do `access_token` or `refresh_token` values end up in URLs, logs, or cookies scoped
  more broadly than they need to be?
- For OIDC, is the `id_token` fully validated server-side — `iss`, `aud`, `exp`, `nonce`
  and signature? Partial validation is common and is worth testing individually.

## 7. Adjacent to discovery — worth a look once the flow is mapped

This playbook stops at mapping the flow. Three areas sit just past that boundary and
are easy to reach from what discovery already told you:

- **IdP mix-up (multi-IdP deployments).** Where an application supports several
  identity providers, an attacker may be able to get a code issued by one and redeemed
  against another. RFC 9207 adds an `iss` parameter to the authorization response
  specifically to defeat this — check whether the AS sends it and whether the client
  validates it. Relevant any time you noted more than one `issuer`.
- **SSRF via `request_uri` (JAR by reference).** If the server advertises support for
  request objects by reference, it will fetch a URL you supply. Classic server-side
  request forgery, reachable from the `request_parameter_supported` and
  `request_uri_parameter_supported` metadata fields. Pushed Authorization Requests
  (PAR, `pushed_authorization_request_endpoint`) are worth checking in the same pass.
- **`id_token` signature attacks.** Section 6 says validate the signature; the ways
  that validation breaks are `alg: none`, RS256→HS256 key confusion (signing with the
  public key as an HMAC secret), and `kid` or `jku` injection pointing at a key set you
  control. The `jwks_uri` you recorded in step 1 is the reference point for all three.

## 8. Reporting

- Lead with impact — account takeover, cross-tenant access, privilege gain — not with
  the parameter name. A triager reads the first sentence and decides how much attention
  the rest gets.
- Show the exact request and response, and name the boundary that broke. Redact real
  tokens.
- Score the impact you actually demonstrated, and state the theoretical maximum
  separately and explicitly. Conflating the two is the fastest way to lose a triager's
  trust.

---

*grantzero · OAuth2 / OIDC Discovery Playbook*
