# Security model

What auth-provider 0.18 guarantees, and what it leaves to the deployment. Each guarantee holds only while the conditions in "Left to you" hold.

## Contents

- [Boot](#boot)
- [Secrets and logs](#secrets-and-logs)
- [Requests and proxies](#requests-and-proxies)
- [Browsers: sessions, cookies and CSRF](#browsers-sessions-cookies-and-csrf)
- [Tokens](#tokens)
- [Sender-constrained tokens](#sender-constrained-tokens)
- [Rate limits](#rate-limits)
- [Upstream identity providers](#upstream-identity-providers)
- [Outbound requests](#outbound-requests)
- [Storage](#storage)
- [Audit](#audit)
- [Keys](#keys)

## Boot

- **Guaranteed:**
  - The app serves nothing while any setting is refused. Every refusal is reported at once, by setting path.
  - Key material has no default.
  - A sample value left in place (`REPLACE-…`) is refused.
- **Left to you:** keeping the configuration files and environment that hold secrets readable only by the app.

## Secrets and logs

- **Guaranteed:**
  - A refusal or a log line names a setting, an error's kind or a key path, never a value.
  - The Redis URL, an `Authorization` value, a proxy's credentials, session attributes and outbound answers' bodies are never logged.
  - Secrets given as bytes must be strict base64 with at least 8 distinct byte values.
- **Left to you:** where logs go and who can read them.

## Requests and proxies

- **Guaranteed:**
  - The public origin comes only from configuration, never from `Host` or forwarded headers.
  - `X-Forwarded-For` is followed only from a peer in `http.trusted-proxies`, and at most `http.proxy-hops` deep. The forwarded scheme is taken only as a single value from a trusted peer. `Forwarded` is never read.
  - A forwarded client certificate is read only from a trusted peer.
  - Security headers (CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy: no-referrer`) are set on every answer.
- **Left to you:**
  - Terminating TLS. The app speaks plain HTTP behind your proxy; an http public origin needs `http.insecure-origin = true`.
  - Setting `http.trusted-proxies` whenever a proxy is in front.
  - Making the proxy strip or overwrite `X-Forwarded-For`, the forwarded scheme and the client-certificate header that clients send.
  - Bounding upload rates and connections per client in front. The app bounds a request's headers and the whole request (`http.headers-timeout`, `http.request-timeout`) and the connections it holds (`http.max-connections`), all clients together.
  - Synchronizing host clocks.
  - Accepting that RP-initiated logout by GET with a recent `id_token_hint` closes a session without asking.
  - The [runbook's list](runbook.md#before-you-deploy) of what the deployment must provide.

## Browsers: sessions, cookies and CSRF

- **Guaranteed:**
  - Each login gets a new session handle, so a session cannot be fixed in advance. The cookie holds an unguessable secret.
  - Where the public origin is https, cookies are `__Host-` and Secure. Cookies are always `Path=/`, `HttpOnly` and `SameSite=Lax`. Cookies on a plain-http request are not read.
  - Every request that changes state needs same-origin evidence or the double-submit token. Any cross-origin evidence refuses it with 403.
  - Revoking a subject's sessions closes each of them.
- **Left to you:**
  - Keeping other subdomains of your origin from being taken over: double submit relies on them being unable to set the cookie.
  - Ending sessions with revocation, not by waiting out their lifetime, when they must end now.

## Tokens

- **Guaranteed:**
  - With `tokens.revocation = denylist`, a revoked token is refused wherever it is checked.
  - A revocation is answered only once it is stored where it survives a crash and a failover.
  - An outage answers 503, never "inactive" and never a success.
- **Session tokens:** when a session holds more tokens than the store keeps, the oldest is pushed out and revoked. A session near its cap is listed before the add, so a crash leaves it to the sweep; only more concurrent adds than `session-tokens.push-out-margin`, together with a crash, can leave a pushed-out token alive until it expires.
- **Left to you:**
  - Choosing `tokens.revocation`. With `unsupported`, nothing issued can be revoked, and boot refuses a composition that issues refresh tokens or codes.
  - With `subject-check = none`, a revoked subject's access tokens live until they expire.

## Sender-constrained tokens

- **Guaranteed:**
  - DPoP:
    - A proof is accepted once (its `jti` is kept where it is never evicted and survives a crash and a failover).
    - `htu` is compared with a URL built from the issuer, never from request headers.
    - Nonces are checked when configured.
  - A token bound to a key or certificate is refused when presented under another scheme, so a binding cannot be stripped.
- **Left to you:**
  - Keeping the issuer's path when your proxy forwards requests: a proxy that strips it breaks every DPoP proof.
  - Choosing `mtls.revocation.on-unavailable` (`reject` refuses during a revocation outage; `allow` binds with a warning).
  - The self-signed mTLS mode binds any certificate that parses.

## Rate limits

- **Guaranteed:**
  - With the default `rate-limit.fail-mode = closed`, a store outage never lifts a limit.
  - Attempt limits (logins, codes) always answer 503 when they cannot count.
  - Lockouts survive a crash and a failover.
  - A request whose source cannot be determined is refused with 503 and logged as a deployment error.
  - Failed password attempts at one identifier, from any source, make each next one wait, doubling to `login-password.account-max-wait` (default `5m`). In exchange, anyone who knows an identifier can keep that account's password login waiting up to that long, again and again; passkey and federation logins are not held back.
- **Left to you:** setting the trusted proxies, so that each request's source is the client's and not your proxy's.

## Upstream identity providers

- **Guaranteed:** an upstream login proves only the amr values its IdP's `upstream-amr` maps; nothing is mapped by default.
- **Exchanged id_tokens (`exchange-id-tokens`):** only a public client must prove a holder key (DPoP, the key's digest as the id_token's `nonce`); a confidential client exchanges an id_token by its own authentication alone. A leaked id_token can be exchanged once, within `max-age` (default `10m`), by a confidential client allowed for that app's id_tokens.
- **Left to you:** mapping an upstream value to a local amr in `federation.idps.<name>.upstream-amr` (to `mfa`, say) trusts that IdP's claim for the amr, and for any acr it meets (such as `urn:o3co:acr:mfa`). Map only what you trust the IdP to have checked.

## Outbound requests

- **Guaranteed:**
  - No host is reached by name unless `outbound.allow` lists it or `outbound.allow-any-public` is set. `outbound.deny` is checked first.
  - A name is resolved once, every address it resolves to is checked, and the request connects only to a checked address.
  - Loopback, link-local, the cloud metadata addresses and other special-purpose addresses are never reached.
  - Private addresses are reached only by URLs a module takes from your own configuration and names so (the audit-http collector, the users-http ledger), at hosts in `outbound.internal-hosts`.
  - Redirects are refused, and only https is used, except plain http to a `plain-loopback` pair.
  - Proxy environment variables are never read.
- **Left to you:**
  - With `outbound.proxy` set, the proxy resolves names and checks where they lead (boot warns so).
  - Network egress filtering is still expected.

## Storage

- **Guaranteed:**
  - Data that must never be lost is kept only where Redis is checked to keep it: no eviction, an append-only file written on every command, and, with replicas, every replica holding it before it counts.
  - An outage or an unknown outcome is unavailable, answered 503, and never read as "absent" or "allowed".
- **Left to you:**
  - Keeping a lagging replica from being promoted.
  - The replicas' own persistence.
  - Leaving the server's settings as they were at boot.

## Audit

- **Guaranteed:**
  - Every event a receiver loses is counted per receiver, as the metric `auth_audit_events_lost_total`, and a warning names the receiver and the kind of failure, never the event.
  - At stop, deliveries under way are awaited until `kernel.stop-deadline`.
  - The `log` receiver writes attribute names, never their values.
- **Not guaranteed:** delivery. Audit is best effort (tier 1): a request is answered without waiting for its events to be delivered, and an event is lost past a receiver's `max-pending`, when its receiver fails, or when still under way at the stop deadline. `audit-http` never sends an event again.
- **Left to you:** a collector that keeps up, and watching the lost-event count.

## Keys

- **Guaranteed:**
  - Signing keys and sealing keys are read from configuration only.
  - A previous signing key verifies only until its `expires-at`.
  - Stored secrets (TOTP secrets, upstream tokens, delegated credentials) are sealed with AES-256-GCM.
- **Left to you:**
  - Rotating keys as the [runbook](runbook.md#rotating-the-signing-key) describes.
  - Retiring a sealing key only after a `reseal` run that exited 0, as the [runbook](runbook.md#rotating-the-sealing-key) describes. A value a removed key still sealed becomes unavailable until the key is put back.
