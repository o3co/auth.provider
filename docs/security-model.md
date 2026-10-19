# Security model

What auth-provider 0.18 guarantees, and what it leaves to the deployment. Each guarantee holds only while the conditions in "Left to you" hold.

## Contents

- [Promises across modules](#promises-across-modules)
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

## Promises across modules

Each promise below holds across every module composed. Each names what keeps it (a contract, a check at boot, a guard rule) and the conformance scenes that test it, by area and scene; where no scene tests a part yet, it says so. An exception is never silent: it is a declaration, in a package manifest or on a route, and the [route reference](routes.md) lists the routes' reasons.

1. **Closing a session closes every path for the tokens issued from it.**
   - Kept by: `session`'s participants, which `session-lifecycle` calls on every close; `session-tokens` and `refresh` take part, and `code-grant` voids a code whose session ended.
   - Scenes: code ("tokens and logout", "refresh: what a token may do", "session grant", "OpenID Connect userinfo"), exchange ("token exchange of a session's token"), federation ("federation tokens: refusals").
   - No scene yet for a device approval. A session that ends by expiry alone calls no participant.
2. **`prompt=login` and `max_age` are met only by a fresh authentication.**
   - Kept by: `authorize`'s re-authentication record, taken once; `session` never counts an authentication time it does not know as fresh.
   - Scenes: federation ("federation logins meeting a client's demand for a fresh login", and the freshness scenes through Google and Apple).
   - No scene yet for a password login.
3. **A dependency that cannot answer never grants anything.**
   - Kept by: `kernel`'s `Unavailable`, which `http` answers `503`, or as the route declares.
   - Scenes: each area's "the store failing" scenes (code, exchange, oauth, federation, second factor, passkey), identity ("password login: a user ledger over HTTP"), mtls (the CRL and OCSP outage scenes).
   - Declared exceptions, each the operator's choice: `rate-limit.fail-mode = open` and `mtls.revocation.on-unavailable = allow`.
4. **A subject's revocation boundary refuses everything made before it.**
   - Kept by: `subject-revocation`'s boundaries, which every holder of a subject's state compares against, and its followers.
   - Does not hold for access tokens where `tokens.subject-check = none` is chosen: they live until they expire.
   - A revocation alone does not stop a second factor's enrollment already past its last check. After an account is taken over, reset the subject's second factors (`mfa-flows`' `mfaReset`) rather than only revoking: a reset also stops an enrollment under way.
   - Scenes: code ("a subject the ledger revokes over HTTP"), federation ("federation grants: a subject the ledger revokes"), second factor ("a subject the ledger revokes").
   - No scene yet for a code not yet redeemed, a device code or a token exchange.
5. **What is used once is used once, on any number of instances.**
   - Kept by: `store`'s take-once writes and each store interface's declared needs; `kernel.deployment = multi` refuses a module that declares itself unsafe on several instances (a module that declares nothing is taken as safe).
   - Does not hold with a store that does not persist (`store.accept-volatile`): a restart forgets what was used.
   - Scenes: code (a code redeemed once, a refresh token rotated once, two concurrent uses), oauth ("refuses a replayed assertion"), device ("decides a code once").
   - No scene yet for an exchanged id_token or a recovery code used twice, and no scene runs several instances.
6. **A token bound to a key or a certificate is never used as a bearer token.**
   - Kept by: `sender-binding`, which refuses a bound token presented in another scheme.
   - Scenes: code (userinfo with a DPoP-bound token and with an mTLS-bound one, "refresh: binding a public client's family"), exchange ("token exchange: a binding washed off").
7. **Every request to another server goes through `outbound`.**
   - Kept by: guard G26, which lets product code reach the network only through `outbound` or as its manifest's `network` declares. It reads how the code is written: static imports of network modules and clients, and calls of `fetch`, `WebSocket` and `EventSource`; a dynamic import or a reach it cannot read from the code is not seen.
   - Declared exceptions: `http` serves, `mail-smtp` speaks SMTP and `redis` speaks to Redis, each by its manifest's `network`.
   - No scene: the guard checks it.
8. **Secrets appear neither in logs nor in answers, but for what the provider hands out on purpose.**
   - What it hands out on purpose: tokens and codes to the one they are issued to, and a secret a registration shows once to its owner (a one-time password app's secret, recovery codes).
   - Kept by: `kernel`'s refusals and logs, which name a setting, never its value; `audit`, whose events carry no token or secret; `http`, which logs a failure by its kind only.
   - Scenes: keys ("refusals about keys"), ops (metrics, readiness, refusals about the operations routes), identity (a ledger's credential at boot), and the audit scenes of the authorization endpoint, client credentials and second factor.
   - No scene reads a running server's log lines.
9. **A browser route that changes state needs CSRF or origin evidence.**
   - Kept by: `csrf`'s policy, marked `own-site` in `http.marks`; a route declares whether it changes state and, without such a policy, why it takes other sites' requests, and `http` checks the declarations at boot.
   - Scenes: identity (login and logout without evidence), device (the verification interface), federation (the grant question, a link started from another site), code ("session grant: refusals").
   - Declared exceptions: the route reference's "Other sites" reasons, among them RP-initiated logout, a navigation from the client's site that closes only the session a hint the provider signed names. No scene checks the boot check itself.
10. **A `POST` taken before authentication is limited per source.**
    - Kept by: `rate-limit`'s policies, marked `per-source`; a route without one declares why it counts no source.
    - Scenes: oauth ("limits requests to the token endpoint per source"), identity (login attempts per sender), passkey ("passkey login: the options' limit"), ops (the operations routes and request counting).
    - Declared exceptions: the route reference's "Per source" reasons.

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
  - Where the public origin is https, cookies are `__Host-` and Secure. Cookies are always `Path=/` and `HttpOnly`, and `SameSite=Lax` but for one: the transaction cookie of an upstream identity provider that answers in a posted form is `SameSite=None`, and so always `__Host-` and Secure. Cookies on a plain-http request are not read.
  - Every request that changes state needs same-origin evidence or the double-submit token. Any cross-origin evidence refuses it with 403.
  - Every route declares whether it changes state, and one that does either uses a policy that keeps other sites' requests out and one that limits each source, or says why not; boot refuses a route that does neither. The [route reference](routes.md) lists each route's. A declaration is its owner's claim, not a proof.
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
  - Loopback, link-local, the cloud metadata addresses and other special-purpose addresses are never reached, but for a `plain-loopback` pair the operator names.
  - Private addresses are reached only by URLs a module takes from your own configuration and names so (the audit-http collector, the users-http ledger), at hosts in `outbound.internal-hosts`.
  - Redirects are refused, and only https is used, except plain http to a named `plain-loopback` pair, and signed material (whose signature is checked), fetched from its caller's named hosts.
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
