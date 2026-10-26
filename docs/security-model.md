# Security model

What auth-provider 0.19 guarantees, and what it leaves to the deployment. Each guarantee holds only while the conditions in "Left to you" hold.

## Contents

- [Trust assumptions](#trust-assumptions)
- [Promises across modules](#promises-across-modules)
- [Revocation delays](#revocation-delays)
- [Boot](#boot)
- [Secrets and logs](#secrets-and-logs)
- [Requests and proxies](#requests-and-proxies)
- [Browsers: sessions, cookies and CSRF](#browsers-sessions-cookies-and-csrf)
- [Tokens](#tokens)
- [Client authentication](#client-authentication)
- [Sender-constrained tokens](#sender-constrained-tokens)
- [Rate limits](#rate-limits)
- [Upstream identity providers](#upstream-identity-providers)
- [Outbound requests](#outbound-requests)
- [Storage](#storage)
- [Audit](#audit)
- [Keys](#keys)

## Trust assumptions

Every guarantee here rests on what the deployment does. Each section's "Left to you" says it where it applies; this gathers them by what the deployment must do.

- **Its proxy strips what clients forge.** It strips or overwrites `X-Forwarded-For`, the forwarded scheme and the client-certificate header that clients send, and `http.trusted-proxies` names it ([Requests and proxies](#requests-and-proxies)).
- **Its host clocks are synchronized (NTP).** Sessions, codes, tokens, lockouts, key expiry and a subject's revocation are judged on each host's clock, with nothing allowed for skew between hosts: a revocation is compared in whole seconds, so what was made just before it on a host whose clock runs ahead can count as made after it and outlive it ([runbook](runbook.md#before-you-deploy)). Keep them as close as NTP allows; no allowance between hosts is promised.
- **What it terminates, it protects.** TLS is terminated in front of the app, which speaks plain HTTP behind it.
- **An outbound proxy checks where names lead.** With `outbound.proxy` set, the proxy resolves names and refuses the addresses `outbound` would refuse ([Outbound requests](#outbound-requests)).
- **Plain-text peers are on a trusted network.** What goes to a `plain-internal` pair, and to Redis where it is reached in the clear, is readable and changeable on the way: such peers sit on a network trusted against both.
- **Redis keeps what it is checked to keep.** Its persistence stays as it was at boot, the replicas persist too, and a lagging replica is never promoted ([Storage](#storage)).
- **An upstream's word on its own authentication is trusted as far as it is mapped.** An IdP's `amr` and `auth_time` count as the IdP says, for what `federation.idps.<name>.upstream-amr` maps and the fresh-login allowance lets in ([Upstream identity providers](#upstream-identity-providers)).
- **A signer key ledger answers the keys signers hold now.** `signer-keys-http` asks for each assertion and keeps nothing between them, so a key the ledger still answers still signs.
- **Its origin's other subdomains are its own.** Double-submit CSRF protection relies on them being unable to set the cookie ([Browsers](#browsers-sessions-cookies-and-csrf)).
- **Its configuration and its credentials are its own.** The configuration files and environment that hold secrets are readable only by the app, and whoever writes them is trusted; each ledger's `credential` is known only to the app and that ledger.
- **What it asks of it is in place.** The runbook's [Before you deploy](runbook.md#before-you-deploy) lists what the deployment must provide.

## Promises across modules

Each promise below holds across every module composed. Each names what keeps it (a contract, a check at boot, a guard rule) and the conformance scenes that test it, by area and scene; where no scene tests a part yet, it says so. An exception is never silent: it is a declaration, in a package manifest or on a route, and the [route reference](routes.md) lists the routes' reasons.

1. **Closing a session closes every path for the tokens issued from it.**
   - Kept by: `session-participants`' participants, which `session-lifecycle` calls on every close through `session`'s `closingParticipants`, refusing to boot without it; `session-tokens` and `refresh` take part, and `code-grant` voids a code whose session ended.
   - Scenes: code ("tokens and logout", "a logout the client starts", "telling the session's clients", "refresh: what a token may do", "session grant", "OpenID Connect userinfo"), exchange ("token exchange of a session's token"), federation ("federation tokens: refusals").
   - A close left pending is not done: the session stays closing until every participant has finished. Each host sweeps every `session-lifecycle.sweep-interval`, and takes a pending close up again once its retry time comes: after half its age so far, from the sweep interval up to an hour, and `logout` and RP-initiated logout answer it `503`, never as logged out.
   - No scene yet for a device approval. A session that ends by expiry alone calls no participant.
   - A session that ends by its lifetime leaves no token past it: each token issued from a session expires no later than the session's end, as the lifetime in force when it is issued sets it.
   - One exception: shortening `session-lifecycle.lifetime` ends the sessions it now covers when they are next read, without their participants, and the tokens issued before then keep their earlier expiry.
   - Bridges such as `session-tokens` come in every app composed through `combinations`; an app composed by hand must compose them itself, or the promise does not hold for what they join.
2. **`prompt=login` and `max_age` are met only by a fresh authentication.**
   - Kept by: `reauth`'s re-authentication record, which `authorize` makes for the request and takes once; `session` never counts an authentication time it does not know as fresh.
   - Scenes: code ("password logins meeting a client's demand for a fresh login"), federation ("federation logins meeting a client's demand for a fresh login", and the freshness scenes through Google and Apple).
   - One exception, through an upstream: a login the upstream says came within its fresh login allowance before the demand counts as fresh, even where the upstream did not authenticate again (`federation`'s card, "Fresh enough"). The login page hands `prompt=login` and `max_age` to the upstream, which asks the user again where it honours them. To narrow the allowance, set `federation.idps.<name>.fresh-login-allowance` for that IdP (by default its `clock-skew`); the id_token is still checked under `clock-skew`.
   - It narrows only how far back a reported login time reaches. At `0s`, a login in the second `prompt=login` was asked in still counts, as that check compares whole seconds. A max age is compared to the millisecond, `auth_time + allowance + max_age >= now`, so at `0s` `max_age=0` refuses a login before the callback, even in its second. A time ahead of ours that `clock-skew` lets the id_token carry counts, and the time is the upstream's word: one that ignores `prompt=login` and reports a new time passes.
3. **A dependency that cannot answer never grants anything.**
   - It covers what an authorization decision waits on; a notice sent best effort, such as an audit event or a logout notice to a client, decides nothing.
   - Kept by: `kernel`'s `Unavailable`, which `http` answers `503`, or as the route declares; the authorization endpoint, once it trusts the redirect URI, answers it to the client by a redirect with `error=temporarily_unavailable`.
   - Scenes: each area's "the store failing" scenes (code, exchange, oauth, federation, second factor, passkey), identity ("password login: a user ledger over HTTP"), mtls (the CRL and OCSP outage scenes).
   - Declared exceptions, each the operator's choice: `rate-limit.fail-mode = open` and `mtls.revocation.on-unavailable = allow`.
   - While an issuer's key set cannot be fetched, the last one fetched is still used, up to `external-jwt.key-set-max-age` (`1d` by default) after its fetch.
4. **A subject's revocation boundary refuses everything made before it.**
   - Kept by: `subject-revocation`'s boundaries, which every holder of a subject's state compares against, and its followers. Among them, `mfa-revocation` moves `mfa`'s fence, so no second factor's enrollment begun before a revocation binds once the revocation is complete.
   - Does not hold for access tokens where `tokens.subject-check = none` is chosen: they live until they expire.
   - Does not hold for federation grants where `federation-grants.keep-on-subject-revocation` is set and a revocation asks to keep delegations: an established grant then answers only to the `delegations` boundary, which such a revocation leaves where it was.
   - A session opened before a revocation removes no factor and reissues no codes once the revocation is complete: `mfa-management` reads the subject's fence before the session's last check, and `mfa` compares it in the write. Recovery codes go out only after a last check of the revocation, with nothing waited on after it; a request past that check is one a revocation cannot stop, as for any request already past its checks. This holds as far as each check reads the boundary as it now stands.
   - Bridges such as `mfa-revocation` come in every app composed through `combinations`; an app composed by hand must compose them itself, and without `mfa-revocation` `mfa-flows` refuses to boot, so no enrollment begun before a revocation binds. After an account is taken over, also reset the subject's second factors (`mfa-reset`'s `mfaReset`): a revocation ends what was made before it, while a reset removes the factors themselves.
   - Scenes: code ("a subject the ledger revokes over HTTP"), exchange ("a subject the ledger revokes: every way to a token", which covers a code redeemed and one not yet, refresh, token exchange, a device code polled and one not yet, and the back-channel logout token), federation ("federation grants: a subject the ledger revokes"), second factor ("second factor: a subject the ledger revokes").
5. **What is used once is used once, on any number of instances.**
   - Kept by: `store`'s take-once writes and each store interface's declared needs; `kernel.deployment = multi` refuses a module that declares itself unsafe on several instances: `store`, the store kept in memory, and `mail`, which only logs mail (a module that declares nothing is taken as safe).
   - Does not hold where the operator accepts losing what was used: with a store that does not persist (`store.accept-volatile`), a restart forgets it; with `redis.durability = none`, a crash can lose the latest writes, spent assertion and proof ids and lockout records among them; with `redis.replication = none`, a failover would lose writes.
   - Upgrading from rc.1 leaves a window in which JWT bearer assertions spent and id_tokens exchanged under rc.1 are not seen, as [From 0.18.0-rc.1](migration.md#from-0180-rc1) says.
   - Scenes: code (a code redeemed once, a refresh token rotated once, two concurrent uses), oauth ("refuses a replayed assertion"), device ("decides a code once").
   - No scene yet for an exchanged id_token used twice, and no scene runs several instances.
6. **A token bound to a key or a certificate is never used as a bearer token.**
   - Kept by: `sender-binding`, which refuses a bound token presented in another scheme.
   - Scenes: code (userinfo with a DPoP-bound token and with an mTLS-bound one, "refresh: binding a public client's family"), exchange ("token exchange: a binding washed off").
7. **Every request to another server goes through `outbound`.**
   - Kept by: guard G26, which lets product code reach the network only through `outbound` or as its manifest's `network` declares. It reads how the code is written: network modules, clients and DNS resolvers imported, or loaded with `import()` or `require`; any use of `node:child_process`; a module loaded by a name known only at run time; and `fetch`, `WebSocket` and `EventSource` used directly or as a property of the global object, named by a dot or a string literal. What the code's form cannot show (`eval`, a worker, a native add-on, a function passed in from outside, the global object under another name, a property named at run time) is left to review.
   - `outbound` is the gate itself, and declares `network` as `outbound`. Besides it, three packages declare their own reach: `http` serves, `mail-smtp` speaks SMTP and `redis` speaks to Redis, each by its manifest's `network`.
   - No scene: the guard checks it.
8. **Secrets appear neither in logs nor in answers, but for what the provider hands out on purpose.**
   - What it hands out on purpose: tokens and codes to the one they are issued to, and a secret a registration shows once to its owner (a one-time password app's secret, recovery codes).
   - Boot refusals name a setting by its key path, never its value.
   - Log lines carry no secret, credential, token, request body or header value, but for header values from a fixed set (such as `Sec-Fetch-Site`). They may carry the identifiers an operator traces a problem by: a peer's or a proxy's address, a host name, a client's id (a metadata document's URL among them), a request's path, and a session's handle.
   - Kept by: `kernel`'s refusals, by key path; a library's `BuildRefused`, whose where and reason it writes as a public diagnostic, never a secret (the kernel checks their form, not what they say); `audit`, whose events carry no token or secret; `http`, which logs a failure by its kind only; and each module's own log lines.
   - Scenes: keys ("refusals about keys"), ops (metrics, readiness, refusals about the operations routes), identity (a ledger's credential at boot), and the audit scenes of the authorization endpoint, client credentials and second factor.
   - No scene reads a running server's log lines.
9. **A browser route that changes state needs CSRF or origin evidence.**
   - Kept by: `csrf`'s policy, marked `own-site` in `http.marks`; a route declares whether it changes state and, without such a policy, why it takes other sites' requests, and `http` checks the declarations at boot.
   - Scenes: identity (login and logout without evidence), device (the verification interface), federation (the grant question, a link started from another site), code ("session grant: refusals").
   - Declared exceptions: the route reference's "Other sites" reasons, among them RP-initiated logout, a navigation from the client's site that closes only the session a hint the provider signed names, which code ("a logout the client starts") checks. No scene checks the boot check itself.
10. **A `POST` taken before authentication is limited per source.**
    - Kept by: `rate-limit`'s policies, marked `per-source`; a route without one declares why it counts no source.
    - Scenes: oauth ("limits requests to the token endpoint per source"), identity (login attempts per sender), passkey ("passkey login: the options' limit"), ops (the operations routes and request counting).
    - Declared exceptions: the route reference's "Per source" reasons; and, as promise 3 declares, `rate-limit.fail-mode = open`, which lets a request limit pass requests uncounted while the store cannot count (an attempt limit still refuses).

## Revocation delays

How long something revoked can still be used, by where it is checked. **None** means the next check after the revocation is recorded refuses it: a request already past its checks is not stopped (promise 4), and the store or ledger that holds it answers as it now stands, an outage refusing rather than allowing (promise 3).

| What is revoked | Where it is checked | Delay | Set by |
|---|---|---|---|
| A subject, for access tokens, with `subject-tokens` composed | Each time this provider verifies a token | None | `subject-revocation` and `subject-tokens` |
| A subject, for access tokens not bound to a session, with `tokens.subject-check = none` | Not checked for the token itself: the revocation closes the subject's sessions, ending the tokens bound to them (promise 1), and leaves the others | Until the token expires | `tokens.access-token-lifetime` (default `1h`) |
| A token revoked by id (`tokens.revocation = denylist`) | Each time this provider verifies a token | None | `tokens.revocation`; with `unsupported`, nothing issued can be revoked |
| Any access token, at a resource server that verifies it itself | That resource server | Until the token expires, unless it asks introspection | `tokens.access-token-lifetime` |
| Any access token, at a resource server that asks introspection | Each call | As long as the resource server keeps the answer, at most to its `exp` (RFC 7662 §4) | The resource server |
| A refresh token or its family | Each refresh | None | `refresh` |
| A session | Each read | None; its tokens as promise 1 says | `session` |
| A back-channel logout notice | The client, once delivered | No bound: after a failure that can pass (408, 429, a 5xx, the client unreachable) a notice is tried again until `rp-logout.notify-within` (default `1d`), then dropped; one `outbound` refuses, any other status, or a client gone is settled at once, undelivered | `rp-logout.notify-within` |
| An issuer's or an IdP's key set (`external-jwt`) | Each verification, against the set fetched | Fetched again after an hour; while none can be had, the last set is used until `external-jwt.key-set-max-age` (default `1d`) after its fetch, then unavailable | `external-jwt.key-set-max-age` |
| A JWT bearer signer's key at a ledger (`signer-keys-http`) | Each assertion | None, as far as the ledger answers its current keys | The ledger |
| A client certificate, `mtls.mode = pki` with CRLs | Each binding | Until the CA publishes a CRL that lists it (the CA's delay, outside the app), then until the CRL held is fetched again: a CRL is kept up to `mtls.revocation.crl-ttl` (default `1h`) from its fetch | `mtls.revocation.crl-ttl` |
| A client certificate, `mtls.mode = pki` with OCSP | Each binding | Until the responder answers it revoked (the responder's delay), then until the answer held ends: its `nextUpdate`, never past its signer's expiry, or `mtls.revocation.ocsp-fresh` (default `10m`) after its `thisUpdate` where it gives none | `mtls.revocation.ocsp-fresh` |
| A client certificate, `mtls.revocation.mode = disabled` | Not checked | Until the certificate expires | `mtls.revocation.mode` |
| A client certificate, while revocation cannot be told and `mtls.revocation.on-unavailable = allow` | Not checked during the outage | The outage's length, and `mtls.revocation.failure-lifetime` (default `30s`) after it, while the failure is held (each binding warns) | `mtls.revocation.on-unavailable`, `mtls.revocation.failure-lifetime` |
| A client certificate, `mtls.mode = self-signed` | Never: this mode binds any certificate that parses, without the client's registration, and has no revocation | Until the tokens bound to it expire or are revoked, or a check outside the app (a proxy refusing it) stops it | `tokens.access-token-lifetime`, `tokens.revocation` |
| This provider's previous signing key | Each verification | Until the key's `expires-at`, and as long as a resource server keeps the key set it fetched | `keys.previous`, the runbook's [rotation](runbook.md#rotating-the-signing-key) |

To shorten a delay: shorten `tokens.access-token-lifetime`, compose `subject-tokens`, choose `tokens.revocation = denylist`, have resource servers ask introspection, prefer CRLs or OCSP to `disabled` and `on-unavailable = reject` to `allow`, and lower `rp-logout.notify-within` only where a client that cannot be reached by then may keep its session.

## Boot

- **Guaranteed:**
  - In a production deployment (`kernel.environment`, `production` by default), boot refuses what each module declares a production deployment must not hold: a plain-http public origin or issuer, a page on a loopback host over plain http, an `http://localhost` WebAuthn origin. A declaration that throws refuses its module, never showing what it threw.
  - The app serves nothing while any setting is refused. Every refusal is reported at once, by setting path.
  - Key material has no default.
  - A sample value left in place (`REPLACE-…`) is refused.
- **Left to you:**
  - Keeping the configuration files and environment that hold secrets readable only by the app.
  - Setting `kernel.environment = development` only to try the provider on one machine. Production still takes plain http on a loopback host for an upstream identity provider's browser endpoints, and loopback and private-use redirect and logout URIs for clients.

## Secrets and logs

- **Guaranteed:**
  - A refusal or a log line names a setting, an error's kind or a key path, never a value.
  - The Redis URL, an `Authorization` value, a proxy's credentials, session attributes and outbound answers' bodies are never logged.
  - A secret given as bytes (a sealing key, the DPoP nonce's key) must be strict base64 with at least 8 distinct byte values. The HS256 signing secret is read as `keys.signing.secret-encoding` names (hex, base64 or utf8), and a ledger's `credential` is an RFC 6750 b64token; each needs at least 8 distinct byte values however read, as the `keys` card says.
- **Left to you:** where logs go and who can read them.

## Requests and proxies

- **Guaranteed:**
  - The public origin comes only from configuration, never from `Host` or forwarded headers.
  - `X-Forwarded-For` is followed only from a peer in `http.trusted-proxies`, and at most `http.proxy-hops` deep. The forwarded scheme is taken only as a single value from a trusted peer. `Forwarded` is never read.
  - A forwarded client certificate is read only from a trusted peer.
  - Security headers (CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy: no-referrer`) are set on every answer the app writes. Node's own `400`, `408` and `431`, to a request it cannot read or that comes too slowly, carry none.
- **Left to you:**
  - Terminating TLS. The app speaks plain HTTP behind your proxy; an http public origin needs `http.insecure-origin = true`, which a production deployment refuses, so only with `kernel.environment = development` ([Boot](#boot)).
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
  - Every request that changes state needs same-origin evidence or the double-submit token. An `Origin` or `Referer` naming another origin refuses it with 403, even with the token.
  - Every route declares whether it changes state, and one that does either uses a policy that keeps other sites' requests out and one that limits each source, or says why not; boot refuses a route that does neither. The [route reference](routes.md) lists each route's. A declaration is its owner's claim, not a proof.
  - Revoking a subject's sessions closes each of them.
  - With second factors composed, `mfa-entry` holds sessions to them: under `mfa.mode = required` using a session needs one, and changing credentials needs one proven recently (or a recent sign-in while none is held). Every credentials entry first reads the subject's factors, judged against the witness, so a factor store that cannot answer makes every credentials route unavailable, witness or not. `mfa` refuses to boot without it, whatever the mode, so no app holds factors that sessions are not held to.
- **Left to you:**
  - Keeping other subdomains of your origin from being taken over: double submit relies on them being unable to set the cookie.
  - Ending sessions with revocation, not by waiting out their lifetime, when they must end now.
  - The pages you serve (`authorize.login-page`, `consent.page`, the step-up pages and federation grants' pages): the provider draws none of them. Escaping what they show, from its answers (a client's name, the scopes asked) and from their URL, and the headers they are served with (a content security policy, framing), are yours.

## Tokens

- **Guaranteed:**
  - With `tokens.revocation = denylist`, a revoked token is refused wherever it is checked.
  - A revocation is answered only once it is stored where it survives a crash and a failover.
  - An outage answers 503, never "inactive" and never a success.
- **Session tokens:** when a session holds more tokens than the store keeps, the oldest is pushed out and revoked. A session near its cap is listed before the add, so a crash leaves it to the sweep; only more concurrent adds than `session-tokens.push-out-margin`, together with a crash, can leave a pushed-out token alive until it expires.
- **Left to you:**
  - Choosing `tokens.revocation`. With `unsupported`, nothing issued can be revoked, and boot refuses a composition that issues refresh tokens or codes.
  - With `subject-check = none`, a revoked subject's access tokens live until they expire.
- **Claims a grant adds:** a grant may add claims to the access tokens it issues (`AccessGrant.claims`). The signature covers the whole token, so a resource server cannot tell which claims the provider wrote and which a grant added. Reserved names only keep a grant from overwriting what the provider writes and what a specification gives a meaning; they make no added claim trustworthy. An added claim is what the grant composed asserts: composing a grant entrusts it with what its tokens say. Only `tokens` signs an access token (`at+jwt`); `keys.sign` refuses that type, and `keys.verify` too, so every access token is checked by `verifyAccess`. `verifyAccess` refuses as none of its own a token whose `exp` comes before its `iat`, whose `iat` is over 60 seconds ahead of the clock, or with over a day between them.
  - A refreshed or exchanged token carries no added claim, so an added claim cannot carry a restriction that must hold on: a resource server never reads a missing one as no restriction.

## Client authentication

- **Guaranteed:**
  - A client assertion (`private_key_jwt`) is taken only when its `aud` is the issuer identifier as one string, at every endpoint that authenticates clients, judged before its `jti` is spent. An assertion a client made for another authorization server that names this server's token endpoint is refused (FAPI 2.0 Security Profile §5.3.2.1).
  - Each assertion is taken once per client and `jti`.
- **Left to you:**
  - `sections.client-assertion.accept-loose-audience`, set for a client still sending the token endpoint's URL or a list as `aud`. While it is set, an assertion that client gave another authorization server naming this server's token endpoint can be used here first, within what the client is allowed, client credentials included. Each such assertion is logged as the warning `client-assertion.loose_audience`; remove the setting once that client sends the issuer.
  - Clients putting the issuer identifier they checked, as one string, in their assertions' `aud`, and checking that the `issuer` of the metadata they discover is the URL they asked for (FAPI 2.0 Security Profile §5.3.3.1). Checking the issuer does not keep a malicious server's metadata from naming another server's endpoints; the issuer as `aud` does.

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
- **id_tokens as JWT bearer assertions (`jwt-bearer-id-tokens`, opt-in):** the same checks, record and holder rule as the exchange, for the issuers `jwt-bearer.delegated-issuers` names; their audience is the app, so this is not RFC 7523 §3. A public client with `sections.jwt-bearer.accept-unbound` takes an id_token naming no key without a proof: a leaked one can be used once, before its owner, while it is still taken (up to `max-age` and `clock-skew` past its `iat`, and before its `exp`), for a token bound to no key. Each such client is logged at boot, and each assertion so taken.
- **Trusted issuers of JWT bearer assertions (`jwt-bearer`):** an issuer whose every signer becomes a subject (`as-is`, its keys written or a key set) makes a token for any `sub` it signs, so a key several organisations share signs for all of them. Such an entry boots only with `conditions` its assertions' verified claims must meet, checked after the signature and before the `jti` is used up, or with `accept-any-subject = true`, warned at each boot. A `ceiling` narrows its tokens within the client's allowance.
- **A JWT bearer grant naming no client (`jwt-bearer`, an entry's `client`, opt-in):** the assertion is the request's only credential, for the one registered client with no credentials its entry names. Its entry boots only with `conditions`, with its subjects bound by a link or a key's thumbprint, or with its keys contributed by a module that answers each signer's own keys alone (`perSigner: true`, as `signer-keys-http` declares): `accept-any-subject` cannot stand in. The entry and its client are bound both ways, so no other client takes its assertions and it takes no other's, and a request naming no client is answered alike for whatever fails before its subject is taken.
- **Left to you:** mapping an upstream value to a local amr in `federation.idps.<name>.upstream-amr` (to `mfa`, say) trusts that IdP's claim for the amr, and for any acr it meets (such as `urn:o3co:acr:mfa`); a login whose amr holds `mfa` passes the local second factor unasked. Map only what you trust the IdP to have checked.

## Outbound requests

- **Guaranteed:**
  - No host is reached by name unless `outbound.allow` lists it or `outbound.allow-any-public` is set. `outbound.deny` is checked first.
  - A name is resolved once, every address it resolves to is checked, and the request connects only to a checked address. For plain http to a `host:port` in `outbound.plain-ipv4`, the name is resolved for IPv4 addresses alone: every one of those is checked, and IPv6 addresses are neither checked nor reached.
  - Loopback, link-local, the cloud metadata addresses, Azure's platform address (`168.63.129.16`) and other special-purpose addresses are never reached, but loopback ones over plain http at a `plain-loopback` or `plain-internal` pair the operator names.
  - Private addresses are reached only by URLs a module takes from your own configuration and names so (the audit-http collector, the users-http, mfa-witness-http, passkey-witness-http and signer-keys-http ledgers, an OpenID Connect IdP's issuer and the endpoints you give it, a GitHub Enterprise's endpoints: the modules `outbound-policy`'s `internalBy` names), at hosts in `outbound.internal-hosts`, or over plain http at a `host:port` in `outbound.plain-internal`, where every address the name resolves to (every IPv4 one, for a pair in `outbound.plain-ipv4`) must be private or loopback. Each is reached only at that URL's origin: an endpoint an IdP's description names on another origin reaches public addresses only.
  - Redirects are refused, and only https is used, except plain http to a named `plain-loopback` or `plain-internal` pair, and signed material (whose signature is checked), fetched from its caller's named hosts.
  - Proxy environment variables are never read.
  - An IdP's authorization and end-of-session endpoints, where the browser goes and outbound never does, are https, or plain http only at a loopback name or, for an OpenID Connect IdP or a GitHub Enterprise, at the origin of an issuer or endpoint of your own configuration that `outbound.plain-internal` names; any other refuses boot. Plain http there carries the user's password and the IdP's cookies in the clear between the browser and the IdP, which the browser reaches by its own resolver, outside any mesh.
- **Left to you:**
  - With `outbound.proxy` set, the proxy resolves names and checks where they lead (boot warns so). The proxy's own name is resolved by `outbound`, within the request's deadline.
  - Names resolve in helper processes that take none of the environment but the resolver's own variables, and answer addresses alone (`outbound.resolution = helper`, the default). A helper is started only in the one form guard G26 lets through.
  - What goes to a `plain-internal` pair, passwords, tokens and credentials among it, is in the clear: name only peers on a network trusted against reading and changing it (each boot warns `outbound.plain_internal`).
  - Name a pair in `outbound.plain-ipv4` only where its IPv4 answers are the ones to reach, as ECS Service Connect's are: the name's IPv6 answers are not used.
  - Network egress filtering is still expected.

## Storage

- **Guaranteed:**
  - Data that must never be lost is kept only where Redis is checked to keep it: no eviction, an append-only file written on every command, and, with replicas, every replica holding it before it counts. This does not hold where the operator states `redis.durability = none` or `redis.replication = none`, accepting that a crash or a failover can lose the latest writes.
  - An outage or an unknown outcome is unavailable, answered 503, and never read as "absent" or "allowed". A record a store answers as missing is read as truly missing (a subject never revoked, for one), because a failing store throws rather than answering, and the spaces kept without end are never evicted.
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
  - Stored secrets (TOTP secrets, the upstream tokens `federation-tokens` keeps, delegated credentials) are sealed by `seal`, with AES-256-GCM; a held login's upstream tokens too, where the default `upstream-handoff-seal` is composed.
- **Left to you:**
  - Rotating keys as the [runbook](runbook.md#rotating-the-signing-key) describes.
  - The strength of a sealing of your own, contributed to `upstream-handoff`'s `handoffSealing` in place of `upstream-handoff-seal`.
  - Retiring a sealing key only after a `reseal` run that exited 0, as the [runbook](runbook.md#rotating-the-sealing-key) describes. A value a removed key still sealed becomes unavailable until the key is put back.
