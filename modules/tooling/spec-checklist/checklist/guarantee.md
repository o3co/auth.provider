# Guarantees

- source: docs/security-model.md#promises-across-modules
- fault Pu: the network from the app to Redis is cut one way.
- fault Pd: the network from Redis to the app is cut one way.
- fault R: the app's connection to Redis is closed.
- fault L: Redis answers later than the command timeout.
- fault S: Redis is slow to run commands.
- fault Lr: a write's success answer is lost once, and the store's retry with the same mark receives it.
- fault Lx: a write's success answer is lost, and every retry's for the whole retry window too.
- fault F: a replica that has caught up is promoted, and every connection moves to it.
- fault Fs: after a failover, the app's operations go to the new primary while its confirmations stay on the old one.
- fault C: Redis is killed at once (SIGKILL).
- fault K: the app is killed after a write succeeds and before it answers.
- fault H2: two app instances act on the same thing at once.
- fault M: Redis runs out of its bounded memory and refuses writes.
- fault Ev: Redis is set to evict keys.
- fault R0: `redis.replication = replicas` is chosen and Redis has no replica.
- fault Wt: a write's confirmation by the replicas times out.
- fault Nr: Redis refuses a write as `NOREPLICAS`.
- fault Ta: the app's clock is moved forward or back.

## 1 Closing a session closes every path for the tokens issued from it.

- **guarantee-1-a** MUST: a session left closing, with participants not yet done, is closed by its logout or a later sweep, and once closed no path is left open for the tokens issued from it, but for a session the cap pushed out while a store outage kept it from closing, declared in design.md's Decisions: it ends without its participants or a back-channel notice, and its access tokens live until they expire, at most to the session's own end; a logout that cannot finish answers `503`, never logged out.
  faults: Lr, Lx, F, Fs, C, K, H2

## 2 `prompt=login` and `max_age` are met only by a fresh authentication.

- **guarantee-2-a** MUST: a request with `prompt=login` is met only by an authentication made for it, by `reauth`'s record, which `authorize` makes for the request and takes once.
- **guarantee-2-b** MUST: a request with `max_age` is met only by an authentication within it, checked as the last step before the code is issued, after every step the request went through, consent included; re-reading the session and the client and writing the claims selection and the code after that check are not counted, the code carries the authentication time checked (a session's does not change), and redemption adds at most the code's lifetime. `max_age=0` is met as `prompt=login` is, by an authentication made for the request (guarantee-2-a). An authentication time `session` does not know never counts as fresh.
- **guarantee-2-c** MUST: through an upstream, the callback takes a login only where the time the upstream reports for it is within its fresh login allowance, `federation.idps.<name>.fresh-login-allowance` (its `clock-skew` by default): for `prompt=login`, no further back than the allowance before the demand, compared in whole seconds; for `max_age`, where `auth_time + allowance + max_age >= now`, compared to the millisecond. The session keeps the upstream's time, lifted to the round trip's start where it is within the allowance before the start's second, and the ID token's `auth_time` is that time; the code is issued only where that time is within `max_age`, checked as the last step before the code is issued with no allowance added (guarantee-2-b), and a later request in the same session is measured from it the same way.

## 3 A dependency that cannot answer never grants anything.

- **guarantee-3-a** MUST NOT: the authorization endpoint issues a code while a dependency its decision waits on cannot answer; until it has found the browser's session it sends the client no outage's answer and answers `503` `temporarily_unavailable` itself, for `prompt=none` too; once it has, it answers the client `error=temporarily_unavailable` at the redirect URI. A silent request's refusals before the session (`invalid_scope`, a repeated parameter, an unknown `reauth`) are no outage's answer: they go to the redirect URI without the session read, as `authorize`'s refusals do. A client's own metadata document is no dependency its decision waits on: fetched from the client's host, a fetch that fails is no client (`clients-cimd`), not unavailable.
  faults: Pu, Pd, R, L, S, F, Fs, C
- **guarantee-3-b** MUST NOT: the token endpoint issues a token for a code while a dependency its decision waits on cannot answer.
  faults: Pu, Pd, R, L, S, F, Fs, C
- **guarantee-3-c** MUST NOT: the token endpoint issues a token for a refresh token while a dependency its decision waits on cannot answer.
  faults: Pu, Pd, R, L, S, F, Fs, C
- **guarantee-3-d** MUST NOT: the token endpoint issues a token for a JWT bearer assertion while a dependency its decision waits on cannot answer.
  faults: Pu, Pd, R, L, S, F, Fs, C
- **guarantee-3-e** MUST NOT: the token endpoint issues a token for a device code while a dependency its decision waits on cannot answer.
  faults: Pu, Pd, R, L, S, F, Fs, C
- **guarantee-3-f** MUST NOT: a password login opens a session while a dependency its decision waits on cannot answer.
  faults: Pu, Pd, R, L, S, F, Fs, C
- **guarantee-3-g** MUST NOT: the token revocation endpoint answers that a token is revoked while a dependency it waits on cannot answer.
  faults: Pu, Pd, R, L, S, F, Fs, C
- **guarantee-3-h** MUST NOT: a request limit lets a request pass while its store cannot count, where `rate-limit.fail-mode = closed`; `open` is the operator's declared exception. No split confirmation is in it: the request windows ask no replication, so no confirmation round can split (rate-limit's card).
  faults: Pu, Pd, R, L, S, F, C
- **guarantee-3-i** MUST NOT: an attempt limit lets an attempt pass while its store cannot count, whatever `rate-limit.fail-mode` is.
  faults: Pu, Pd, R, L, S, F, Fs, C
- **guarantee-3-j** MUST NOT: a grant that keeps in the store what it issues or what issuing spends (a code redeemed, a refresh family rotated, a device code used, a JWT bearer assertion's or an exchanged id_token's use) issues anything while the store cannot write, and a request made after it can write again passes.
  faults: M, R0, Wt, Nr
- **guarantee-3-k** MUST NOT: the provider boots on a Redis set to evict keys.
  faults: Ev
- **guarantee-3-l** MUST NOT: the ledger's subject revocation route (`/ledger/subject-revocations`) answers `200` complete while a dependency it waits on cannot answer; it answers `503` with `state` `unknown` where the boundary's write was not confirmed, `incomplete` where the boundary is written and a follower did not finish, and with no `state` where its window could not count.
  faults: Pu, Pd, R, L, S, F, Fs, C
- **guarantee-3-m** MUST NOT: the provider reads a user ledger over HTTP (`users-http`) as knowing no such user from any answer but a `404` with `{"error":"not_found"}` or a `410` with `{"error":"gone"}`; an answer that is neither those nor the user, one it cannot read included, is unavailable. The password call's `401` that challenges no credential it sent is read as no such user too, a deprecated exception kept for 0.17's ledgers.

## 4 A subject's revocation boundary refuses everything made before it.

- **guarantee-4-a** MUST NOT: once a subject's boundary is written, a read from any instance lets through a session, a code, a refresh token, an access token or a session grant made before it; a revocation that cannot finish never answers done. One exception alone: where `tokens.subject-check = none` is chosen, an access token lives until it expires. A split confirmation is held by guarantee-5-a, the store's one path.
  faults: Lr, Lx, F, C, K, H2
- **guarantee-4-b** MUST NOT: once a subject's boundary is written, a read from any instance lets through a token from a device code approved before it. One exception alone: where `tokens.subject-check = none` is chosen, an access token lives until it expires. The boundary's write is the artifact of guarantee-4-a (subject-revocation's boundary) on the same path, so its faults are held there.
  faults: H2
- **guarantee-4-c** MUST NOT: once a subject's boundary is written, a read from any instance lets an established federation grant made before it answer. One exception alone: where `federation-grants.keep-on-subject-revocation` is set and a revocation asks to keep delegations, the grant answers only to the `delegations` boundary, which such a revocation leaves where it was. The boundary's write is the artifact of guarantee-4-a (subject-revocation's boundary) on the same path, so its faults are held there.
  faults: H2
- **guarantee-4-d** MUST NOT: once a subject's revocation is complete, a second factor's enrollment begun before it binds, or a session opened before it removes a factor or reissues recovery codes, read from any instance. The boundary's write is the artifact of guarantee-4-a (subject-revocation's boundary) on the same path, so its faults are held there.
  faults: H2
- **guarantee-4-e** MUST NOT: once a subject's boundary is written, a read from any instance lets through a token exchanged from a subject token made before it. The boundary's write is the artifact of guarantee-4-a (subject-revocation's boundary) on the same path, so its faults are held there.
  faults: H2

## 5 What is used once is used once, on any number of instances.

- **guarantee-5-a** MUST: an authorization code is redeemed once.
  faults: Lr, Lx, F, Fs, C, K, H2, Ta
- **guarantee-5-b** MUST: a refresh token is rotated once.
  faults: Lr, Lx, F, Fs, C, K, H2
- **guarantee-5-c** MUST: a JWT bearer assertion's `jti` is spent once.
  faults: Lr, Lx, F, C, K, H2
- **guarantee-5-d** MUST: a client assertion's `jti` is spent once.
  faults: Lr, Lx, F, C, K, H2
- **guarantee-5-e** MUST: a DPoP proof's `jti` is spent once.
  faults: Lr, Lx, F, C, K, H2
- **guarantee-5-f** MUST: a device code is decided and redeemed once.
  faults: Lr, Lx, F, C, K, H2
- **guarantee-5-g** MUST: a recovery code is used once.
  faults: Lr, Lx, F, C, K, H2
- **guarantee-5-h** MUST: a passkey challenge is used once.
  faults: Lr, Lx, F, C, K, H2
- **guarantee-5-i** MUST: a login lockout's count holds across a crash and a failover, each attempt counted once, the same on every instance.
  faults: Lr, F, C, K, H2
- **guarantee-5-j** MUST: an id_token is exchanged once, whether by the token exchange or as a JWT bearer assertion.
  faults: Lr, Lx, F, C, K, H2
- **guarantee-5-k** MUST: a passkey assertion's challenge is redeemed only by the requester it was made for: the module that asked, by its own name, and the id it asked for; another module's assertion with the same id is refused.

## 6 A token bound to a key or a certificate is never used as a bearer token.

- **guarantee-6-a** MUST NOT: a resource route takes a DPoP-bound or certificate-bound access token presented as a bearer token.
- **guarantee-6-b** MUST NOT: a refresh or a token exchange issues, from a bound token, a token that is not bound.

## 7 Every request to another server goes through `outbound`.

- **guarantee-7-a** MUST NOT: product code reaches the network other than through `outbound` or as its manifest's `network` declares, as far as the code's form shows it.

## 8 Secrets appear neither in logs nor in answers, but for what the provider hands out on purpose.

- **guarantee-8-a** MUST NOT: a refusal at boot shows a setting's value; it names the setting by its key path, and a contribution by its name (a route's method and path, a receiver's name), even where a setting chose the name (`metrics-prometheus.path`); a name is never a secret.
- **guarantee-8-b** MUST NOT: a log line carries a secret, credential, token, request body or header value, but for header values from a fixed set.
- **guarantee-8-c** MUST NOT: an audit event carries a token or a secret.
- **guarantee-8-d** MUST NOT: an answer carries a secret, but for tokens and codes to the one they are issued to, and a secret a registration shows once to its owner.

## 9 A browser route that changes state needs CSRF or origin evidence.

- **guarantee-9-a** MUST NOT: a browser route that changes state takes a request without CSRF or origin evidence, but where it declares why it takes other sites' requests.
- **guarantee-9-b** MUST NOT: the provider boots with a route that changes state and declares neither a policy marked `own-site` nor why it takes other sites' requests.

## 10 A `POST` taken before authentication is limited per source.

- **guarantee-10-a** MUST: a `POST` taken before authentication is limited per source, but where its route declares why it counts no source, and, where `rate-limit.fail-mode = open`, while a request limit's store cannot count; an attempt limit refuses then too.
- **guarantee-10-b** MUST NOT: the provider boots with such a route that declares neither a policy marked `per-source` nor why it counts no source.
