# @o3co/auth-provider-federation-grants

Federation grants for [`auth.provider`](https://github.com/o3co/auth.provider) — offline delegation of upstream access tokens (#593). A user consents once that a client may reach one upstream connection on their behalf; the client then obtains upstream access tokens over HTTP, later, with the user nowhere near a browser.

Optional. Nothing here is active until `federationGrants.enabled = true`.

> **Work in progress.** Both routes are here; the Redis-backed integration coverage and the ADR amendments land in the commit that follows.

## Install both modules

```ts
import { federationGrantsModules } from "@o3co/auth-provider-federation-grants";
import { memoryFederationGrantStoreModule } from "@o3co/auth-provider-core";

const app = await createApp({
  modules: [...federationGrantsModules, memoryFederationGrantStoreModule],
  bootstrapComponents: { config, clientRepository, keyStore },
});
```

`federationGrantsModules` is a pair: the routes, and the background registry a shutdown drains. They are separate manifests because their dependency edges point in different directions — see below — and mounting the routes without the registry is a boot refusal rather than a shutdown that quietly drops rotated credentials.

The grant store is a separate module again, because a store is what a deployment installs whether or not it mounts these routes: a logout and a subject-wide revocation reach grants through the same port. `memoryFederationGrantStoreModule` is single-replica only; a scaled deployment wires `redisFederationGrantStoreModule` from `@o3co/auth-provider-redis`.

## A disabled deployment is indistinguishable from an uninstalled one

`federationGrants.enabled` defaults to `false`, and while it is false both paths answer:

```http
HTTP/1.1 404 Not Found
Cache-Control: no-store
Pragma: no-cache
x-request-id: 4f1e…

{"error":"not_found"}
```

No description, deliberately. A body naming the feature would tell an unauthenticated caller that this deployment could do offline delegation if someone flipped one key. Nothing on that path parses a body, authenticates a client or reads a store either, so there is no timing to measure it by — and a deployment that leaves the feature off needs none of the components it would need to turn it on.

What it is **not** is byte-identical to a deployment that never installed the package: there, nothing matches the path at all and the host's own fallback answers — Express's HTML 404 in a bare composition. Review measured the difference and it is the headers and the content type, not the body. So the property this actually has is the one worth having: the refusal names no feature, and nothing behind it runs. A deployment that wants the two indistinguishable gives its host a JSON 404 of its own.

## The two routes

Both are `POST`, both are authenticated as a confidential client
(`client_secret_basic`, `client_secret_post` or `private_key_jwt`), and both
take the grant id as an opaque path segment.

### `POST /oauth/federation-grants/:grantId/token`

```json
{ "sub": "local-subject", "min_ttl": 60, "connection": "graph", "scope": "openid Files.Read" }
```

`sub` is required and compared exactly. The rest are *assertions*: things the
caller claims about the grant, which are checked and never widen anything —
asking for a scope the grant does not carry is a refusal, not a request.
`min_ttl` asks for a refresh; it does not turn a short token into an error.

A success is an ordinary OAuth token response carrying the **upstream's**
access token, its own spelling of `token_type`, and the scopes that token
holds. There is never a refresh token, an id token or an upstream response
object in it.

Everything else is `{"error": "<code>"}` with an `"error_description"`
alongside it wherever the failure has a reason to give — `grant_not_found`,
`invalid_scope`, `invalid_target` and `authorization_pending` have none, and
carry the code alone. Both fields are **identifiers, not prose**: a client may
switch on them. The status
says what kind of problem it is: `400` the caller's, `403` the client's
registration, `404` no such grant of theirs, `410` the user must be asked
again, `429` slow down, `502` the upstream, `503` come back. `Retry-After` is
present whenever the answer knew when — including on `502` and `503`, not only
on `429`.

An unknown grant id, a grant belonging to another client and one belonging to
another subject all answer the same `404` body, byte for byte.

### `POST /oauth/federation-grants/:grantId/status`

```json
{ "sub": "local-subject" }
```

`sub` and nothing else; the token route's assertions are refused here rather
than ignored. A successful inspection answers `200` for **every** effective
status, expired and revoked included — a grant that is over is not a failed
call — with the grant's lifecycle, its upstream account, the scopes consented
to and its dates in UTC.

`expires_at` is **effective** expiry, computed from `maxExpiresIn` as it is
configured now. Lowering the maximum therefore moves it earlier for grants that
already exist, possibly into the past; raising it moves it back, never beyond
the stored expiry, which never changes.

Status calls `inspect` and nothing else: never a refresh, never the refresh
lock, never `touch`. It is also **not** a health check for `/token` — `active`
does not promise a token, and an ineligible status can sit beside a perfectly
usable cached one.

## Install these modules before `oauthModule`

These routes live under `/oauth`, and `oauthModule` mounts its own router there
whose first two middlewares are `express.json()` and `express.urlencoded()`
with the library's defaults. Express runs route contributions in mount order,
so when that router is mounted first it sees `/oauth/federation-grants/...`
requests before this one does — and `body-parser` does not parse a body twice.

What that costs, and what it does not:

- **It does not cost the body limit.** The 16 KiB bound is checked from
  `Content-Length` ahead of the parsers, so it holds whatever else is mounted.
- **It does cost one exit.** A body that is not valid JSON is rejected by
  whichever parser reaches it first. Mounted second, that is the OAuth
  router's, and its refusal carries neither this package's `x-request-id` nor
  its `Cache-Control: no-store`, and does not pass this package's throttle.

So list `federationGrantsModules` ahead of `oauthModule` at the composition
root. This package deliberately does not declare a `before` edge against the
OAuth router's id: that would refuse to boot for every deployment that runs
federation grants *without* `/oauth/token`, which is a perfectly ordinary thing
to want.

## `x-request-id`

Every response this package produces carries one: the caller's when it matches `[A-Za-z0-9._:+/=#-]{1,128}` and arrived exactly once, a fresh UUID otherwise. An unusable value is *replaced*, never trimmed into a usable one.

It is caller-controlled correlation metadata and nothing else — not authentication, not an idempotency key, not a lock key, not a trusted identifier of a person. Its job is that a credential rotation persisted *after* the response was sent can still be tied to the request that started it.

## Shutting down without losing a rotated credential

A refresh against an upstream is not finished when the HTTP response is. The provider may still be letting go of a refresh lock, writing down a refresh token the upstream has already rotated to, or telling the audit sink what happened — and if the caller was answered at the soft deadline, the refresh itself is still running, holding its lock until its result is persisted.

`federationGrantBackgroundModule` provides the per-application registry that holds all of it, and its cleanup drains: it refuses new operations, then waits for every admitted request and registered promise, rechecking as finishing work registers more.

It is a **component** rather than a `lifecycleRegistrar` callback because `AppHandle.dispose()` runs component cleanups first and registrar callbacks afterwards — a drain registered there would run after the store's own cleanup, and an adapter that closes its client there would pull the connection out from under the write being waited for. The registry's `optional` edges on `federationGrantStore`, `subjectRevocation` and `auditSink` order it after all three at boot, and therefore before all three at shutdown.

What it is not: durable job execution, guaranteed audit delivery, or protection against `SIGKILL`. It bounds nothing by itself — core bounds its own waits, and an adapter whose read can hang needs its own I/O timeout.

And there is one thing it cannot wait for, by core's design rather than by omission: the wait for a refresh lock the call gave up on is kept outside the registry, because it may never end. If that lock arrives after the drain has finished, its release is registered into a registry nobody is waiting for. No answer and no credential is lost; what is left is a lock nobody released, which stands for its `refreshLockTtlMs` while other replicas answer `503 temporarily_unavailable/lock_timeout` for that one grant. A larger cleanup allowance does not help — the drain has already returned. A store whose lock acquisition is bounded does.

### Give the host enough cleanup allowance

A deployment mounting this package wants **at least 45 seconds** of cleanup allowance. The standalone template's default is ten, which is shorter than the upstream hard timeout and persist budget this feature ships with, so a shutdown would abandon exactly the write the drain exists to wait for. HTTP draining and the orchestrator's termination grace are sized separately, and both have to be longer again.

## License

Apache-2.0
