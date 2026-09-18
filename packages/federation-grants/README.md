# @o3co/auth-provider-federation-grants

Federation grants for [`auth.provider`](https://github.com/o3co/auth.provider) — offline delegation of upstream access tokens (#593). A user consents once that a client may reach one upstream connection on their behalf; the client then obtains upstream access tokens over HTTP, later, with the user nowhere near a browser.

Optional. Nothing here is active until `federationGrants.enabled = true`.

> **Work in progress.** This commit ships the package, its shutdown drain, and the routes a *disabled* deployment mounts. The token and status routes land in the commits that follow; this file grows with them.

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

## `x-request-id`

Every response this package produces carries one: the caller's when it matches `[A-Za-z0-9._:+/=#-]{1,128}` and arrived exactly once, a fresh UUID otherwise. An unusable value is *replaced*, never trimmed into a usable one.

It is caller-controlled correlation metadata and nothing else — not authentication, not an idempotency key, not a lock key, not a trusted identifier of a person. Its job is that a credential rotation persisted *after* the response was sent can still be tied to the request that started it.

## Shutting down without losing a rotated credential

A refresh against an upstream is not finished when the HTTP response is. The provider may still be letting go of a refresh lock, writing down a refresh token the upstream has already rotated to, or telling the audit sink what happened — and if the caller was answered at the soft deadline, the refresh itself is still running, holding its lock until its result is persisted.

`federationGrantBackgroundModule` provides the per-application registry that holds all of it, and its cleanup drains: it refuses new operations, then waits for every admitted request and registered promise, rechecking as finishing work registers more.

It is a **component** rather than a `lifecycleRegistrar` callback because `AppHandle.dispose()` runs component cleanups first and registrar callbacks afterwards — a drain registered there would run after the store's own cleanup, and an adapter that closes its client there would pull the connection out from under the write being waited for. The registry's `optional` edges on `federationGrantStore`, `subjectRevocation` and `auditSink` order it after all three at boot, and therefore before all three at shutdown.

What it is not: durable job execution, guaranteed audit delivery, or protection against `SIGKILL`. It bounds nothing by itself — core bounds its own waits, and an adapter whose read can hang needs its own I/O timeout.

### Give the host enough cleanup allowance

A deployment mounting this package wants **at least 45 seconds** of cleanup allowance. The standalone template's default is ten, which is shorter than the upstream hard timeout and persist budget this feature ships with, so a shutdown would abandon exactly the write the drain exists to wait for. HTTP draining and the orchestrator's termination grace are sized separately, and both have to be longer again.

## License

Apache-2.0
