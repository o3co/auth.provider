# @o3co/auth-provider-foundation

Production HTTP user-authentication adapter for auth.provider. Registers the `"http"` adapter type into a `UserRepository` factory, which delegates `authenticate` / `authenticateByToken` to an upstream HTTP service.

This package's scope is **production non-database / external-service adapters** for the v0.5.0 module system. As of v0.5.0 it ships exactly one such adapter (`HttpUserRepository`); the previous Redis `CodeRepository` adapter was relocated to [`@o3co/auth-provider-redis`](../redis/README.md) in Phase 10.

## Install

```sh
npm install @o3co/auth-provider-foundation
# Peer dependency (required):
npm install @o3co/auth-provider-core
```

## Public API

### `registerBuiltinAdapters`

Registers the `"http"` adapter type into the provided `userFactory`.

```typescript
function registerBuiltinAdapters(factories: {
  userFactory: AdapterFactory<UserRepository>;
}): void;
```

For Redis-backed code storage, register the builder from `@o3co/auth-provider-redis` directly:

```typescript
import { redisCodeRepositoryBuilder } from "@o3co/auth-provider-redis";
codeFactory.register("redis", redisCodeRepositoryBuilder);
```

### `HttpUserRepository`

A `UserRepository` implementation that delegates authentication to an upstream HTTP service.

```typescript
class HttpUserRepository implements UserRepository {
  constructor(options: {
    authenticateUrl: string;        // POST endpoint for username/password auth
    authenticateByTokenUrl: string; // POST endpoint for token-based auth
    linkFederatedIdentityUrl?: string; // POST endpoint that links a federated identity (#482)
    findSubjectByFederatedIdentityUrl?: string; // POST endpoint that says who holds an upstream identity (#613)
    federatedIdentityLookupCoverage?: FederatedIdentityLookupCoverage[]; // what that lookup covers (#613)
    timeout: number;                // request timeout in milliseconds
    maxResponseBytes?: number;      // response body cap, default 1 MiB
  });

  // POST authenticateUrl with body: { email, password }
  authenticate(username: string, password: string): Promise<User | null>;

  // POST authenticateByTokenUrl with body: { token }
  authenticateByToken(token: string): Promise<User | null>;

  // POST linkFederatedIdentityUrl with body: { userId, provider, sub, token, claims }
  // — present only when the URL is configured (#482)
  linkFederatedIdentity?(userId: string, identity: FederatedIdentityLink): Promise<LinkFederatedIdentityResult>;

  // From the coverage declaration alone; the Store is not asked (#613).
  // Present together with the lookup, only when its URL is configured.
  supportsFederatedIdentityLookup?(registration: { provider, issuer, clientId }, identityClaims: string[]): boolean;

  // POST findSubjectByFederatedIdentityUrl with body: { provider, issuer, clientId, sub, claims }
  findSubjectByFederatedIdentity?(identity: FederatedIdentityLookup): Promise<FederatedIdentityLookupResult>;
}
```

For `authenticate` and `authenticateByToken`:

- Returns `null` on HTTP 401 or 403.
- Throws an error on any other non-OK HTTP status.
- Throws when the upstream returns 2xx with a body that is not a JSON `User`
  (`{ id: string, username: string, … }`) — an upstream failure, not a
  "user not found".
- `linkFederatedIdentity` (#482): a `2xx` `User` is `{ ok: true, user }`;
  `401` / `403` is `{ ok: false, reason: "refused" }`; `409` is
  `{ ok: false, reason: "conflict" }`; anything else throws. The method is
  absent when `linkFederatedIdentityUrl` is not configured, which is how the
  federation routes know to refuse `?link=1` up front. What a Store checks
  before answering `2xx` — never on an unverified or relay address, never by
  e-mail alone — is in the
  [session package README](../session/README.md#account-linking-across-federations-482).

#### The identity lookup (#613)

What a federation-grant deployment (`@o3co/auth-provider-federation-grants`,
D7 check 5) asks of the Store: who holds an upstream identity, so that a
delegation is refused when the account belongs to another local user. The
Store answers about ownership across **every** registration of the IdP, not
only the one the identity came through — a login links under the federation
the user signed in through, and an IdP whose `sub` is pairwise per app
registration (Entra's is) gives the same person another `sub` under each. For
D19's separate grants registration, that means: to answer `unlinked`
honestly, your Store must resolve the verified `(tid, oid)` against an
authoritative directory complete for the relevant tenant and all local
ownership links across registrations; no match in a partial directory or an
unfamiliar identity is `identity_not_resolvable`, and multiple distinct local
owners are a server error. Declaring coverage attests to that strategy; boot
neither discovers nor proves the remote directory's completeness.

The request is `POST findSubjectByFederatedIdentityUrl` with

```json
{ "provider": "entra-files", "issuer": "https://login.microsoftonline.com/<tenant>/v2.0",
  "clientId": "<the grants app registration>", "sub": "<verified sub>",
  "claims": { "tid": "<verified>", "oid": "<verified>" } }
```

— the registration exactly as the connection is configured, the verified
`sub`, and every claim the connection's `identityClaims` named (verified,
from the id_token; `{}` when it named none). The lookup must change nothing:
no login stamped, no link made, no user provisioned. The answer is a `2xx`
JSON body, one of

| Body | Meaning |
|---|---|
| `{ "kind": "linked", "subject": "<local User.id>" }` | exactly one local user holds it. `subject` is that user's `id` **byte for byte** — the callback compares it with the signed-in user's `sub` exactly, so a padded or otherwise normalised id reads as another user's |
| `{ "kind": "unlinked" }` | a **complete** resolution found nobody |
| `{ "kind": "indeterminate", "reason": "registration_not_covered" }` | no strategy for this registration |
| `{ "kind": "indeterminate", "reason": "identity_not_resolvable" }` | a strategy, and this identity is not in it |

Fields beyond those are ignored. **Everything else is an outage, never
"nobody"**: any status but a `2xx` — `404`, `401`, `403`, `409`, `5xx` — a
`2xx` whose body is empty or not one of the four, a redirect (never followed:
the body carries a verified identity), a timeout, or a body over the cap all
throw, and the callback answers `temporarily_unavailable`. More than one
distinct local owner is a `500` from the Store. What is thrown names the
endpoint — and, for an answer with a status, the status — never the body,
the identity, a status text or an underlying cause.

**Coverage.** The probe the grants module asks at boot is synchronous and
cannot reach the Store, so `federatedIdentityLookupCoverage` relays what the
Store's lookup covers: one entry per registration,
`{ provider, issuer, clientId, requiredClaims }`, all four fields, compared
exactly (no trimming, no case folding, no trailing-slash tolerance), and
`requiredClaims` the claim names the strategy needs — `[]` for one on the
registration and `sub` alone. `supportsFederatedIdentityLookup(registration,
identityClaims)` is `true` when an entry equals the registration and every
`requiredClaims` name is among `identityClaims`; the grants module refuses at
boot every connection it is `false` for. A registration nobody declared is
answered `registration_not_covered` locally, and a declared one arriving
without a required claim `identity_not_resolvable`, with no request either
way. The declaration is snapshotted at construction; a duplicate registration,
a malformed entry, or coverage without the URL is a construction error. It has
no environment-variable form (a list is HOCON's), as `federationGrants.connections`
has none.

### Constructor validation

Every option is validated in the **constructor**, so a misconfigured deployment
fails at boot rather than at the first login attempt.

**Every URL must use `https://`** (the link and lookup endpoints included). They carry plaintext user credentials — a
password on `authenticateUrl`, a token on `authenticateByTokenUrl`, a verified
upstream identity on `findSubjectByFederatedIdentityUrl` — so an
`http://` URL does not merely weaken the connection, it publishes the credential
to every hop on the path.

**The one carve-out is loopback:** `http://` is accepted when the host is
`localhost`, an address in `127.0.0.0/8`, or `[::1]`. That traffic never leaves
the machine, so local development and in-process test fixtures need no
certificate. Every other host must use `https://`, **including private-range
addresses and container-network service names** (`http://10.0.0.5/…`,
`http://user-service/…` are refused): those cross a network the deployment does
not control end to end, and "internal" is not a synonym for "encrypted". URLs
embedding credentials (`https://user:pass@…`) are refused as well.

This is the same rule `oauth.jwt.issuer` applies in
[`@o3co/auth-provider-core`](../core/README.md), with the carve-out widened from
the single address `127.0.0.1` to the whole `127.0.0.0/8` block, and query
strings allowed (an issuer may not carry one; a POST endpoint legitimately may).

**`timeout` must be a positive integer** no greater than `2147483647`
milliseconds. `0`, a negative number, and `NaN` all clamp to "fire immediately"
in `setTimeout` — which would abort every request — and a value above Node's
timer range clamps to 1ms, turning "be patient" into the most impatient setting
available. The deadline covers the whole exchange, **body included**: the body
read is raced against it rather than relying on the abort signal, because
aborting a request does not reliably interrupt a read already in flight. That is
the slow-loris shape — headers arrive promptly, then the body dribbles or stops
— and without the race it hangs forever. A request that outlives the deadline
rejects with a `timed out after <n>ms` error naming the endpoint.

**`maxResponseBytes` must be a positive integer**, defaulting to
`DEFAULT_MAX_RESPONSE_BYTES` (1 MiB). The cap is enforced against
`Content-Length` *and* while streaming, so a Store that omits the header — or
lies in it — is still cut off rather than allowed to exhaust memory.

## Usage Example

```typescript
import { createRepositoryFactories } from "@o3co/auth-provider-core";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";

const { userFactory } = createRepositoryFactories();

registerBuiltinAdapters({ userFactory });

// Create an HTTP user repository via the factory
const userRepo = await userFactory.create({
  type: "http",
  authenticateUrl: "https://users.example.com/authenticate",
  authenticateByTokenUrl: "https://users.example.com/authenticate-by-token",
  timeout: 5000,
});
```

## See Also

- [`@o3co/auth-provider-core`](../core/README.md) — Core interfaces (`UserRepository`, `CodeRepository`, `AdapterFactory`, `createAdapterFactory`, `BuilderContext`, `PathResolver`)
- [`@o3co/auth-provider-redis`](../redis/README.md) — Redis-backed adapters (challenges, replay-seen-set, refresh-token-family, user-sessions, federation-tokens, **code-repository**, rate-limiter)
- [auth.provider](../../README.md) — Top-level repository documentation
