# @o3co/auth-provider-foundation

Last updated: 2026-09-24

The HTTP client of "the Store" — the deployment's own user service — for
auth.provider. `HttpUserRepository` implements core's `UserRepository` port over
HTTPS: it authenticates users, links federated identities, and answers the
identity lookup federation grants ask for. `registerBuiltinAdapters` registers
it as the `"http"` user adapter.

## Responsibility

**Role.** An adapter for one core port,
[`UserRepository`](../core/src/repositories/UserRepository.mts) (see
[`core/src/repositories`](../core/src/repositories/README.md)). Despite the
package name it is not a base layer: no other package imports it at runtime
(`federation-grants` uses it in a test). A composition root selects it —
`repositories.user.type = "http"` in the standalone template.

**Owns:**

- the wire contract a Store implements: the requests `HttpUserRepository` sends
  and what each answer means (below);
- the transport rules on the Store's URLs — `https`, or `http` to a loopback
  host only ([`src/endpointUrl.mts`](src/endpointUrl.mts)) — and that no
  request follows a redirect away from them;
- the request deadline and the response-size cap;
- the coverage declaration the identity lookup is judged by at boot.

**Does not own:** the port and the `User` shape (core); when a user is
authenticated, an identity linked or an owner looked up — the session routes
([`@o3co/auth-provider-session`](../session/README.md)), `oauth`'s jwt-bearer
grant ([`@o3co/auth-provider-oauth`](../oauth/README.md)) and federation grants
([`@o3co/auth-provider-federation-grants`](../federation-grants/README.md)); the
Store itself; core's development user adapters (`yaml` / `static`); Redis-backed
stores ([`@o3co/auth-provider-redis`](../redis/README.md), which also holds the
Redis authorization-code store).

**Why a separate package.** Core ships only development user adapters, read from
a file; a production deployment keeps its users in a service of its own, and
this is the client for one. It is the replaceable piece — a deployment with its
own `UserRepository` implementation does not install it — and it depends on
nothing but core (the global `fetch`, no other dependency).

## Install

```sh
npm install @o3co/auth-provider-foundation @o3co/auth-provider-core
```

`@o3co/auth-provider-core` is a peer dependency.

## Usage

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

`registerBuiltinAdapters` ([`src/index.mts`](src/index.mts)) registers the
`"http"` type on a `UserRepository` factory; the builder reads the keys below,
defaults `timeout` to 5000 ms and `maxResponseBytes` to
`DEFAULT_MAX_RESPONSE_BYTES` (1 MiB) when absent, and accepts numbers given as
strings (an environment override). `HttpUserRepository`
([`src/repositories/HttpUserRepository.mts`](src/repositories/HttpUserRepository.mts))
can also be constructed directly with the same options; there `timeout` is
required, since the 5000 ms default is the builder's.

### Configuration

Under `repositories.user` (`type = "http"`, `CLIENT_USER_TYPE`), in its `http`
block; defaults are in [`reference.conf`](../core/config/reference.conf):

| Key | Env | |
| --- | --- | --- |
| `authenticateUrl` | `CLIENT_USER_AUTHENTICATE_URL` | Required. Password login. |
| `authenticateByTokenUrl` | `CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL` | Required. Resolves an opaque handle: federated login, the jwt-bearer grant. |
| `linkFederatedIdentityUrl` | `CLIENT_USER_LINK_FEDERATED_IDENTITY_URL` | Optional. Enables account linking. |
| `findSubjectByFederatedIdentityUrl` | `CLIENT_USER_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL` | Optional. The identity lookup. |
| `federatedIdentityLookupCoverage` | — (a list; HOCON only) | What the lookup covers. Default `[]`. |
| `timeout` | `CLIENT_USER_TIMEOUT` | Milliseconds. Default 5000. |
| `maxResponseBytes` | `CLIENT_USER_MAX_RESPONSE_BYTES` | Default 1048576. |

## The wire contract

Every request is a `POST` with a JSON body. The user a Store answers with is
core's [`User`](../core/src/repositories/types.mts).

**`authenticate`** posts `{ email, password }` to `authenticateUrl` (the
username arrives as `email`); **`authenticateByToken`** posts `{ token }` to
`authenticateByTokenUrl`, where `token` is an opaque handle the Store resolves
to a user — `<provider>:<sub>` from the federation callback, the verified
assertion's subject handle from `oauth`'s jwt-bearer grant. For both:

- a `2xx` whose body is a JSON `User` (`{ id: string, username: string, … }`) is
  the user;
- `401` or `403` is `null` — no such user, or wrong credentials;
- a `2xx` with a body that is not a `User` throws — an upstream failure, not a
  "user not found";
- any other status throws.

The body of a non-`2xx` answer is discarded unread, for these and for linking.
No request follows a redirect, including the identity lookup: a `3xx` is one
more status that throws, and its `Location` is never contacted.

**`linkFederatedIdentity`** posts `{ userId, provider, sub, token, claims }` to
`linkFederatedIdentityUrl`: a `2xx` `User` is `{ ok: true, user }`; `401` / `403`
is `{ ok: false, reason: "refused" }`; `409` is
`{ ok: false, reason: "conflict" }`; anything else throws. Because the body of a
refusal is not read, a refusal carries no description from the Store. The method is absent
when `linkFederatedIdentityUrl` is not configured, which is how the federation
routes know to refuse `?link=1` up front. What a Store checks before answering
`2xx` — never on an unverified or relay address, never by e-mail alone — is in
the
[session package README](../session/README.md#account-linking-across-federations-482).

#### The identity lookup (#613)

What a federation-grant deployment (`@o3co/auth-provider-federation-grants`,
the connect callback's check 5 in the ADR's
[D7](../core/docs/adr/2026-09-17-federation-grants-offline-delegation.md#d7--the-connect-flow-binds-its-callback-and-refuses-on-any-mismatch))
asks of the Store: who holds an upstream identity, so that a
delegation is refused when the account belongs to another local user. The
Store answers about ownership across **every** registration of the IdP, not
only the one the identity came through — a login links under the federation
the user signed in through, and an IdP whose `sub` is pairwise per app
registration (Entra's is) gives the same person another `sub` under each. For
a separate registration for grants (the ADR's
[D19](../core/docs/adr/2026-09-17-federation-grants-offline-delegation.md#d19--entra-on-behalf-of-is-not-implemented-and-consent-accumulates)),
that means: to answer `unlinked`
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
from the id_token; `{}` when it named none). The Store must not log, persist
or echo those claims — core's
[`FederatedIdentityLookup`](../core/src/repositories/UserRepository.mts) marks
them transient. The lookup must change nothing:
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
`requiredClaims` name is among `identityClaims`. When federation grants are enabled and have at
least one connection and `federationGrants.identityLookup` is `"required"` (the
default), the grants module refuses at boot every connection it is `false` for;
under `"unsupported"`, or with no connection, it asks nothing. A registration nobody declared is
answered `registration_not_covered` locally, and a declared one arriving
without a required claim `identity_not_resolvable`, with no request either
way. The declaration is snapshotted at construction; a duplicate registration,
a malformed entry, or coverage without the URL is a construction error. It has
no environment-variable form (a list is HOCON's), as `federationGrants.connections`
has none. `supportsFederatedIdentityLookup` and `findSubjectByFederatedIdentity`
are absent when `findSubjectByFederatedIdentityUrl` is not configured, and a
deployment that then has a connection under `"required"` is refused at boot.

## What the Store must enforce itself

- **Who may call it.** `HttpUserRepository` sends no credential of its own: each
  request carries only `Content-Type: application/json`, there is no option to
  add a header, and a URL carrying `user:password@` is refused. Nor is what
  `authenticateByToken` and linking carry a secret — the federation callback's `<provider>:<sub>` is an
  identifier. So anyone who can reach `authenticateByTokenUrl` can resolve a
  known identity to its user, and anyone who can reach an open
  `linkFederatedIdentityUrl` can bind any identity to any `userId`. Accept these
  calls only from auth.provider: a network policy or a private network, or
  mutual TLS provided by the platform in front of the Store.
- **No secret in the URL.** A query-string token would not stay secret: the
  errors this adapter throws name the full URL, and the session routes log
  them.
- **Answer without redirecting.** No request follows a redirect, so a
  password, a token, a link request or an identity goes only to the configured
  URL — the one the `https` rule below checks — and no answer from anywhere
  else is taken as the user, the link or the lookup's answer. A `3xx` from any
  of the four endpoints throws like any other unexpected status (the session
  routes and the jwt-bearer grant answer `503 temporarily_unavailable`, the
  grants callback `temporarily_unavailable`), so a Store behind a URL that
  redirects — a host alias redirecting to the canonical host, an added
  trailing slash, a moved path — fails every call. Configure each URL as the
  endpoint that answers, not one that redirects.

## Constructor validation

Every option is validated in the **constructor**, so a misconfigured deployment
fails at boot rather than at the first login attempt.

**Every URL must use `https://`** (the link and lookup endpoints included). They carry plaintext user credentials — a
password on `authenticateUrl`, a token on `authenticateByTokenUrl`, a verified
upstream identity on `findSubjectByFederatedIdentityUrl` — so an
`http://` URL does not merely weaken the connection, it publishes the credential
to every hop on the path. The URL checked here is the only place a request goes
and the only one whose answer is taken: no request follows a redirect, so a
`307` or `308` cannot re-send the body to, and no `301`, `302` or `303` can fetch an answer from, a `Location` this rule never saw.

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
available. A blank environment override is a boot failure, not the default. The
deadline covers the whole exchange, **body included**: the body read is raced
against it rather than relying on the abort signal, because aborting a request
does not reliably interrupt a read already in flight. That is the slow-loris
shape — headers arrive promptly, then the body dribbles or stops — and without
the race it hangs forever. A request that outlives the deadline rejects with a
`timed out after <n>ms` error naming the endpoint.

**`maxResponseBytes` must be a positive integer**, defaulting to
`DEFAULT_MAX_RESPONSE_BYTES` (1 MiB). The cap is enforced against
`Content-Length` *and* while streaming, so a Store that omits the header — or
lies in it — is still cut off rather than allowed to exhaust memory.

## Public API

Exported from [`src/index.mts`](src/index.mts):

- `registerBuiltinAdapters({ userFactory })` — registers the `"http"` type.
- `HttpUserRepository` — the repository
  ([`src/repositories/HttpUserRepository.mts`](src/repositories/HttpUserRepository.mts)).
- `DEFAULT_MAX_RESPONSE_BYTES` — the default response cap.
- `FederatedIdentityLookupCoverage` — the type of one coverage entry.

## Tests

| Test file | Pins |
| --- | --- |
| [`HttpUserRepository.test.mts`](src/repositories/__tests__/HttpUserRepository.test.mts) | authentication and its answers, the `User` shape check, the https rule, the timeout and the response cap, linking, and the identity lookup's presence, probe and wire |
| [`HttpUserRepository.transport.test.mts`](src/repositories/__tests__/HttpUserRepository.transport.test.mts) | against real HTTP servers: the identity lookup releasing a refused answer's connection, and a redirect refused on each of the four requests — to another origin, to the same origin, or with no `Location` — with nothing sent to a redirect target |
| [`registerBuiltinAdapters.test.mts`](src/repositories/__tests__/registerBuiltinAdapters.test.mts) | the `"http"` builder, its defaults and string coercion, and configuration refused at build time |
| [`endpointUrl.test.mts`](src/__tests__/endpointUrl.test.mts) | the https-or-loopback rule |

## See also

- [`@o3co/auth-provider-core`](../core/README.md) — the `UserRepository` port,
  `createRepositoryFactories` and the development user adapters
- [`@o3co/auth-provider-session`](../session/README.md) — the routes that call
  `authenticate`, `authenticateByToken` and `linkFederatedIdentity`
- [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md) — the
  caller of the identity lookup
- [auth.provider](../../README.md) — top-level repository documentation
