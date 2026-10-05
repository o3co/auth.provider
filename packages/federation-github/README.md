# @o3co/auth-provider-federation-github

Last updated: 2026-10-05

GitHub federation provider for `auth.provider`: sign-in with a GitHub account
through a GitHub OAuth App, with upstream logout and claim mapping.

## Responsibility

**Role.** An adapter: it implements core's federation contract
([`core/src/federations`](../core/src/federations/README.md)) for GitHub. It
contributes the federation type `github`: core hands it each enabled
`core.federations` entry of that type, and it builds one federation per entry,
under the entry's name, registered for the session router with its redirect
policy.

**Owns:** GitHub's endpoints, how a GitHub user becomes a profile (the `sub`, the
e-mail choice, the scope translation), the logout URL, and the schema of a
`github` entry's own keys ([`src/entry.mts`](src/entry.mts)).

**Does not own:** the contract (core); the `core.federations` map, the keys
core owns on every entry (`enabled`, `type`, `trustUpstreamAmr`,
`callbackURL`) and the dispatch of an entry by its type (core's boot); the routes, `state` / PKCE verifier
generation, the redirect-allowlist rules and claim precedence
([`@o3co/auth-provider-session`](../session/README.md)); who the user is (the
Store); the logout routes that call this adapter
([`@o3co/auth-provider-oauth`](../oauth/README.md)).

**Why a separate package.** Each adapter is its own package so that a deployment
installs only the IdPs it uses, and `openid-client` only with an adapter.
GitHub OAuth Apps are not OpenID Connect — no id_token, no `nonce`, a numeric
user `id` instead of `sub`, a comma-delimited `scope`, and the e-mail address behind a separate API —
so [`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md), which
requires `openid` and an id_token, cannot stand in for it.

## Install

```sh
npm install @o3co/auth-provider-federation-github @o3co/auth-provider-core @o3co/auth-provider-session
```

Peer dependencies: `@o3co/auth-provider-core` and
`@o3co/auth-provider-session`. The package depends on `openid-client` and
`zod`.

## Usage

One module, `githubFederationTypeModule()`
([`src/type-module.mts`](src/type-module.mts)), handles every enabled
`core.federations` entry whose `type` is `github`. It contributes
`federationTypes.github`; core parses each such entry with the type's schema at
boot and calls the module's factories with the entry's name, its
`callbackURL` and its parsed keys, so the composition root fills no slot and
writes no bridge. The module requires no dependency.

```ts
import { createApp } from "@o3co/auth-provider-core";
import { githubFederationTypeModule } from "@o3co/auth-provider-federation-github";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";

const handle = await createApp({
  modules: [
    sessionStoreModuleFor(config),
    sessionModule,
    githubFederationTypeModule(),
    // ... composition-root modules supplying userRepository and the session stores
  ],
  bootstrapComponents: { config, pathResolver },
});
```

`githubFederationTypeModule({ fetch })` sends every request to GitHub of every
`github` entry — the token exchange, `/user` and `/user/emails` — through that
fetch: a proxy, or a test double. Without it the global `fetch` is used.

### Configuration

```hocon
core.federations {
  github {
    enabled = true
    type = "github"
    clientId = ${GITHUB_CLIENT_ID}
    clientSecret = ${GITHUB_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/github/callback"
    clientUrl = "https://app.example.com/"
  }
}
```

The entry's name is the federation's: the `:name` segment of its routes and
the prefix of the identity handed to the Store (`<name>:<id>`). Each entry is
its own GitHub client, so two entries of type `github` — say `github-work` and
`github-oss`, each with its own OAuth App and `callbackURL` — are two
federations, and one GitHub user signs in to them as two identities.

An entry is flat, and its schema is strict: the keys core owns (`enabled`,
`type`, `trustUpstreamAmr`, `callbackURL`) and the keys below, nothing else.
The schema is `githubEntrySchema` in [`src/entry.mts`](src/entry.mts). A key it
does not name — a typo, or a nested `github { ... }` section — refuses boot with `config-validation-failed` at `core.federations.<name>`,
naming the key; a missing or malformed key is refused at
`core.federations.<name>.<field>`. A refusal names the key, never its value. A
key written `null` counts as absent. An absent key means what the table says,
read by the provider and the redirect policy; the schema fills in no default.

| Field | Required | Meaning |
| --- | --- | --- |
| `clientId` | yes | The OAuth App's client ID. |
| `clientSecret` | yes | The OAuth App's client secret, sent in the token request body (`client_secret_post`). |
| `callbackURL` | yes | Where GitHub sends the browser back; the OAuth App's callback URL. A key core owns: boot requires it of every entry it dispatches, and the session routes read it from the same entry. |
| `clientUrl` | in practice | Where the browser lands after a login whose start carried no `redirect_to`. Without it such a login ends in `500 misconfiguration` after the session has been saved — so it is needed unless every start carries a `redirect_to` and `authCallbackUrl` is set. |
| `redirectAllowlist`, `authCallbackUrl`, `sessionDomain` | no | The `redirect_to` policy, as for every federation — see the [session package's redirect rules](../session/README.md#redirect-allowlists). A start that carries `redirect_to` needs both an allowlist entry for it and `authCallbackUrl`, or it is refused (`400`) or ends in `500 misconfiguration`. |
| `endSessionEndpoint` | no | Replaces GitHub's logout — see [Refresh and logout](#refresh-and-logout). |

`fetch` is not an entry key: it is the type module's option (above), and a
`GithubProviderConfig` field for `createGithubProvider`.


`createGithubProvider` throws at boot when `clientId`, `clientSecret` or
`callbackURL` is missing.

## What a login does

- **Authorization request:** scope `read:user user:email` and PKCE S256. The
  `nonce` the session router mints is ignored — GitHub issues no id_token to bind
  it to.
- **Code exchange:** at GitHub's token endpoint, the client secret in the
  request body (`client_secret_post`, `openid-client`'s default), with the PKCE
  verifier.
- **The callback's `iss` is checked when it is sent (RFC 9207).** The library is
  configured with GitHub's authorization server's issuer,
  `https://github.com/login/oauth`, as its published metadata names it, and the
  exchange URL is built with core's `callbackUrlForExchange`, so a callback whose
  `iss` names another issuer is refused before any token request. A callback
  without `iss` is accepted. The profile's `issuer` label stays
  `https://github.com`: it is part of the identity a linked account is keyed by.
- **The user** is `GET https://api.github.com/user`, with no subject binding
  (there is no id_token `sub` to bind to). It is GitHub's REST API, not an
  OpenID Connect UserInfo endpoint — it answers a numeric `id` and no `sub` — so
  the adapter fetches it as a protected resource and reads the answer itself,
  rather than through `openid-client`'s UserInfo handling, which requires a
  `sub`. Both `/user` and `/user/emails` are asked for
  `application/vnd.github+json` at REST API version `2022-11-28`
  (`X-GitHub-Api-Version`), the schema the `sub` rule reads `id` against.
  GitHub supports a version for at least 24 months after its successor ships
  (2022-11-28's successor shipped 2026-03-10), so revisit the pin before
  2028-03: once GitHub retires it, every login fails. A
  non-2xx answer, a body that is not JSON, or a user object with neither a
  usable `sub` nor a usable `id` fails the exchange, and the login answers
  `502 exchange_failed`.
- **The e-mail** always comes from `GET /user/emails`, never from `/user`: the
  primary verified address, else the first verified one, else none. A row that
  is not an object is skipped. A failed `/user/emails` request is read as "no
  address" and does not fail the login.

What `exchangeCode` returns:

| Field | Value |
| --- | --- |
| `issuer` | `https://github.com` |
| `sub` | a non-empty string `sub` when the user object carries one; otherwise its `id` — a positive safe integer (`Number.isSafeInteger`, above 0) as a decimal string, or a string of decimal digits with no sign and no leading zero as it is. Any other `id` fails the exchange like a missing one: GitHub sends an int64 integer, and one outside the safe-integer range after `Response.json()`, where a parsed number no longer names one id — above 2^53 − 1, where two ids parse as the same number, or `1e400`, which parses as `Infinity` — would sign two GitHub users in as one `<name>:<id>` |
| `email`, `emailVerified` | the chosen address and `true`, or both absent |
| `name` | `/user`'s `name`, when a string |
| `picture` | `/user`'s `avatar_url`, when a string |
| `accessToken` | as GitHub issued it |
| `refreshToken` | always absent — the adapter has no refresh, so one that a GitHub App's expiring user token comes with is not kept |
| `scope` | GitHub's comma-delimited `scope` rewritten as the space-delimited list the rest of the system reads (RFC 6749 §3.3); absent when GitHub sent none. A `scope` that is not a string is refused by `openid-client` before the adapter sees it, and the login answers `502 exchange_failed` |
| `expiresAt` | when `openid-client` handed the answer over + `expiresIn` when GitHub sends one; **`null` when it does not** (OAuth App tokens), which `oauth`'s `POST /oauth/federation/:name/token` reads as "do not refresh; reuse the stored token" |
| `expiresIn` | `expires_in` as `openid-client` read it (it applies `parseFloat`), `null` when none |
| `tokenType` | `token_type` as `openid-client` reports it (lower-cased `bearer`), recorded by the session router verbatim |
| `idToken` | always absent — GitHub issues none, so one in its token answer was added on the way and is not kept |

`mapClaims` maps `email`, `emailVerified`, `name` and `picture`; the session
package promotes only `email`, `name` and `picture`, and only where the local
record is silent.

## Refresh and logout

- **No refresh.** The provider does not implement `SupportsRefresh`, so `oauth`'s
  federation token route cannot refresh a GitHub token.
- **`endSession()`** (`SupportsLogout`, called by `oauth`'s logout routes): with
  `endSessionEndpoint` configured, that URL with `id_token_hint`,
  `post_logout_redirect_uri` and `state`; otherwise `postLogoutRedirectUri`, and without one
  `https://github.com/logout`, with `state`. An unparsable URL throws; the
  message names the field and quotes no value it was handed.
  Redirecting straight to `postLogoutRedirectUri` is safe because the caller
  hands only a URI it has matched against the client's registered
  `postLogoutRedirectUris`, or none — core's `EndSessionRequest` states the
  rule, and `oauth`'s logout routes keep it. A composition that calls
  `endSession()` itself must do the same.

## Public API

Exported from [`src/index.mts`](src/index.mts):

- `githubFederationTypeModule` ([`src/type-module.mts`](src/type-module.mts)) —
  the Module contributing `federationTypes.github`, with its options
  `GithubFederationTypeModuleOptions`.
- `GITHUB_FEDERATION_TYPE` (`"github"`, [`src/type-module.mts`](src/type-module.mts)).
- `createGithubProvider(config)` ([`src/github.mts`](src/github.mts)) — the
  provider for the federation `github`.
- Types: `GithubEntry` ([`src/entry.mts`](src/entry.mts)), an entry's own keys
  as the schema answers them; [`GithubProviderConfig`](src/github.mts),
  `GithubProvider` ([`src/github.mts`](src/github.mts)).

## Tests

Nothing mocks `openid-client`. The provider tests run the real library against
a fake GitHub ([`fake-github.mts`](src/__tests__/fake-github.mts)) handed to the
provider as `config.fetch`, which answers with GitHub's own bodies and records
every request; the global `fetch` is a tripwire that throws. It
enforces the two points where the library's defaults decide success: the token
endpoint answers form-encoded unless `Accept` asks for JSON, and the REST API
refuses a request without a `User-Agent`. `Authorization` and the API version
are pinned by the tests' assertions instead.

| Test file | Pins |
| --- | --- |
| [`github.test.mts`](src/__tests__/github.test.mts) | the authorization request, the token request (PKCE verifier, `client_secret_post`), the callback's `iss` (GitHub's accepted, another refused before the token request, none accepted), the profile's issuer label, the REST headers, the e-mail choice, malformed rows and a failed `/user/emails`, the scope rules, `expiresAt`, `expiresIn` and `tokenType`, no refresh, `mapClaims`, `endSession`, and that `config.fetch` carries every request |
| [`github.user.test.mts`](src/__tests__/github.user.test.mts) | how `/user` becomes the `sub`: GitHub's numeric `id` without a `sub`, the `sub` and `id` rules, and the refusals (a non-2xx answer, a body that is not JSON, no `id`, or one that is not a positive safe integer or a canonical digit string) |
| [`fake-github.test.mts`](src/__tests__/fake-github.test.mts) | the fake itself: form-encoded token answers, the `User-Agent` refusal, and that the adapter's requests satisfy both |
| [`github-type-module.test.mts`](src/__tests__/github-type-module.test.mts) | the type module through `createApp`: one provider and policy per entry, a login through the session routes under the entry's name, the strict, flat schema, that a refusal never quotes the client secret, the `fetch` option, and that every key of the entry reaches the provider and its redirect policy |
