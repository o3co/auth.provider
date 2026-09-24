# @o3co/auth-provider-federation-github

Last updated: 2026-09-24

GitHub federation provider for `auth.provider`: sign-in with a GitHub account
through a GitHub OAuth App, with upstream logout and claim mapping.

## Responsibility

**Role.** An adapter: it implements core's federation contract
([`core/src/federations`](../core/src/federations/README.md)) for GitHub, and
`githubFederationModule` contributes it to the session router as the federation
`github`, with its redirect policy.

**Owns:** GitHub's endpoints, how a GitHub user becomes a profile (the `sub`, the
e-mail choice, the scope translation), and the logout URL.

**Does not own:** the contract (core); the routes, `state` / PKCE verifier
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
npm install @o3co/auth-provider-federation-github
```

Peer dependencies: `@o3co/auth-provider-core` and
`@o3co/auth-provider-session`. `openid-client` is installed with it.

## Usage

Add `githubFederationModule` to the manifest list passed to `createApp`. A small
config-bootstrap module supplies the typed `githubFederationConfig` slot:

```ts
import { createApp, defineModule } from "@o3co/auth-provider-core";
import {
  extractFederationSection,
  sessionModule,
  sessionStoreModuleFor,
} from "@o3co/auth-provider-session";
import {
  githubFederationModule,
  type GithubProviderConfig,
} from "@o3co/auth-provider-federation-github";

const githubConfigBridgeModule = defineModule({
  name: "github-federation-config",
  requires: ["config"] as const,
  provides: {
    githubFederationConfig: (deps): GithubProviderConfig => {
      const slice = extractFederationSection(deps.config.federations, "github");
      if (slice?.type !== "github") throw new Error("federations.github must be enabled, with type github");
      return {
        clientId: slice.clientId as string,
        clientSecret: slice.clientSecret as string,
        callbackURL: slice.callbackURL as string,
        // The redirect policy is built from this same object: a redirect
        // field left out here is one the policy never sees.
        redirectAllowlist: slice.redirectAllowlist as readonly string[] | undefined,
        sessionDomain: slice.sessionDomain as string | undefined,
        authCallbackUrl: slice.authCallbackUrl as string | undefined,
        clientUrl: slice.clientUrl as string | undefined,
      };
    },
  },
});

const handle = await createApp({
  modules: [
    sessionStoreModuleFor(config),
    sessionModule,
    githubFederationModule,
    githubConfigBridgeModule,
    // ... composition-root modules supplying userRepository and the session stores
  ],
  bootstrapComponents: { config, pathResolver },
});
```

Single-tenant: `provider.name` is fixed at `"github"`, so the federation is
`federations.github`, the identity handed to the Store is `github:<id>`, and a
deployment has one GitHub client. The config fields are
[`GithubProviderConfig`](src/github.mts). The four redirect fields
(`redirectAllowlist`, `sessionDomain`, `authCallbackUrl`, `clientUrl`) follow the
[session package's redirect rules](../session/README.md#redirect-allowlists),
and they reach the redirect policy only through this slot. **Set `clientUrl`:**
a login whose start carried no `redirect_to` lands there, and without it the
callback answers `500 misconfiguration` after the session has been saved; a
start that carries `redirect_to` needs an allowlist entry for it and
`authCallbackUrl` as well. A bridge that forwards the credentials alone
therefore ends every such login on a `500` instead of in the app. The bridge above does not forward the other
optional fields (`endSessionEndpoint`, `fetch`); forward them if the deployment sets them. `fetch` is the one
every request to GitHub goes through — the token exchange, `/user` and
`/user/emails` — for a deployment that reaches GitHub through a proxy; it
defaults to the global `fetch`. It
reads the section only when its `type` is `github` (the default for a section
named `github`), as the standalone template does for Google (in `buildModules.mts`), so a `type = "oidc"` section
under that name is not read as this adapter's. It casts; a production bridge
checks each field's type, as the template's Google bridge
(`googleFederationConfigModule` in
[`templates/standalone/src/modules.mts`](../../templates/standalone/src/modules.mts)) does.
`createGithubProvider` throws at boot when `clientId`, `clientSecret` or
`callbackURL` is missing.

## What a login does

- **Authorization request:** scope `read:user user:email` and PKCE S256. The
  `nonce` the session router mints is ignored — GitHub issues no id_token to bind
  it to.
- **Code exchange:** at GitHub's token endpoint, the client secret in the
  request body (`client_secret_post`, `openid-client`'s default), with the PKCE
  verifier.
- **The callback's `iss` is not checked.** GitHub advertises RFC 9207 and names
  its issuer `https://github.com/login/oauth`, while this adapter configures its
  library with `https://github.com` (the profile's `issuer` label); forwarding
  `iss` would refuse every login, so the exchange URL is built from `code` alone.
  Configuring the library with GitHub's own issuer and then comparing `iss` is
  [#598](https://github.com/o3co/auth.provider/issues/598).
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
| `sub` | a non-empty string `sub` when the user object carries one; otherwise its `id` — a positive safe integer (`Number.isSafeInteger`, above 0) as a decimal string, or a string of decimal digits with no sign and no leading zero as it is. Any other `id` fails the exchange like a missing one: GitHub sends an int64 integer, and one outside the safe-integer range after `Response.json()`, where a parsed number no longer names one id — above 2^53 − 1, where two ids parse as the same number, or `1e400`, which parses as `Infinity` — would sign two GitHub users in as one `github:<id>` |
| `email`, `emailVerified` | the chosen address and `true`, or both absent |
| `name` | `/user`'s `name`, when a string |
| `picture` | `/user`'s `avatar_url`, when a string |
| `accessToken` | as GitHub issued it |
| `refreshToken` | always absent — the adapter has no refresh, so one that a GitHub App's expiring user token comes with is not kept |
| `scope` | GitHub's comma-delimited `scope` rewritten as the space-delimited list the rest of the system reads (RFC 6749 §3.3); absent when GitHub sent none. A `scope` that is not a string is refused by `openid-client` before the adapter sees it, and the login answers `502 exchange_failed` |
| `expiresAt` | when the answer arrived + `expires_in` when GitHub sends one; **`null` when it does not** (OAuth App tokens), which `oauth`'s `POST /oauth/federation/:name/token` reads as "do not refresh; reuse the stored token" |
| `expiresIn` | the `expires_in` GitHub sent, `null` when none |
| `tokenType` | `token_type` as `openid-client` reports it (lower-cased `bearer`), recorded by the session router verbatim |
| `idToken` | not returned — GitHub issues none |

`mapClaims` maps `email`, `emailVerified`, `name` and `picture`; the session
package promotes only `email`, `name` and `picture`, and only where the local
record is silent.

## Refresh and logout

- **No refresh.** The provider does not implement `SupportsRefresh`, so `oauth`'s
  federation token route cannot refresh a GitHub token.
- **`endSession()`** (`SupportsLogout`, called by `oauth`'s logout routes): with
  `endSessionEndpoint` configured, that URL with `id_token_hint`,
  `post_logout_redirect_uri` and `state`; otherwise `postLogoutRedirectUri`, and without one
  `https://github.com/logout`, with `state`. An unparsable URL throws.

## Public API

Defined in [`src/github.mts`](src/github.mts), exported from
[`src/index.mts`](src/index.mts):

- `githubFederationModule` — const Module contributing `federations.github` and
  `federationRedirectPolicies.github`; requires `githubFederationConfig`.
- `createGithubProvider(config)` — the provider.
- `GithubProviderConfig`, `GithubProvider` — types.
- `githubFederationConfig` — the `ComponentMap` slot the module requires,
  declared by module augmentation (not an export).

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
| [`github.test.mts`](src/__tests__/github.test.mts) | the authorization request, the token request (PKCE verifier, `client_secret_post`), the exchange without `iss`, the REST headers, the e-mail choice, malformed rows and a failed `/user/emails`, the scope rules, `expiresAt`, `expiresIn` and `tokenType`, no refresh, `mapClaims`, `endSession`, and that `config.fetch` carries every request |
| [`github.user.test.mts`](src/__tests__/github.user.test.mts) | how `/user` becomes the `sub`: GitHub's numeric `id` without a `sub`, the `sub` and `id` rules, and the refusals (a non-2xx answer, a body that is not JSON, no `id`, or one that is not a positive safe integer or a canonical digit string) |
| [`fake-github.test.mts`](src/__tests__/fake-github.test.mts) | the fake itself: form-encoded token answers, the `User-Agent` refusal, and that the adapter's requests satisfy both |
| [`github-module.test.mts`](src/__tests__/github-module.test.mts), [`github-module-boot.test.mts`](src/__tests__/github-module-boot.test.mts) | the module's contributions and boot with the session module |
