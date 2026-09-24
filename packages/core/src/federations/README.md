# `core/src/federations`

Last updated: 2026-09-24

The federation adapter port: what an upstream-IdP adapter implements, and what everything downstream of it reads.

## Responsibility

This directory owns the contract an adapter implements — `FederationProvider` and `FederationProfile`, and the optional capabilities `SupportsLogout`, `SupportsClaimMapping`, `SupportsRefresh` and `SupportsDelegatedAuthorization` with their request and result types and one guard each — and the rules the federation paths share: the reserved-parameter and identity-claim policy a delegated authorization is held to, the response-mode vocabulary (`query` / `form_post`), RFC 6749 §3.3's scope grammar, and what an upstream token may be handed on as (RFC 6749 `token_type`). It also owns the adapter toolkit — the pure helpers every adapter builds its upstream requests with: the PKCE S256 challenge, the URL an adapter's library exchanges the code at, and a `client_secret` that may be computed per request. None of it holds state.

**Why it is separate, and why in core.** Three packages meet at this contract: `@o3co/auth-provider-session` drives an adapter from its router, `@o3co/auth-provider-oauth` reads providers off the `federationProviders` slot, and `@o3co/auth-provider-federation-grants` delegates through the capability; four adapter packages implement it. They do not all depend on one another — `session` and `oauth` are independent, `federation-grants` depends on `oauth` but not on `session`, and the adapters depend on `session` — so core is the one place all of them already depend on, and the type a federation is registered with is therefore the type its consumer reads. It is a directory of its own because it is the adapter's side of the line: no store, no route, no grant record.

**Why the toolkit is here.** An adapter is its only caller — the session router uses none of it — and this contract already tells adapters to use it; core is the package every adapter depends on anyway.

**What is not here.** The router, the redirect policy it feeds and `FederationResult` stay in `@o3co/auth-provider-session`; nothing outside that package answers with one. The adapters themselves are their own packages. Core implements no federation. The upstream tokens a session holds are [`../federation-tokens/`](../README.md#federation-tokens); a grant that outlives the session is [`../federation-grants/`](../federation-grants/README.md).

## Public contract

- The contract is [`types.mts`](./types.mts); the response-mode vocabulary is [`response-mode.mts`](./response-mode.mts), the scope grammar [`scope.mts`](./scope.mts), the token-type rule [`token-type.mts`](./token-type.mts). The adapter toolkit is `codeChallenge` ([`pkce.mts`](./pkce.mts)), `callbackUrlForExchange` ([`callback-url.mts`](./callback-url.mts)) and `FederationClientSecret` / `resolveClientSecret` ([`client-secret.mts`](./client-secret.mts)). Everything here is exported from the package root.
- `FederationProvider` is also the value type of the `federations` contribution kind ([`../modules/manifest/contributes-map.mts`](../modules/manifest/contributes-map.mts)) and of the `federationProviders` slot ([`../modules/manifest/synthetic-keys.mts`](../modules/manifest/synthetic-keys.mts)) — one type.
- A contribution factory may answer with the value or a promise of it (`Contributed<T>`): `applyContributions` awaits it, which is what lets an adapter discover issuer metadata at boot.

## Inputs and outputs

- In: whatever the route layer passes — the redirect URI, the CSRF `state`, the PKCE `codeVerifier`, the `nonce`, and on the callback the code and the parameters as received. A provider allocates no state of its own.
- Out: a [`FederationProfile`](./types.mts) from `exchangeCode`, whose `[key: string]: unknown` is the extension slot for provider-specific claims — which is why a negative type test against this contract has to be written against a missing method rather than a misspelt field.
- The capability results are the adapter's own snapshot of what the upstream said. Every field on [`RefreshedTokens`](./types.mts) and [`DelegatedTokens`](./types.mts) is optional: absent is the upstream saying nothing, `null` on a lifetime is the upstream naming none, and a consumer must tell those apart.

## Dependencies

- Inside the directory, the contract and the response-mode vocabulary refer to each other, type-only in both directions. The token-type rule uses `node:net` (`isIPv6`, for the inside of an IP-literal) and `codeChallenge` uses `node:crypto` (SHA-256); neither uses anything in core. Nothing else: no store, no config, no logger.
- Depended on inside core by `modules/manifest/` (the contribution type, which is how the synthetic `federationProviders` slot and `boot/` reach it), `federation-grants/` and the package root; outside core, by the session router, `oauth`'s logout and federation-token routes, `federation-grants` and the four adapters.

## Invariants

1. **A capability is declared by having the method, and read by the guard.** `supportsLogout`, `supportsClaimMapping`, `supportsRefresh` and `supportsDelegatedAuthorization` each answer `false` for `null` and `undefined`, so a caller can pass a `Map.get()` result straight in. `supportsDelegatedAuthorization` needs all three methods, not one — [`types.test.mts`](./__tests__/types.test.mts).
2. **The response mode defaults rather than refuses.** An unrecognised value reads as `query`, because absence has to mean `query` for every provider that does not name a mode — [`response-mode.test.mts`](./__tests__/response-mode.test.mts).
3. **A delegated authorization may not carry the reserved parameters**, and the identity claims it may select are the listed ones: `RESERVED_DELEGATED_AUTHORIZATION_PARAMS`, `RESERVED_IDENTITY_CLAIMS`, `identityClaimsProblem` and `selectIdentityClaims` in [`types.mts`](./types.mts) — [`types.test.mts`](./__tests__/types.test.mts).
4. **A scope is split on any whitespace and kept only where it is a scope-token**, in order and without repeats; `canonicalScope` is the one form a scope is written and compared in — [`scope.test.mts`](./__tests__/scope.test.mts).
5. **An upstream token is handed on as a bearer token or not at all.** `canonicalTokenType` accepts only what RFC 6749 §A.13 calls a `token-type` — a `type-name` or a URI reference, checked against RFC 3986's grammar including its structure — and `isBearerTokenType` compares without regard to case (§5.1). No other name in IANA's registry is one a recipient could present: `PoP` and `DPoP` are sender-constrained and the recipient of a token delegated by value holds no proof key, and `N_A` is not an access token type at all. Answering one as `Bearer` would drop a constraint the upstream imposed, or invent one it never issued. Both routes that disclose an upstream token ask this: `../federation-grants/eligibility.mts` and `oauth`'s `POST /oauth/federation/:name/token` — [`token-type.test.mts`](./__tests__/token-type.test.mts).
6. **What the capability answers is what the retrieval consumes.** `SupportsDelegatedAuthorization.refreshDelegatedToken` and `FederationGrantRefresher.refreshDelegatedToken` both answer with the one `DelegatedTokens` type, so an adapter with the capability is a refresher the retrieval can use — [`delegated-authorization-types.test.mts`](./__tests__/delegated-authorization-types.test.mts).
7. **A provider has `name`, `scope`, `buildAuthorizationUrl` and `exchangeCode`, and no redirect method** (`validateRedirect`, `resolveCallbackRedirect`): the redirect policy is the session router's — [`federation-provider-slim.test.mts`](./__tests__/federation-provider-slim.test.mts).
8. **The contribution type is this contract**, and a module contributing a federation without the methods does not compile — [`../__tests__/contributes-map-substitution.test.mts`](../__tests__/contributes-map-substitution.test.mts).
9. **The code-exchange URL carries `code`, the callback's RFC 9207 `iss`, and nothing else from the callback.** An `iss` already on the registered redirect URI is dropped when the callback carried none, so configuration cannot answer for the response — [`callback-url.test.mts`](./__tests__/callback-url.test.mts).
10. **A client secret is resolved on every token request and never cached here**; an empty or non-string one is refused locally rather than posted upstream — [`client-secret.test.mts`](./__tests__/client-secret.test.mts). The S256 challenge is [`pkce.test.mts`](./__tests__/pkce.test.mts).

## Failure and lifecycle

- Nothing here holds state or has a lifetime: the guards are predicates, the policy helpers are pure, and `resolveFederationResponseMode` reads one field. The one throw is `resolveClientSecret` refusing a secret it would otherwise post upstream. An adapter's own failures are its package's business; what a delegated retrieval does with a malformed answer is [`../federation-grants/`](../federation-grants/README.md).

## Contract tests

[`__tests__/`](./__tests__/) — the files named above. `federation-provider-slim.test.mts` and `delegated-authorization-types.test.mts` assert types, so they run under typecheck mode (`vitest.config.mts`).
