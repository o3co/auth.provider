# `core/src/federations`

The federation adapter port: what an upstream-IdP adapter implements, and what everything downstream of it reads. The boundary review behind it is [#626](https://github.com/o3co/auth.provider/issues/626) (P1).

## Responsibility

| File | Kind | Owns |
| --- | --- | --- |
| [`types.mts`](./types.mts) | contract | [`FederationProvider`](./types.mts) and [`FederationProfile`](./types.mts); the optional capabilities [`SupportsLogout`](./types.mts), [`SupportsClaimMapping`](./types.mts), [`SupportsRefresh`](./types.mts), [`SupportsDelegatedAuthorization`](./types.mts) with their request and result types and one guard each; the reserved-parameter and identity-claim policy a delegated authorization is held to. No state. |
| [`response-mode.mts`](./response-mode.mts) | contract | `query` versus `form_post` ([`FederationResponseMode`](./response-mode.mts)), the list, the default, and [`resolveFederationResponseMode`](./response-mode.mts), which reads an unrecognised value as the default so a provider that predates the field keeps working. No state. |

**Why here.** Three packages meet at this contract and none of them may import another: `@o3co/auth-provider-session` drives an adapter from its router, `@o3co/auth-provider-oauth` reads providers off the `federationProviders` slot, and `@o3co/auth-provider-federation-grants` delegates through the capability. It lived in session until #626 P1, which is why the contribution type was `unknown` at registration — core cannot import downwards, so the type a federation was registered with was not the type its consumer read. Core is the one place all of them already depend on.

**What is not here.** The router, the redirect policy it feeds and `FederationResult` stay in `@o3co/auth-provider-session`; nothing outside that package answers with one. The adapters themselves are their own packages. Core implements no federation.

## Public contract

- Everything in both files is exported from the package root. `FederationProvider` is also the value type of the `federations` contribution kind ([`../modules/manifest/contributes-map.mts`](../modules/manifest/contributes-map.mts)) and of the `federationProviders` slot ([`../modules/manifest/synthetic-keys.mts`](../modules/manifest/synthetic-keys.mts)) — one type, which is the point of the move.
- A contribution factory may answer with the value or a promise of it (`Contributed<T>`): `applyContributions` awaits it, which is what lets an adapter discover issuer metadata at boot.

## Inputs and outputs

- In: whatever the route layer passes — the redirect URI, the CSRF `state`, the PKCE `codeVerifier`, the `nonce`, and on the callback the code and the parameters as received. A provider allocates no state of its own.
- Out: a [`FederationProfile`](./types.mts) from `exchangeCode`, whose `[key: string]: unknown` is the extension slot for provider-specific claims — which is why a negative type test against this contract has to be written against a missing method rather than a misspelt field.
- The capability results are the adapter's own snapshot of what the upstream said. Every field on [`RefreshedTokens`](./types.mts) and [`DelegatedTokens`](./types.mts) is optional: absent is the upstream saying nothing, `null` on a lifetime is the upstream naming none, and a consumer must tell those apart.

## Dependencies

`types` → `response-mode` (the `responseMode` field) · `response-mode` → `types` (`Pick<FederationProvider, "responseMode">`), type-only in both directions. Nothing else: no store, no config, no logger. Imported by `../modules/manifest/contributes-map`, `../modules/manifest/synthetic-keys`, `../boot/`, `../federation-grants/retrieve` and, outside core, by the session router, `oauth`'s logout and federation-token routes, `federation-grants` and the four adapters.

## Invariants

1. **A capability is declared by having the method, and read by the guard.** `supportsLogout`, `supportsClaimMapping`, `supportsRefresh` and `supportsDelegatedAuthorization` each answer `false` for `null` and `undefined`, so a caller can pass a `Map.get()` result straight in. `supportsDelegatedAuthorization` needs all three methods, not one — [`types.test.mts`](./__tests__/types.test.mts).
2. **The response mode defaults rather than refuses.** An unrecognised value reads as `query`, because absence has to mean `query` for every provider written before the field existed — [`response-mode.test.mts`](./__tests__/response-mode.test.mts).
3. **A delegated authorization may not carry the reserved parameters**, and the identity claims it may select are the listed ones — `RESERVED_DELEGATED_AUTHORIZATION_PARAMS`, `RESERVED_IDENTITY_CLAIMS`, `identityClaimsProblem`, `selectIdentityClaims` in [`types.mts`](./types.mts).
4. **What the capability answers is what the retrieval consumes.** `SupportsDelegatedAuthorization.refreshDelegatedToken` and `FederationGrantRefresher.refresh` both answer with `DelegatedTokens`; they were two identical declarations until #626 P1 — [`delegated-authorization-types.test.mts`](./__tests__/delegated-authorization-types.test.mts).

## Failure and lifecycle

- Nothing here throws, holds state or has a lifetime: the guards are predicates, the policy helpers are pure, and `resolveFederationResponseMode` reads one field. An adapter's own failures are its package's business; what a delegated retrieval does with a malformed answer is [`../federation-grants/`](../federation-grants/README.md).

## Contract tests

| Test file | Pins |
| --- | --- |
| [`__tests__/types.test.mts`](./__tests__/types.test.mts) | each guard on a provider that has the capability and one that does not, including the all-three rule for delegated authorization. |
| [`__tests__/federation-provider-slim.test.mts`](./__tests__/federation-provider-slim.test.mts) | the required members, and that the redirect methods removed in A5 have not come back. |
| [`__tests__/delegated-authorization-types.test.mts`](./__tests__/delegated-authorization-types.test.mts) | an adapter with the capability is a refresher the retrieval can use, and the named fields of a token snapshot — which `Omit` over an index signature did not check. |
| [`__tests__/response-mode.test.mts`](./__tests__/response-mode.test.mts) | the default, the list, and an unrecognised value reading as the default. |
| [`../__tests__/contributes-map-substitution.test.mts`](../__tests__/contributes-map-substitution.test.mts) | that the contribution type is this contract, and that a module contributing a federation without the methods does not compile. |
