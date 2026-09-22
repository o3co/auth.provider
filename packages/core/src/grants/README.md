# grants

## Responsibility

The contract between the `/oauth/token` dispatch and a grant handler, and the token and claim rules every grant shares: `GrantHandler`, `GrantContext`, `GrantHandlerResult`, `GrantDependencies`; `generateToken` / `generateTokenResponse`; `generateIdToken` and `generateLogoutToken`; `filterClaimsByScope`; `evaluateGrantPolicy` / `boundPolicyAudience`; the `Confirmation` union with the one `matchConfirmation` matrix (#324); `TokenBinding` and `SenderConstraint`; `wellFormedAmr` / `wellFormedAcr`; `isEmailVerified`; and the `GrantRegistry` the boot planner keys handlers in.

It owns no grant type. `authorization_code`, `refresh_token`, `client_credentials`, `session`, the device, token-exchange, jwt-bearer and WebAuthn grants live in `packages/oauth` and its siblings and reach core through `contributes.grants`. It owns no HTTP: `GrantContext` is what the token route hands a handler after client authentication, binding middleware and the allowlist check have run; the route (`packages/oauth`) maps the result to a response. "Grant" here is an OAuth grant type; a *federation grant* is [`../federation-grants/`](../federation-grants/README.md).

## Public contract

- [`types.mts`](./types.mts) — `GrantHandler`, `GrantContext`, `SessionData`, `AuthenticatedClient`, `GrantHandlerResult`, `GrantDependencies`, `GrantFactory`, `GrantModule`. The contribution-side `GrantHandler` in `../modules/manifest/contributes-map.mts` is this type.
- [`token.mts`](./token.mts) — `Token`, `TokenResponse`, `GenerateTokenOptions`, `generateToken`, `generateTokenResponse`, `formatObject`.
- [`idToken.mts`](./idToken.mts), [`logoutToken.mts`](./logoutToken.mts), [`claimFilter.mts`](./claimFilter.mts), [`grantPolicy.mts`](./grantPolicy.mts), [`confirmation.mts`](./confirmation.mts), [`confirmationMatch.mts`](./confirmationMatch.mts), [`tokenBinding.mts`](./tokenBinding.mts), [`senderConstraint.mts`](./senderConstraint.mts), [`authenticationClaims.mts`](./authenticationClaims.mts), [`emailVerifiedGate.mts`](./emailVerifiedGate.mts).
- [`registry.mts`](./registry.mts) — `GrantRegistry` / `GrantRegistryError`, `@internal`: not exported from the root barrel since AS-8; `../boot/create-app.mts` wraps it as the `grants` collector, and `../testing/` re-exports it for tests that build a registry by hand.
- Package README: [Grant System](../../README.md#grant-system), [Token Utilities](../../README.md#token-utilities), [OIDC id_token + claim filter](../../README.md#oidc-id_token--claim-filter-todo-f-4), [Logout helpers](../../README.md#logout-helpers-todo-f-5).

## Inputs and outputs

- `GrantContext.body` is attacker-controlled. Client identity is `authenticatedClient`, set by `clientAuthMw`; it is `null` outside the standard token route, and a handler that needs a client rejects `null` with `invalid_client`.
- `GrantContext` is readonly at the top level; `session` stays field-mutable because handlers write through Express's `req.session` — [`../__tests__/grant-context-readonly.test.mts`](../__tests__/grant-context-readonly.test.mts).
- `SessionData` carries `user`, `client`, `code`, `isAuthenticated`, `sid`. `code_client_id`, `code_redirect_uri` and `granted_scopes` were removed in v0.5.1 (D-1): identity binding lives on the code record (`../repositories/types.mts`, `CodeData.client_id` / `redirect_uri`), and `code` is kept only so pre-v0.5.1 sessions can be cleared.
- A handler returns a `GrantHandlerResult` — status and tokens or an RFC 6749 error, plus an optional `sessionMutation` — and never touches the response.
- `generateToken` signs through `KeyStore.sign`, so `alg` and `kid` are the key store's; `cnf` is emitted only when a `confirmation` is given; `jti` and `issuedAt` may be reserved by the caller (#449) and are otherwise minted here.
- The optional `GrantDependencies` stores are absence-tolerant: no `sid`, no `subjectRevocation`, no logger is "nothing to bind to", never an error.

## Dependencies

- Imports: `../keys/KeyStore` (signing), `../user-sessions/types` (claims, session stores, `SubjectRevocation`), `../policy/types` (`GrantPolicyHook`), `../repositories/types` (`TokenEndpointAuthMethod`, type-only), `../refresh-token-family/types`, `../config/application.schema`, `../modules/types`, `../logging/Logger`; `node:crypto`, `zod` (type).
- Imported by: `../boot/create-app.mts` (registry), `../middleware/{tokenBinding,protectedResourceBinding,express}` and `../accessTokenHeader.mts` (confirmation matching, `BINDING_PROFILES`), `../modules/manifest/contributes-map.mts` (`GrantHandler`), `../repositories/types.mts` (`SenderConstraint`, type-only), the root barrel, `../testing/`.
- The `grants` ↔ `repositories` edge is type-only in both directions. This directory must never import `boot/`, `middleware/`, `routes/`, an adapter package, or `testing/`.

## Invariants

- `generateToken` refuses an empty `jti` and a non-integer `issuedAt`, signs exactly the identity it was given, emits `cnf` only from `confirmation` and echoes it on the `Token`; `generateTokenResponse` answers `Bearer` unless asked for `DPoP` and adds `id_token` only when given — [`token.test.mts`](./__tests__/token.test.mts).
- id_token: `typ: JWT` (disjoint from `at+jwt`), the OIDC claims, `nonce` reflected verbatim, `amr` / `acr` only when recorded, 3600 s default — [`idToken.test.mts`](./__tests__/idToken.test.mts); `email_verified: false` is not absence and a non-boolean is dropped — [`emailVerifiedClaim.test.mts`](./__tests__/emailVerifiedClaim.test.mts).
- logout_token: `typ: logout+jwt`, the `events` claim, never `nonce`, `sid` by default, 300 s — [`logoutToken.test.mts`](./__tests__/logoutToken.test.mts).
- `filterClaimsByScope` is a strict allowlist; provider-specific claims never pass; non-string `groups` members are dropped — [`claimFilter.test.mts`](./__tests__/claimFilter.test.mts).
- Policy: a throwing hook is `503 temporarily_unavailable` (fail closed); a hook that widens scope or audience past its ceiling is `500 server_error`; a deny passes through as `400`; an empty `grantedScope` strips all — [`grantPolicy.test.mts`](./__tests__/grantPolicy.test.mts).
- `matchConfirmation` gates on the mechanism `kind`, not on the confirmation's shape, so a third-party kind cannot satisfy `jkt`; `Confirmation` is a closed union — [`confirmationMatch.test.mts`](./__tests__/confirmationMatch.test.mts), [`confirmation.test.mts`](./__tests__/confirmation.test.mts).
- `isEmailVerified` accepts exactly `true` — [`emailVerifiedGate.test.mts`](./__tests__/emailVerifiedGate.test.mts); `wellFormedAmr` / `wellFormedAcr` — [`authenticationClaims.test.mts`](./__tests__/authenticationClaims.test.mts).
- `GrantRegistry`: `register` throws on a duplicate and never overwrites; `replace` throws on unknown; `frozen` wins over `duplicate`; `addModule` runs no factory when a name conflicts and registers only grants whose config says `enabled: true` / `"true"` — [`registry.test.mts`](./__tests__/registry.test.mts).
- Documented, not tested here: `requiresExplicitGrantAllowlist` (deny-by-absence, #326) and `isGrantTypeAllowed` are enforced at dispatch in `packages/oauth`; the rule itself is tested in [`../repositories/__tests__/allowedGrantTypes.test.mts`](../repositories/__tests__/allowedGrantTypes.test.mts).

## Failure and lifecycle

- A handler refuses with a `GrantError` (`status`, `error`, `errorDescription?`) and fails by throwing; the route decides the HTTP mapping of a throw. Policy outcomes are fixed here: deny → the hook's own `400`, throw → `503`, out of bounds → `500`.
- `GrantRegistry.cleanup()` calls each handler's `cleanup?()`. Boot's `dispose()` runs the `lifecycle.cleanup` hooks of provided components, not the registry, so a handler that holds a resource releases it through its module's `lifecycle` — documented, not tested.
- No cancellation: `handle(ctx)` receives no signal or deadline.

## Contract tests

[`__tests__/`](./__tests__/) — the files cited above, plus [`grantContext.test.mts`](./__tests__/grantContext.test.mts) (`tokenBinding` is optional on the context). The compile-time readonly contract is [`../__tests__/grant-context-readonly.test.mts`](../__tests__/grant-context-readonly.test.mts).
