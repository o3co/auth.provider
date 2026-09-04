# @o3co/auth-provider-oauth-token-exchange

RFC 8693 Token Exchange grant for [auth.provider](https://github.com/o3co/auth.provider).
Supports on-behalf-of, delegation (`act` claim), and scope / audience narrowing.

## Install

```bash
pnpm add @o3co/auth-provider-oauth-token-exchange
```

## Register the grant

```ts
import { createApp } from "@o3co/auth-provider-core";
import { tokenExchangeModule } from "@o3co/auth-provider-oauth-token-exchange";

const handle = await createApp({
  modules: [
    tokenExchangeModule,
    clientRepositoryModule,
    keyStoreModule,
    refreshTokenStoreModule,
  ],
  bootstrapComponents: {
    config,
    pathResolver,
  },
});
```

The grant type URI is `urn:ietf:params:oauth:grant-type:token-exchange` (IETF registered).

The built-in `access_token` validator is contributed by `tokenExchangeModule` itself. Consumers do not create or mutate a validator registry.

## Disabling the module

There is no config-driven disable switch. To disable Token Exchange, **do not import `tokenExchangeModule`**.

Rationale: the RFC 8693 grant type URI (used for HTTP dispatch) differs from the HOCON-friendly config key, which makes a config-driven `enabled` flag structurally awkward to implement cleanly. Consumer-level opt-in via module import is both simpler and consistent with the rest of the v0.5.0 package-split philosophy (`@o3co/auth-provider-oauth-federation-*`).

## Client configuration

A client registration is the ceiling for an exchange on every axis. All three fields below are read by this grant:

```yaml
clients:
  billing-gateway:
    clientSecret: "..."
    allowedGrantTypes: ["urn:ietf:params:oauth:grant-type:token-exchange"]
    allowedScopes: ["read", "write"]
    allowedAudiences: ["billing-service", "inventory-service"]
```

- **`allowedGrantTypes` must name the exchange grant type.** This grant denies by absence (#326): a registration that omits the field, or names other grants only, is refused with `unauthorized_client`. See Security note 15.
- **`allowedScopes` bounds the granted scope**, on top of the subject token's own scope. Empty or omitted means no scope is granted. See Security note 2.
- **`allowedAudiences` bounds the `audience` parameter.** When it is empty or omitted, the only accepted `audience` parameter value is the client's own `clientId`. This allowlist applies to the **request's `audience` parameter only** — a `GrantPolicyHook` can override `grantedAudience` in its decision, which is not re-validated against the allowlist (see Security note 4 for the rationale). If you want hard-boundary enforcement across both paths, write your policy hook defensively.

## External JWT subject_token

The package ships a built-in validator only for the `access_token` token type (tokens issued by this same auth.provider instance). To accept external JWTs as `subject_token`, implement `ExchangeTokenValidator` yourself and contribute it from a sibling module for `urn:ietf:params:oauth:token-type:jwt`:

```ts
import { createApp, defineModule } from "@o3co/auth-provider-core";
import type { ExchangeTokenValidator, ValidatedToken } from "@o3co/auth-provider-oauth-token-exchange";
import { tokenExchangeModule } from "@o3co/auth-provider-oauth-token-exchange";

class ExternalJwtValidator implements ExchangeTokenValidator {
  constructor(private readonly options: { keyStore: unknown }) {}

  async validate(
    token: string,
    ctx: { role: "subject" | "actor" },
  ): Promise<ValidatedToken | null> {
    // Fetch jwks, verify signature, check issuer allowlist, consult remote
    // introspection for revocation — all are YOUR responsibility.
    // Return null on validation failure; throw on infrastructure failure (→ 503).
  }
}

const externalJwtTokenExchangeValidatorModule = defineModule({
  name: "external-jwt-token-exchange-validator",
  requires: ["keyStore"],
  contributes: {
    tokenExchangeValidators: {
      "urn:ietf:params:oauth:token-type:jwt": (deps) =>
        new ExternalJwtValidator({ keyStore: deps.keyStore }),
    },
  },
});

const handle = await createApp({
  modules: [
    tokenExchangeModule,
    externalJwtTokenExchangeValidatorModule,
    clientRepositoryModule,
    keyStoreModule,
  ],
  bootstrapComponents: { config, pathResolver },
});
```

## Security notes

1. **refreshTokenStore must be wired via a module that provides `refreshTokenStore`** so the boot planner injects it into `tokenExchangeModule`'s typed deps and the handler can surface the specific `family_revoked` errorDescription (spec §5.3). Without `refreshTokenStore` in the module graph, self-issued access_tokens carrying `family_id` cannot be revocation-checked; the handler returns `invalid_grant` (fail-closed). `tokenExchangeModule` declares both `refreshTokenStore` and `grantPolicy` in `optional`. See the "Register the grant" example above.

2. **Scope is bounded by two ceilings, always.** `granted scope ⊆ subject_token.scope ∩ client.allowedScopes` is enforced unconditionally, and a `GrantPolicyHook` cannot bypass either **through the request parameter** (point 5 covers the policy-level override, which is re-checked against both). An explicitly requested scope outside either ceiling is refused with `invalid_scope` naming it; an omitted `scope` inherits the subject token's, clamped to the registration.

   **An absent or empty `allowedScopes` grants no scope at all.** A registration that names no scope may receive none — the deny-by-absence discipline of #363 / #396, not a permissive "unrestricted" reading. The exchange still succeeds; the issued token simply carries no `scope` claim. Without this ceiling a client registered for `read` that obtained a subject token carrying `admin` exchanged it and received `admin`, its own registration bounding nothing.

3. **Audience allowlist (client-scoped).** The `audience` request parameter must be in `client.allowedAudiences ∪ { client.clientId }`. This is enforced by the core handler before the policy hook runs. Empty `allowedAudiences` means only the client's own `clientId` is a valid exchange audience.

4. **Cross-client audience confusion defense.** When the `audience` request parameter is omitted, the handler inherits `subject_token.aud` only if it is in `client.allowedAudiences ∪ { client.clientId }`. Otherwise it falls back to `clientId`. This prevents a malicious client from exchanging a stolen token outside its intended audience just by omitting the audience parameter.

5. **Policy hook widening is always rejected.** The `GrantPolicyHook.evaluate()` result's `grantedScope` and `grantedAudience` are still allowed to override the request-derived values, but the handler always re-checks them before minting: `grantedScope` against **both** the validated `subject_token` scope and `client.allowedScopes`, `grantedAudience` against the subject token's audience boundary. Scope or audience widening returns `invalid_target` with `scope_widening_not_allowed` or `audience_widening_not_allowed`. There is no opt-in to bypass this check.

6. **Resource indicators must equal the issued-token audience.** When the request includes RFC 8707 `resource`, every requested resource must equal `audienceForToken` — the single value that will be minted into the issued token's `aud` claim (typically `grantedAudience[0]`). Multi-resource requests whose resources cannot all be represented in the single-valued `aud` are rejected with `invalid_target` / `requested_resources_not_in_audience`. This avoids issuing a token whose `aud` silently disagrees with the requested resource (RFC 8707 §3).

7. **Impersonation vs delegation.** An exchange without `actor_token` issues an impersonation token (no `act` claim). Deployments that require audit trails should add a `GrantPolicyHook` that rejects requests lacking `actor_token`:

   ```ts
   async evaluate(req) {
     if (req.grantType === "urn:ietf:params:oauth:grant-type:token-exchange" && !req.actorTokenType) {
       return { outcome: "deny", error: "invalid_request",
                errorDescription: "actor_token required for delegation" };
     }
     return { outcome: "allow" };
   }
   ```

8. **`may_act` is enforced when present — on both exchange shapes.** If a subject token carries a `may_act` claim, the party acting on the subject's behalf must match one of its `{ sub?, iss? }` constraints. Malformed or non-matching values fail closed with `may_act_violation`; subject tokens without `may_act` continue to use the existing policy-hook boundary.

   Which party that is depends on the exchange. **Delegation** (`actor_token` supplied): the actor token must match, comparing `sub` against its subject and `iss` against its issuer. **Impersonation** (no `actor_token`, note 7): the authenticated calling client is the actor, and its `clientId` must match a `may_act` entry's `sub`. Enforcing the claim only when an `actor_token` happened to be supplied made it opt-out — omitting the parameter skipped it entirely, so a token naming one permitted actor was exchangeable by any exchange-enabled client that got hold of it.

   The impersonation check is deliberately narrower: an entry that also constrains `iss` is **never** satisfied by a client identity. No token was presented for the actor, so there is no issuer to compare, and substituting this AS's own issuer would be a guess in the permissive direction. Write `may_act` entries as `{ "sub": "<client-id>" }` when the intended actor is a client acting in its own name.

9. **Actor chains are bounded.** `oauth.tokenExchange.maxActorChainDepth` defaults to `3` and can be overridden with `OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH`. When an `actor_token` would add to an already-full nested `act` chain, the handler rejects the request with `actor_chain_too_deep`.

10. **Family cascade.** Issued access_tokens inherit the subject's `family_id` claim. Revoking the subject's family (e.g. on logout) automatically invalidates every token exchanged from it. This is the same mechanism auth.provider's introspect and userinfo endpoints use.

11. **Refresh / ID tokens are never issued.** Per RFC 8693 §4.2.2 the handler only returns an access_token. The response always carries `issued_token_type: "urn:ietf:params:oauth:token-type:access_token"`.

12. **Missing subject claim rejection.** Self-issued access_tokens without a `sub` claim (or with an empty-string `sub`) are rejected with `invalid_grant`. This prevents a silently-anonymous token from reaching downstream services.

13. **Validator contributions are immutable after boot.** The boot planner aggregates `tokenExchangeValidators` contributions, freezes the world during activation, and exposes only a read-only resolver to the grant handler. Post-boot mutation cannot replace the built-in validator at runtime.

14. **Confidential clients only (v0.5.0).** The handler requires `client_secret` and authenticates via `clientRepository.authenticate()`. Requests without a secret are rejected with `invalid_client` (401). The core `Client` type carries `clientSecret: string` as a required field and `PublicClient = Omit<Client, "clientSecret">`, so `findById()` alone cannot tell a "no secret configured" client from "secret omitted by caller" — accepting the unauthenticated path would let an attacker exchange a stolen `subject_token` under any client's allowlist. Public-client support is deferred until a `Client.public` flag (or equivalent) lands in core.

15. **The grant denies by absence of `allowedGrantTypes` (#326).** Token exchange mints a fresh credential out of one a client already holds — a standing capability of a registration, not a per-user ceremony — so it is never acquired by omission. The handler declares `requiresExplicitGrantAllowlist`, which `/oauth/token` dispatch enforces before `handle` runs, and repeats the check internally for the standalone wiring this package documents (no `clientAuthMw`, `ctx.authenticatedClient === null`), where no dispatch rule runs at all. Both paths refuse with `400 unauthorized_client` / `client is not authorized for urn:ietf:params:oauth:grant-type:token-exchange`. This does not depend on `oauth.requireGrantTypeAllowlist`, which defaults off; the two compose to the stricter rule.

16. **The issued token never outlives the subject token (RFC 8693 §2.2.1).** `expires_in` is `min(configured accessToken.expiresIn, subject_token exp − now)`, so a chain of exchanges cannot refresh the clock past the credential it descends from. A subject token with no remaining lifetime — already expired, or expiring within the current second — is refused with `invalid_grant` / `subject_token has expired` rather than minting a token with a zero or negative lifetime. A subject token carrying **no `exp` claim at all** leaves the configured lifetime standing: there is no lifetime for the cap to descend from. The built-in validator never produces one (jose rejects an expired token before the handler sees it); a consumer-implemented validator that returns an `exp`-less `ValidatedToken` is asserting an unbounded credential, and should not do so lightly.

17. **A DPoP-bound issued token is advertised as `token_type: "DPoP"` (RFC 9449 §5).** The response envelope names the mechanism the issued `cnf` actually binds, read off the confirmation stamped into the token. mTLS-bound tokens keep `"Bearer"` — RFC 8705 §3 does not redefine the wire-level type. Previously the envelope always said `Bearer`, so a DPoP-aware client presented a `cnf.jkt` token as a Bearer token and this provider's own protected-resource middleware refused it (RFC 9449 §7.1).

18. **Nothing ties the `subject_token` to the calling client.** This is a known property, stated rather than fixed. The built-in validator does not pin `aud` — `ExchangeTokenValidationContext` deliberately does not carry the calling-client identity, and the central verifier records the gap as `jwt_verify_aud_skipped` — and omitting the `audience` parameter falls back to the caller's own `clientId` (note 4). So an exchange-enabled client can present a self-issued access token it legitimately obtained and re-audience it to itself.

    What bounds the consequence is the registration, which is why notes 2 and 15 matter beyond their own findings: the re-audienced token cannot carry a scope outside the client's `allowedScopes`, cannot outlive the subject (note 16), and cannot be minted at all by a client whose registration does not name this grant. The escalation is therefore bounded by what the client was already registered to hold, not by what the subject token happened to carry.

    **Recommended:** gate the grant with a `GrantPolicyHook` (`grantPolicy`) that asserts the relationship your deployment expects between the subject token and the caller — the hook is the layer that has both identities in hand. Registrations that do not need token exchange should simply omit it from `allowedGrantTypes`, which note 15 now makes sufficient.

## Registration pattern summary

- Import `tokenExchangeModule` and any sibling modules that contribute additional validators
- Boot the app with `await createApp({ modules: [...], bootstrapComponents: { config, pathResolver } })`
- Call `handle.dispose()` during shutdown

## Unsupported RFC 8693 features (v0.5.0 scope-out)

- `saml1` / `saml2` subject token types
- Token type conversion (access ↔ id, access → refresh): returns `unsupported_token_type`
- Built-in external JWT validator (consumer-implement; planned as a separate package post-0.5)

Sender-constrained token minting **is** supported and was listed here in error: the handler enforces the full DPoP and mTLS `cnf` matrices on the `subject_token` and the `actor_token` (#265, #309), stamps the proven binding into the issued token, and advertises `token_type: "DPoP"` for a `cnf.jkt` token (Security note 17). See `src/__tests__/senderConstraint.test.mts` for the matrix rows.

## Breaking changes (unreleased)

Each of these fails closed. A client registration that relied on omission stops working until the field is declared; that is the intended direction.

- **The grant denies by absence of `allowedGrantTypes`.** Add `"urn:ietf:params:oauth:grant-type:token-exchange"` to `allowedGrantTypes` on every registration that performs an exchange. Registrations that omit the field, or name other grants only, now receive `400 unauthorized_client`. Security note 15.
- **`client.allowedScopes` is a ceiling on the granted scope.** Declare every scope an exchanging client may receive. A registration with an absent or empty `allowedScopes` now receives a token with no `scope` claim, and any explicitly requested scope is refused with `invalid_scope`. Security note 2.
- **`may_act` is enforced on impersonation exchanges.** A subject token carrying `may_act` is no longer exchangeable without an `actor_token` by a client the claim does not name. Add the acting client's id as a `may_act` entry's `sub` (with no `iss`), or stop minting `may_act` onto subject tokens that are meant to be freely exchangeable. Security note 8.
- **The issued token's lifetime is capped by the subject token's**, and a subject token with no remaining lifetime is refused with `invalid_grant`. Consumers that relied on an exchange refreshing the clock must re-authenticate instead. Security note 16.
- **`token_type` is `"DPoP"` for a DPoP-bound issued token.** Clients that hard-coded `Bearer` from this endpoint's response must read `token_type`. This is a fix: the previous envelope was rejected by the provider's own protected-resource middleware. Security note 17.

## Breaking changes (v0.5.0)

- **`createSelfIssuedAccessTokenValidator({ issuer })` requires `issuer`.**
  The `issuer` field on `CreateSelfIssuedAccessTokenValidatorOptions` is
  no longer optional and must be a non-empty string. Constructing the
  validator without it throws synchronously. Without an issuer, any
  `access_token`-typed JWT signed by the same KeyStore could pass
  validation — a token-type confusion vector. Most consumers do not
  invoke this factory directly and pick up `issuer` automatically from
  `config.oauth.jwt.issuer` via `tokenExchangeModule`; only direct
  callers of the factory function need to update their call sites.
- **`tokenExchangeModule` declares `configSchema` requiring
  `config.oauth.jwt.issuer: string().min(1)`.** Boot fails with
  `BootError(reason: "config-validation-failed")` when the issuer is
  missing or empty. The schema is intersected over the core schema's
  optional issuer via `composeConfigSchema`, so the more-restrictive
  module schema wins.

## RFC references

- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — OAuth 2.0 Token Exchange
- [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) — Resource Indicators (`invalid_target`)
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0 core
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) — Token Introspection
