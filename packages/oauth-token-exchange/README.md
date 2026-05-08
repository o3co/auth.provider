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

Add `allowedAudiences` to the client record to permit audience narrowing to specific API identifiers:

```yaml
clients:
  billing-gateway:
    clientSecret: "..."
    allowedScopes: ["read", "write"]
    allowedAudiences: ["billing-service", "inventory-service"]
```

When `allowedAudiences` is empty or omitted, the only accepted `audience` parameter value is the client's own `clientId`. This allowlist applies to the **request's `audience` parameter only** — a `GrantPolicyHook` can override `grantedAudience` in its decision, which is not re-validated against the allowlist (see Security note 4 for the rationale). If you want hard-boundary enforcement across both paths, write your policy hook defensively.

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

2. **Scope is always narrowed by the core handler.** `requested scope ⊆ subject_token.scope` is enforced unconditionally — a `GrantPolicyHook` cannot bypass this subset check for narrowing **through the request parameter**. However, see point 5 below about policy-level override.

3. **Audience allowlist (client-scoped).** The `audience` request parameter must be in `client.allowedAudiences ∪ { client.clientId }`. This is enforced by the core handler before the policy hook runs. Empty `allowedAudiences` means only the client's own `clientId` is a valid exchange audience.

4. **Cross-client audience confusion defense.** When the `audience` request parameter is omitted, the handler inherits `subject_token.aud` only if it is in `client.allowedAudiences ∪ { client.clientId }`. Otherwise it falls back to `clientId`. This prevents a malicious client from exchanging a stolen token outside its intended audience just by omitting the audience parameter.

5. **Policy hook widening is rejected by default.** The `GrantPolicyHook.evaluate()` result's `grantedScope` and `grantedAudience` are still allowed to override the request-derived values, but the handler re-checks them against the validated `subject_token` boundary before minting. Scope or audience widening returns `invalid_target` with `scope_widening_not_allowed` or `audience_widening_not_allowed`. Direct callers of `createTokenExchangeGrant()` can set the deprecated `allowPolicyWidening` migration escape hatch while replacing old widening policies; module wiring keeps the safe default.

6. **Resource indicators must be represented in the issued audience.** When the request includes RFC 8707 `resource`, every requested resource must appear in the effective `grantedAudience` used for the exchange. A resource/audience mismatch returns `invalid_target` with `requested_resources_not_in_audience`.

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

8. **`may_act` is enforced when present.** If a subject token carries a `may_act` claim, the supplied `actor_token` must match one of its `{ sub?, iss? }` constraints. Malformed or non-matching `may_act` values fail closed with `may_act_violation`; subject tokens without `may_act` continue to use the existing policy-hook boundary.

9. **Actor chains are bounded.** `oauth.tokenExchange.maxActorChainDepth` defaults to `3` and can be overridden with `OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH`. When an `actor_token` would add to an already-full nested `act` chain, the handler rejects the request with `actor_chain_too_deep`.

10. **Family cascade.** Issued access_tokens inherit the subject's `family_id` claim. Revoking the subject's family (e.g. on logout) automatically invalidates every token exchanged from it. This is the same mechanism auth.provider's introspect and userinfo endpoints use.

11. **Refresh / ID tokens are never issued.** Per RFC 8693 §4.2.2 the handler only returns an access_token. The response always carries `issued_token_type: "urn:ietf:params:oauth:token-type:access_token"`.

12. **Missing subject claim rejection.** Self-issued access_tokens without a `sub` claim (or with an empty-string `sub`) are rejected with `invalid_grant`. This prevents a silently-anonymous token from reaching downstream services.

13. **Validator contributions are immutable after boot.** The boot planner aggregates `tokenExchangeValidators` contributions, freezes the world during activation, and exposes only a read-only resolver to the grant handler. Post-boot mutation cannot replace the built-in validator at runtime.

14. **Confidential clients only (v0.5.0).** The handler requires `client_secret` and authenticates via `clientRepository.authenticate()`. Requests without a secret are rejected with `invalid_client` (401). The core `Client` type carries `clientSecret: string` as a required field and `PublicClient = Omit<Client, "clientSecret">`, so `findById()` alone cannot tell a "no secret configured" client from "secret omitted by caller" — accepting the unauthenticated path would let an attacker exchange a stolen `subject_token` under any client's allowlist. Public-client support is deferred until a `Client.public` flag (or equivalent) lands in core.

## Registration pattern summary

- Import `tokenExchangeModule` and any sibling modules that contribute additional validators
- Boot the app with `await createApp({ modules: [...], bootstrapComponents: { config, pathResolver } })`
- Call `handle.dispose()` during shutdown

## Unsupported RFC 8693 features (v0.5.0 scope-out)

- `saml1` / `saml2` subject token types
- Token type conversion (access ↔ id, access → refresh): returns `unsupported_token_type`
- DPoP-bound token minting (planned for 1.0 GA)
- Built-in external JWT validator (consumer-implement; planned as a separate package post-0.5)

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
