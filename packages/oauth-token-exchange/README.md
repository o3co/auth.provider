# @o3co/auth-provider-oauth-token-exchange

RFC 8693 Token Exchange grant for [auth.provider](https://github.com/o3co/auth.provider).
Supports on-behalf-of, delegation (`act` claim), and scope / audience narrowing.

## Install

```bash
pnpm add @o3co/auth-provider-oauth-token-exchange
```

## Register the grant

```ts
import { GrantRegistry } from "@o3co/auth-provider-core";
import {
  ExchangeTokenValidatorRegistry,
  createSelfIssuedAccessTokenValidator,
  tokenExchangeModule,
} from "@o3co/auth-provider-oauth-token-exchange";

const validatorRegistry = new ExchangeTokenValidatorRegistry();
validatorRegistry.register(
  "urn:ietf:params:oauth:token-type:access_token",
  // Signature + typ + issuer check only. Revocation is handled by the
  // grant handler via deps.refreshTokenStore so the specific
  // `family_revoked` errorDescription can be surfaced (spec §5.3).
  createSelfIssuedAccessTokenValidator({
    keyStore,
    issuer,
  }),
);

grantRegistry.addModule(tokenExchangeModule, {
  ...deps,
  refreshTokenStore,  // REQUIRED — handler uses this for cascading revoke
  validatorRegistry,
  clientRepository,
});
```

The grant type URI is `urn:ietf:params:oauth:grant-type:token-exchange` (IETF registered).

After `addModule` returns, the `validatorRegistry` is frozen — subsequent `register()` calls throw. This prevents a consumer reference from silently replacing the built-in validator at runtime.

## Disabling the module

There is no config-driven disable switch. To disable Token Exchange, **do not import `tokenExchangeModule`** (do not call `grantRegistry.addModule(tokenExchangeModule, ...)`).

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

The package ships a built-in validator only for the `access_token` token type (tokens issued by this same auth.provider instance). To accept external JWTs as `subject_token`, implement `ExchangeTokenValidator` yourself and register it for `urn:ietf:params:oauth:token-type:jwt`:

```ts
import type { ExchangeTokenValidator, ValidatedToken } from "@o3co/auth-provider-oauth-token-exchange";

class ExternalJwtValidator implements ExchangeTokenValidator {
  async validate(
    token: string,
    ctx: { role: "subject" | "actor" },
  ): Promise<ValidatedToken | null> {
    // Fetch jwks, verify signature, check issuer allowlist, consult remote
    // introspection for revocation — all are YOUR responsibility.
    // Return null on validation failure; throw on infrastructure failure (→ 503).
  }
}

validatorRegistry.register(
  "urn:ietf:params:oauth:token-type:jwt",
  new ExternalJwtValidator({ /* your config */ }),
);
```

## Security notes

1. **refreshTokenStore must be wired into the grant dependencies (not into the validator)** so the handler can surface the specific `family_revoked` errorDescription (spec §5.3). Without `refreshTokenStore` in the grant deps, self-issued access_tokens carrying `family_id` cannot be revocation-checked; the handler returns `invalid_grant` (fail-closed). Leaving it absent from the validator is intentional — the handler owns revocation so the specific error can propagate. See the "Register the grant" example above.

2. **Scope is always narrowed by the core handler.** `requested scope ⊆ subject_token.scope` is enforced unconditionally — a `GrantPolicyHook` cannot bypass this subset check for narrowing **through the request parameter**. However, see point 5 below about policy-level override.

3. **Audience allowlist (client-scoped).** The `audience` request parameter must be in `client.allowedAudiences ∪ { client.clientId }`. This is enforced by the core handler before the policy hook runs. Empty `allowedAudiences` means only the client's own `clientId` is a valid exchange audience.

4. **Cross-client audience confusion defense.** When the `audience` request parameter is omitted, the handler inherits `subject_token.aud` only if it is in `client.allowedAudiences ∪ { client.clientId }`. Otherwise it falls back to `clientId`. This prevents a malicious client from exchanging a stolen token outside its intended audience just by omitting the audience parameter.

5. **Policy hook widening is permitted by design.** The `GrantPolicyHook.evaluate()` result's `grantedScope` and `grantedAudience` override the handler's pre-narrowed values without re-verification. A first-party consumer policy CAN widen scope or audience if it wants to — this is the intentional escape hatch for operational needs (e.g., an admin flow that grants a superset). Consumers own the consequences of widening policies. If you want strict narrowing-only policies, write your `evaluate()` method defensively and never return `grantedScope`/`grantedAudience` that exceeds what you were given.

6. **Impersonation vs delegation.** An exchange without `actor_token` issues an impersonation token (no `act` claim). Deployments that require audit trails should add a `GrantPolicyHook` that rejects requests lacking `actor_token`:

   ```ts
   async evaluate(req) {
     if (req.grantType === "urn:ietf:params:oauth:grant-type:token-exchange" && !req.actorTokenType) {
       return { outcome: "deny", error: "invalid_request",
                errorDescription: "actor_token required for delegation" };
     }
     return { outcome: "allow" };
   }
   ```

7. **Family cascade.** Issued access_tokens inherit the subject's `family_id` claim. Revoking the subject's family (e.g. on logout) automatically invalidates every token exchanged from it. This is the same mechanism auth.provider's introspect and userinfo endpoints use.

8. **Refresh / ID tokens are never issued.** Per RFC 8693 §4.2.2 the handler only returns an access_token. The response always carries `issued_token_type: "urn:ietf:params:oauth:token-type:access_token"`.

9. **Missing subject claim rejection.** Self-issued access_tokens without a `sub` claim (or with an empty-string `sub`) are rejected with `invalid_grant`. This prevents a silently-anonymous token from reaching downstream services.

10. **Validator registry is sealed at registration.** Once `grantRegistry.addModule(tokenExchangeModule, ...)` is called, the `validatorRegistry` passed in is frozen — subsequent `register()` calls throw. This prevents a consumer reference from replacing the built-in validator at runtime.

11. **Confidential clients only (v0.5.0).** The handler requires `client_secret` and authenticates via `clientRepository.authenticate()`. Requests without a secret are rejected with `invalid_client` (401). The core `Client` type carries `clientSecret: string` as a required field and `PublicClient = Omit<Client, "clientSecret">`, so `findById()` alone cannot tell a "no secret configured" client from "secret omitted by caller" — accepting the unauthenticated path would let an attacker exchange a stolen `subject_token` under any client's allowlist. Public-client support is deferred until a `Client.public` flag (or equivalent) lands in core.

## Registration pattern summary

- Consumer creates `ExchangeTokenValidatorRegistry` and registers validators for each supported `subject_token_type`
- Consumer calls `grantRegistry.addModule(tokenExchangeModule, { ..., validatorRegistry, clientRepository })`
- Module factory receives deps, calls `validatorRegistry.freeze()`, returns the grant handler
- Post-wire, the registry is immutable — consumers cannot mutate it even via their own reference

## Unsupported RFC 8693 features (v0.5.0 scope-out)

- `saml1` / `saml2` subject token types
- Token type conversion (access ↔ id, access → refresh): returns `unsupported_token_type`
- DPoP-bound token minting (planned for 1.0 GA)
- Built-in external JWT validator (consumer-implement; planned as a separate package post-0.5)

## RFC references

- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — OAuth 2.0 Token Exchange
- [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) — Resource Indicators (`invalid_target`)
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0 core
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) — Token Introspection
