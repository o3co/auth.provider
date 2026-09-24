# @o3co/auth-provider-oauth-token-exchange

Last updated: 2026-09-25

RFC 8693 Token Exchange grant for [auth.provider](https://github.com/o3co/auth.provider).
Supports on-behalf-of, delegation (`act` claim), and scope / audience narrowing.

## Responsibility

**Role.** The `urn:ietf:params:oauth:grant-type:token-exchange` grant handler, and the built-in validator for this provider's own access tokens presented as `subject_token` or `actor_token`. The package has no route: `tokenExchangeModule` contributes the handler as a `grants` entry, core's boot planner puts it in the `grantHandlerResolver`, and [`@o3co/auth-provider-oauth`](../oauth/README.md)'s `oauthModule` dispatches `POST /oauth/token` requests of this grant type to it. A composition therefore installs both — a dependency through composition, not an import.

**Owns:**

- the exchange decision: which client may exchange ([note 14](#security-notes), [note 15](#security-notes)), the scope and audience ceilings, `may_act`, the actor chain and the `act` claim, the sender-constraint matrices, the refresh-token family check on the `subject_token` and the `actor_token` ([note 1](#security-notes)), and the issued token's lifetime;
- the built-in `access_token` validator in [`src/validator/`](./src/validator) (`createSelfIssuedAccessTokenValidator`), which verifies a token this provider issued and consults the access-token denylist and the subject watermark. It reads a token's `family_id` but leaves the family check to the handler.

**Does not own:**

- the validator contract — `ExchangeTokenValidator`, `ValidatedToken`, `ExchangeTokenValidationContext` — which is core's ([`token-exchange/validator.mts`](../core/src/token-exchange/validator.mts)), nor the `TokenExchangeValidatorResolver` the boot planner builds from every module's `tokenExchangeValidators` contribution ([`modules/manifest/synthetic-keys.mts`](../core/src/modules/manifest/synthetic-keys.mts));
- the HTTP route, client authentication and the dispatch-time grant-type allowlist — `@o3co/auth-provider-oauth`;
- validators for other token types, such as external JWTs — the deployment's own modules ([below](#external-jwt-subject_token));
- the revocation stores it consults (`refreshTokenFamilyRevocation`, `accessTokenDenylist`, `subjectRevocation`).

**Why a separate package.** Token exchange is optional, and not installing the module is how it is disabled; keeping it out of `@o3co/auth-provider-oauth` keeps a deployment that does not exchange tokens from carrying the grant at all. It depends on core alone — the handler and the validator need only core's grant and validator contracts — so it does not import the oauth package, and a sibling can contribute further validators without depending on either.

The resolver the grant reads is the one core's boot planner builds; the package keeps no validator registry of its own. Everything under `src/` outside `__tests__` is reached from `src/index.mts` and is published; test scaffolding stays under `__tests__`.

## Install

```sh
npm install @o3co/auth-provider-oauth-token-exchange @o3co/auth-provider-core @o3co/auth-provider-oauth express express-session
```

Peer dependency: `@o3co/auth-provider-core`. The package depends on `zod`.

`@o3co/auth-provider-oauth` is not a dependency of either kind — the package
does not import it — but its `POST /oauth/token` is what serves the grant, so
the composition below installs it, with its own peers `express` and
`express-session`.

## Register the grant

```ts
import {
  createApp,
  defaultRefreshTokenFamilyRevocationModule,
  jwksModule,
  memoryRefreshTokenFamilyStoreModule,
} from "@o3co/auth-provider-core";
import { oauthModule } from "@o3co/auth-provider-oauth";
import { tokenExchangeModule } from "@o3co/auth-provider-oauth-token-exchange";

const handle = await createApp({
  modules: [
    oauthModule({ config }), // serves POST /oauth/token, which dispatches the exchange
    tokenExchangeModule,
    // refreshTokenFamilyRevocation, so an exchange can see a revoked family (note 1).
    // The memory store is single-replica; @o3co/auth-provider-redis ships a shared one.
    memoryRefreshTokenFamilyStoreModule,
    defaultRefreshTokenFamilyRevocationModule,
    // The grant requires oauth.jwt.issuer, and with an issuer configured the
    // discovery document needs the jwks_uri this module contributes.
    jwksModule,
    // …the modules that provide clientRepository, codeRepository and keyStore
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});
// on shutdown
await handle.dispose();
```

The grant type URI is `urn:ietf:params:oauth:grant-type:token-exchange` (IETF registered).

The built-in `access_token` validator is contributed by `tokenExchangeModule` itself. Consumers do not create or mutate a validator registry.

`oauthModule` has requirements of its own — `endpoints.login.url`, and the absence decisions for `auditSink` and the revocation stores — listed in the oauth README's [Composing it](../oauth/README.md#composing-it). What this module requires, what it reads optionally and which absent slots must be declared is its manifest, [`module.mts`](./src/module.mts): it requires `config`, `clientRepository` and `keyStore`, and `oauth.jwt.issuer` must be a non-empty string or boot fails with `config-validation-failed`. `accessTokenDenylist` and `subjectRevocation` are optional to wire but not to decide: an unfilled one must be declared with `oauth.revocation.accessToken = "unsupported"` / `oauth.revocation.subject = "unsupported"`, or boot refuses.

## Public API

Exported from [`src/index.mts`](./src/index.mts):

- `tokenExchangeModule` — [`module.mts`](./src/module.mts). The module value to install.
- `createTokenExchangeGrant`, `TokenExchangeDependencies`, `TOKEN_EXCHANGE_GRANT_TYPE`, `ACCESS_TOKEN_TYPE` — [`grant.mts`](./src/grant.mts). The handler itself, for a composition that dispatches it from its own route.
- `createSelfIssuedAccessTokenValidator`, `CreateSelfIssuedAccessTokenValidatorOptions` — [`validator/selfIssuedAccessToken.mts`](./src/validator/selfIssuedAccessToken.mts). The built-in validator. `issuer` is required; the factory throws without a non-empty one, because without it an `at+jwt` signed by the same key store but naming another issuer could pass. It takes no `refreshTokenFamilyRevocation`: the options type declares the key `never`, so a deps object spread into them does not compile, and the factory throws if the key is present, even as `undefined`. The family check is the handler's (note 1), so a composition that dispatches `createTokenExchangeGrant` itself gives that slot to the handler. The validator does not check the family: a caller using it outside `createTokenExchangeGrant` must check `familyId` itself, and refuse the token when it has no family store.

The validator contract is not re-exported: import `ExchangeTokenValidator`, `ValidatedToken` and `ExchangeTokenValidationContext` from `@o3co/auth-provider-core`.

## Disabling the module

There is no config-driven switch: installing `tokenExchangeModule` is enabling the grant. To disable token exchange, **leave `tokenExchangeModule` out of the composition**. Per client, a registration that does not name the grant in `allowedGrantTypes` cannot use it (note 15).

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

- **`allowedGrantTypes` must name the exchange grant type.** This grant denies by absence: a registration that omits the field, or names other grants only, is refused with `unauthorized_client`. See Security note 15.
- **`allowedScopes` bounds the granted scope**, on top of the subject token's own scope. Empty or omitted means no scope is granted. See Security note 2.
- **`allowedAudiences` bounds the audience, requested or granted.** When it is empty or omitted, the only accepted audience is the client's own `clientId`. It bounds the request's `audience` parameter and a `GrantPolicyHook`'s `grantedAudience` alike, each together with the subject token's audience (see Security notes 3 and 5).

## Requesting a lifetime (`expires_in`)

A token-exchange request may carry an optional `expires_in` form parameter: the lifetime, in seconds, the client wants the issued token to have. RFC 8693 defines no such parameter and RFC 6749 §3.2 has a server ignore a parameter it does not recognise, so sending it is safe against any authorization server.

- **Absent, or sent without a value** (`expires_in=`, RFC 6749 §3.2): the token gets `oauth.accessToken.defaultExpiresIn`.
- **Present:** honoured up to `oauth.accessToken.maxExpiresIn` — a larger request is **clamped** to the max, not refused — and always capped at the subject token's remaining lifetime (Security note 16). The response's `expires_in` is the lifetime actually minted; read it rather than assuming the request was granted in full.
- **`maxExpiresIn` unset means the default.** Until the operator raises it (`OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN`), a request can shorten a token but not lengthen it. Security note 19 is what raising it costs.
- **Malformed is refused** with `400 invalid_request` naming `expires_in`: sent more than once, zero, longer than 10 digits, or anything but ASCII decimal digits — no sign, decimal point, exponent or whitespace.
- **Only this grant reads it.** Every other grant ignores the parameter and mints the default.

## External JWT subject_token

The package ships a built-in validator only for the `access_token` token type (tokens issued by this same auth.provider instance). To accept external JWTs as `subject_token`, implement `ExchangeTokenValidator` yourself and contribute it from a sibling module for `urn:ietf:params:oauth:token-type:jwt`:

```ts
import { createApp, defineModule, jwksModule } from "@o3co/auth-provider-core";
// The validator contract is core's, not this package's.
import type { ExchangeTokenValidator, ValidatedToken } from "@o3co/auth-provider-core";
import { oauthModule } from "@o3co/auth-provider-oauth";
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
    oauthModule({ config }),
    tokenExchangeModule,
    externalJwtTokenExchangeValidatorModule,
    jwksModule,
    // …the modules that provide clientRepository, codeRepository, keyStore and
    // refreshTokenFamilyRevocation, as above
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});
```

Two modules contributing a validator for the same token type is refused at boot.

**`familyId` is how a validator tells the handler about a refresh-token family.** A validator that accepts this provider's own family-bearing tokens — under any token type — must fill `ValidatedToken.familyId` from the token's `family_id`: the handler checks it against this provider's family store, refuses the token when none is wired, and copies it into the issued token so a later family revocation reaches that token too (Security notes 1 and 10). A family left only in `claims` is neither checked nor inherited. A validator of foreign tokens, whose families this provider's store does not hold, leaves `familyId` unset. An empty string counts as unset.

## Error responses

`/oauth/token` answers with the handler's `error` and `error_description` ([RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)), held to that section's character set as described at the end of this section:

- **`400 invalid_request` when the request is not valid or the `subject_token` or the `actor_token` is refused.** [RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2) requires this one code both when "the request itself is not valid" and when either token is "invalid for any reason, or [...] unacceptable based on policy". A refused token, whichever check refused it: validation (`subject_token validation failed`, note 20), the DPoP and mTLS binding matrices (`subject_token requires a DPoP proof`, `DPoP proof does not match subject_token binding`, `subject_token has compound cnf binding which is not supported (Stage 1)` and their `client certificate` and `actor_token` forms), the family rule (note 1), `may_act` (note 8), the actor-chain bound (note 9) and the subject's expiry (note 16). The request itself: a missing parameter, `actor_token` and `actor_token_type` not sent together, a `client_id` or `client_secret` that is not one string, a body `client_id` that is not the authenticated client (`client_id does not match authenticated client`, note 14), a malformed `expires_in`, and a `subject_token_type` or `actor_token_type` no validator is registered for or a `requested_token_type` other than `access_token` (`… '<type>' is not supported`) — RFC 6749 §5.2's "an unsupported parameter value". `unsupported_token_type` is not used: RFC 7009 registers it for the revocation endpoint, and RFC 8693 defines no token-type error.
- **`400 invalid_target`** for a requested `audience` outside the client's allowlist or outside the subject token's audience (`audience_widening_not_allowed`), both refused before the policy runs (note 3), and a `resource` that is not the issued audience (note 6).
- **`400 invalid_scope`** for a requested `scope` outside the subject token's or the client's (note 2).
- **`400 unauthorized_client`** when the client's `allowedGrantTypes` does not name the grant (note 15), and **`401 invalid_client`** for a public client or a failed client authentication (note 14).
- **`503 temporarily_unavailable`** when a store cannot answer — the client repository, a revocation store (notes 1 and 20) — or the policy hook throws. The token is not judged.

A `GrantPolicyHook` deny carries the hook's own `error` (`403` for `access_denied`), which must be an RFC 6749 error code: non-empty printable ASCII without `"` and `\`. Anything else is answered `invalid_request` and logged, sanitised and capped, as `token_exchange_policy_deny_error_malformed`. Its `errorDescription` is sent when it is a non-empty string, and `denied by policy` otherwise. A policy that refuses because of a token — a subject or actor it will not accept — should deny with `invalid_request`: §2.2.2 makes that the code for a token "unacceptable based on policy", and a deny with `invalid_grant` would put this grant back outside it. A decision the policy was not entitled to make is `500 server_error` (note 5): a `grantedScope` past the subject token or the registration (`policy returned scopes exceeding the subject_token scope or client allowedScopes: …`), a `grantedAudience` past the subject token's audience or the registration (`policy returned audiences outside the subject_token audience or client allowedAudiences: …`), or a non-array decision. That is core's `policyOutOfBounds`, the answer every grant gives a policy that exceeds its ceiling — the caller did nothing wrong. The request's own `scope` and `audience` are held to the same ceilings before the policy runs (`invalid_scope`, `invalid_target`), so who asked for more decides the answer.

Because `invalid_request` covers both a malformed request and a refused token, the `error_description` is what tells a client which check refused it. The descriptions quoted in this README are part of the contract. They keep to the characters [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) allows in one — printable ASCII without `"` and `\` — and quote a value the client sent with `'`; `/oauth/token` replaces any other character in the value with `?`. Every `invalid_request` this handler returns goes through one function, `invalidRequest` in [`grant.mts`](./src/grant.mts). `/oauth/token` records a refusal in the `token.issued.failure` audit event with its `error` and, as `details.reason`, its `error_description` capped at 200 characters, so a refused token and a malformed request stay apart in the audit stream too. The `refresh_token` grant answers the same binding and family rows `invalid_grant`, which is RFC 6749's code for a refresh token.

## Security notes

1. **Wire `refreshTokenFamilyRevocation`, or this provider's family-bearing access tokens cannot be exchanged.** A self-issued access token carrying `family_id` — every token the `authorization_code` and `refresh_token` grants mint — is accepted as `subject_token` or as `actor_token` only when its family's revocation state can be read. The handler owns this check, for both tokens; the built-in validator does not read the slot. The answers (for the `actor_token`, each description is prefixed `actor_token `):

   - **No `refreshTokenFamilyRevocation` in the module graph:** `invalid_request` / `refresh token family revocation not configured (revocation cannot be verified)` (fail-closed). Core's `defaultRefreshTokenFamilyRevocationModule` provides the slot over a refresh-token family store (see [Register the grant](#register-the-grant)).
   - **The family is revoked** (logout, refresh-token replay): `invalid_request` / `family_revoked` (`actor_token family_revoked`) — the description the `refresh_token` grant gives a revoked family on the same endpoint, where its code is `invalid_grant` (see [Error responses](#error-responses)). A client seeing it needs the user to authenticate again; retrying the exchange will not help.
   - **The store cannot answer:** `503 temporarily_unavailable` / `refresh token store unavailable`, logged as `token_exchange_family_store_unavailable` with the role and core's [`loggableError`](../core/README.md#logger) projection of the store's error — never the error, which for an ioredis reply carries the command it answered, the family's key included.

   The check keys on the family the validator reports (`ValidatedToken.familyId`), not on the token type: the built-in validator registered under another type, or a validator of your own that reports a family, is held to the same answers, because the issued token inherits the subject's `family_id` whichever validator produced it. A token without a family (a `client_credentials` token, say; an empty `familyId` counts as none) has nothing to check. The answers depend only on the `refreshTokenFamilyRevocation` handed to the handler, so they hold as well for a composition that dispatches `createTokenExchangeGrant` itself.

2. **Scope is bounded by two ceilings, always.** `granted scope ⊆ subject_token.scope ∩ client.allowedScopes` is enforced unconditionally, and a `GrantPolicyHook` cannot bypass either **through the request parameter** (point 5 covers the policy-level override, which is re-checked against both). An explicitly requested scope outside either ceiling is refused with `invalid_scope` naming it; an omitted `scope` inherits the subject token's, clamped to the registration.

   **An absent or empty `allowedScopes` grants no scope at all.** A registration that names no scope may receive none — deny by absence, not a permissive "unrestricted" reading. The exchange still succeeds; the issued token simply carries no `scope` claim. Without this ceiling a client registered for `read` that obtained a subject token carrying `admin` could exchange it and receive `admin`, its own registration bounding nothing.

3. **Audience ceilings — the registration and the subject token.** The `audience` request parameter must be in `client.allowedAudiences ∪ { client.clientId }` — otherwise `400 invalid_target` / `audience '<aud>' is not allowed for this client` — and in the subject token's audience (its `aud`, or the client's own id when it names none) — otherwise `400 invalid_target` / `audience_widening_not_allowed: <audiences>`, the code RFC 8693 §2.2.2 gives a target the server will not issue for. Both are checked before the policy hook runs, so what a policy does afterwards cannot change the answer to the client's own request. Empty `allowedAudiences` means only the client's own `clientId` is a valid exchange audience. A policy's `grantedAudience` is held to the same two ceilings (note 5).

4. **Cross-client audience confusion defense.** When the `audience` request parameter is omitted, the handler inherits `subject_token.aud` only if it is in `client.allowedAudiences ∪ { client.clientId }`. Otherwise it falls back to `clientId`. This prevents a malicious client from exchanging a stolen token outside its intended audience just by omitting the audience parameter.

5. **Policy hook widening is always rejected.** The `GrantPolicyHook.evaluate()` result's `grantedScope` and `grantedAudience` may narrow the request-derived values, never widen them. Each is checked before it replaces the request's value, against the ceilings the request met: `grantedScope` against **both** the subject token's scope and `client.allowedScopes` (note 2), `grantedAudience` against **both** the subject token's audience and `client.allowedAudiences ∪ { client.clientId }` (note 3) — the registration bound core's `boundPolicyAudience` applies for every other grant, plus the subject token's. A decision past either is the deployment's policy exceeding its authority, not the caller's mistake, and is answered as every other grant answers it, with core's `policyOutOfBounds`: `500 server_error` / `policy returned scopes exceeding the subject_token scope or client allowedScopes: <scopes>` or `policy returned audiences outside the subject_token audience or client allowedAudiences: <audiences>`, logged as `token_exchange_policy_scope_refused` / `token_exchange_policy_audience_refused`. An empty `grantedAudience` is no decision, as `boundPolicyAudience` reads it: the request's audience, or the default of note 4, stands. An empty `grantedScope` strips every scope. There is no opt-in to bypass either check.

6. **Resource indicators must equal the issued-token audience.** When the request includes RFC 8707 `resource`, every requested resource must equal `audienceForToken` — the single value that will be minted into the issued token's `aud` claim (typically `grantedAudience[0]`). Multi-resource requests whose resources cannot all be represented in the single-valued `aud` are rejected with `invalid_target` / `requested_resources_not_in_audience`. This avoids issuing a token whose `aud` silently disagrees with the requested resource (RFC 8707 §3). A resource no issued audience could equal — neither the client's own id nor an audience both its registration and the subject token carry (note 3) — is refused before the policy hook runs, so what a policy does with the resource cannot turn the caller's `400` into a `500`, and a policy deny is not reached. That early refusal names every requested resource the audience the request itself asks for would not equal: the same list the check after the policy gives, unless a policy would have replaced the audience — then the later check would have compared against the policy's audience, and the early one compares against the request's.

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

8. **`may_act` is enforced when present — on both exchange shapes.** If a subject token carries a `may_act` claim, the party acting on the subject's behalf must match one of its `{ sub?, iss? }` constraints. Malformed or non-matching values fail closed with `may_act_violation`; subject tokens without `may_act` continue to use the policy-hook boundary.

   Which party that is depends on the exchange. **Delegation** (`actor_token` supplied): the actor token must match, comparing `sub` against its subject and `iss` against its issuer. **Impersonation** (no `actor_token`, note 7): the authenticated calling client is the actor, and its `clientId` must match a `may_act` entry's `sub`. Enforcing the claim only when an `actor_token` happened to be supplied would make it opt-out — omitting the parameter would skip it, so a token naming one permitted actor would be exchangeable by any exchange-enabled client that got hold of it.

   The impersonation check is deliberately narrower: an entry that also constrains `iss` is **never** satisfied by a client identity. No token was presented for the actor, so there is no issuer to compare, and substituting this AS's own issuer would be a guess in the permissive direction. Write `may_act` entries as `{ "sub": "<client-id>" }` when the intended actor is a client acting in its own name.

9. **Actor chains are bounded.** `oauth.tokenExchange.maxActorChainDepth` defaults to `3` and can be overridden with `OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH`. When an `actor_token` would add to an already-full nested `act` chain, the handler rejects the request with `actor_chain_too_deep`.

10. **Family cascade.** Issued access_tokens inherit the subject's `family_id` claim. Revoking the subject's family (e.g. on logout) automatically invalidates every token exchanged from it. This is the same mechanism auth.provider's introspect and userinfo endpoints use.

    The cascade follows the subject only. Revoking an **actor's** family refuses that actor_token in later exchanges (note 1), but does not reach tokens it already acted on: a delegated token carries the subject's `family_id` alone, and the actor appears only in its `act` claim, whose family nothing checks. When that token is exchanged again, the earlier actor becomes a nested `act`, which RFC 8693 §4.1 makes informational only.

11. **Refresh / ID tokens are never issued.** Per RFC 8693 §4.2.2 the handler only returns an access_token. The response always carries `issued_token_type: "urn:ietf:params:oauth:token-type:access_token"`.

12. **Missing subject claim rejection.** Self-issued access_tokens without a `sub` claim (or with an empty-string `sub`) are rejected with `invalid_request` / `subject_token validation failed` (`actor_token validation failed` for an `actor_token`). This prevents a silently-anonymous token from reaching downstream services.

13. **Validator contributions are immutable after boot.** The boot planner aggregates `tokenExchangeValidators` contributions, freezes the world during activation, and exposes only a read-only resolver to the grant handler. Post-boot mutation cannot replace the built-in validator at runtime.

14. **Confidential clients only.** A public client (`tokenEndpointAuthMethod: "none"`) is refused with `401 invalid_client`. Through `/oauth/token` the client has already been authenticated by the oauth package's client authentication — `client_secret_basic`, `client_secret_post` or `private_key_jwt` — and the handler uses that identity, re-reading the record with `clientRepository.findById()`. A body `client_id` that disagrees with the authenticated client is refused there by client authentication itself (`401 invalid_client`); the handler's own `400 invalid_request` for a mismatch applies only where something other than that middleware supplied `ctx.authenticatedClient`. A composition that dispatches the handler without client-authentication middleware (`ctx.authenticatedClient === null`) must send `client_id` and `client_secret` in the body, which the handler checks with `clientRepository.authenticate()`: a missing secret is `401 invalid_client`, and so is a failed authentication. A client-repository failure is `503 temporarily_unavailable` on either path.

15. **The grant denies by absence of `allowedGrantTypes` (#326).** Token exchange mints a fresh credential out of one a client already holds — a standing capability of a registration, not a per-user ceremony — so it is never acquired by omission. The handler declares `requiresExplicitGrantAllowlist`, which `/oauth/token` dispatch enforces before `handle` runs, and repeats the check itself for a composition that dispatches it without client-authentication middleware (`ctx.authenticatedClient === null`), where no dispatch rule runs at all. Both paths refuse with `400 unauthorized_client` / `client is not authorized for grant_type 'urn:ietf:params:oauth:grant-type:token-exchange'`, the words every `/oauth/token` allowlist refusal uses. This does not depend on `oauth.requireGrantTypeAllowlist`, which defaults off; the two compose to the stricter rule.

16. **The issued token never outlives the subject token (RFC 8693 §2.2.1), nor exceeds `oauth.accessToken.maxExpiresIn`.** `expires_in` is `min(requested expires_in ?? oauth.accessToken.defaultExpiresIn, oauth.accessToken.maxExpiresIn, subject_token exp − now)`, where `now` is the one issuance instant the minted `iat` and `exp` are also measured from — so the cap and the stamp cannot land in different seconds and put `exp` past the subject's. A chain of exchanges therefore cannot refresh the clock past the credential it descends from, and a client cannot ask its way past the operator's max (see [Requesting a lifetime](#requesting-a-lifetime-expires_in)). A subject token with no remaining lifetime — already expired, or expiring within the current second — is refused with `invalid_request` / `subject_token has expired` rather than minting a token with a zero or negative lifetime. A subject token carrying **no `exp` claim at all** leaves `min(requested ?? default, max)` standing: there is no lifetime for the cap to descend from. The built-in validator never produces one (jose rejects an expired token before the handler sees it); a consumer-implemented validator that returns an `exp`-less `ValidatedToken` is asserting an unbounded credential, and should not do so lightly.

17. **A DPoP-bound issued token is advertised as `token_type: "DPoP"` (RFC 9449 §5).** The response envelope names the mechanism the issued `cnf` actually binds, read off the confirmation stamped into the token. mTLS-bound tokens keep `"Bearer"` — RFC 8705 §3 does not redefine the wire-level type. A client must read `token_type`: this provider's own protected-resource middleware refuses a `cnf.jkt` token presented as Bearer (RFC 9449 §7.1).

18. **Nothing ties the `subject_token` to the calling client.** This is a known property, stated rather than fixed. The built-in validator does not pin `aud` — `ExchangeTokenValidationContext` deliberately does not carry the calling-client identity, and the central verifier records the gap as `jwt_verify_aud_skipped` — and omitting the `audience` parameter falls back to the caller's own `clientId` (note 4). So an exchange-enabled client can present a self-issued access token it legitimately obtained and re-audience it to itself.

    What bounds the consequence is the registration, which is why notes 2 and 15 matter beyond their own findings: the re-audienced token cannot carry a scope outside the client's `allowedScopes`, cannot outlive the subject or exceed `maxExpiresIn` (note 16), and cannot be minted at all by a client whose registration does not name this grant. The escalation is therefore bounded by what the client was already registered to hold, not by what the subject token happened to carry.

    **Recommended:** gate the grant with a `GrantPolicyHook` (`grantPolicy`) that asserts the relationship your deployment expects between the subject token and the caller — the hook is the layer that has both identities in hand. Registrations that do not need token exchange should simply omit it from `allowedGrantTypes`, which note 15 makes sufficient.

19. **`oauth.accessToken.maxExpiresIn` bounds the offline-revocation window of an exchanged token.** Revoking the subject's family (note 10) stops an exchanged token wherever the family is consulted — introspection, userinfo, a verifier that checks revocation. A resource server that validates the JWT offline, by signature and `exp` alone, cannot observe that and keeps accepting the token until it expires. The longest that can be is the issued lifetime, and the longest a token-exchange request can make the issued lifetime is `maxExpiresIn`. Unset, it equals `defaultExpiresIn`, so the window is the default lifetime. Raise it only as far as you accept an exchanged token outliving its revocation at such a resource server.

20. **A revoked access token cannot be exchanged, and a revocation store that cannot answer is `503 temporarily_unavailable`, not a verdict on the token.** The built-in validator consults the access-token denylist (by `jti`) and the subject watermark for the `subject_token` and the `actor_token`, as userinfo and introspection do, so revoking an access token also stops it being exchanged: a denylisted or watermarked token is `invalid_request` / `subject_token validation failed` (`actor_token validation failed` for the actor). When either store cannot be read, the token is still refused, but the answer is `503 temporarily_unavailable` / `subject_token validation store unavailable` (`actor_token …` for the actor): an outage says nothing about the token, and an answer that judged it would tell the client to discard a credential that may be perfectly good. The validator follows core's `ExchangeTokenValidator` contract — `null` for a token that is not acceptable, a throw for an answer that is not knowable — and tells the two apart with core's `isRevocationUnavailable`, as the `refresh_token` grant does. The family store's answers are note 1's.

## What it does not do

- `saml1` / `saml2` subject token types.
- Token type conversion (access ↔ id, access → refresh): answered `invalid_request` / `requested_token_type '<type>' is not supported`.
- Validate external JWTs out of the box: implement a validator ([above](#external-jwt-subject_token)).

Sender-constrained exchange is supported: the handler enforces the DPoP and mTLS `cnf` matrices on the `subject_token` and the `actor_token`, stamps the proven binding into the issued token, and advertises `token_type: "DPoP"` for a `cnf.jkt` token (Security note 17). [`senderConstraint.test.mts`](./src/__tests__/senderConstraint.test.mts) holds the matrix rows.

## Tests

[`grant.test.mts`](./src/__tests__/grant.test.mts) and [`hardening.test.mts`](./src/__tests__/hardening.test.mts) pin the handler's refusals, [`act.test.mts`](./src/__tests__/act.test.mts) the actor chain and `may_act`, [`selfIssuedAccessToken.test.mts`](./src/__tests__/selfIssuedAccessToken.test.mts) the built-in validator, and [`grant-integration.test.mts`](./src/__tests__/grant-integration.test.mts) the module's manifest, the family answers of note 1, the store-outage answers of note 20, the code and description of every token refusal in [Error responses](#error-responses), and which answer a scope or audience past the ceilings gets depending on whether the request or the policy asked for it, with `tokenExchangeModule` booted through `createApp`. [`oauth-token-route.test.mts`](./src/__tests__/oauth-token-route.test.mts) makes the exchange over HTTP, through `oauthModule`'s `POST /oauth/token` in the composition [Register the grant](#register-the-grant) shows: client authentication, the allowlist answers of note 15, the response the route writes, and the §5.2 character set of a description that quotes the request. [`published-files.test.mts`](./src/__tests__/published-files.test.mts) holds that every source file the build publishes is reached from the entry point.

## RFC references

- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — OAuth 2.0 Token Exchange (§2.2.2: `invalid_request`, `invalid_target`)
- [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) — Resource Indicators (`invalid_target`)
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0 core
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) — Token Introspection
