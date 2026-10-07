# @o3co/auth-provider-oauth-token-exchange

Last updated: 2026-10-07

RFC 8693 Token Exchange grant for [auth.provider](https://github.com/o3co/auth.provider).
Supports on-behalf-of, delegation (`act` claim), and scope / audience narrowing.

## Responsibility

**Role.** The `urn:ietf:params:oauth:grant-type:token-exchange` grant handler, and the built-in validator for this provider's own access tokens presented as `subject_token` or `actor_token`. The package has no route: `tokenExchangeModule` contributes the handler as a `grants` entry, core's boot planner puts it in the `grantHandlerResolver`, and [`@o3co/auth-provider-oauth`](../oauth/README.md)'s `oauthEndpointsModule` dispatches `POST /oauth/token` requests of this grant type to it. A composition therefore installs both — a dependency through composition, not an import.

**Owns:**

- the exchange decision: which client may exchange ([note 14](#security-notes), [note 15](#security-notes)), which subject tokens it may present ([note 18](#security-notes)), the scope and audience ceilings, `may_act`, the actor chain and the `act` claim, the sender-constraint matrices, the refresh-token family check on the `subject_token` and the `actor_token` ([note 1](#security-notes)), the session check and the `sid` the issued token carries ([note 21](#security-notes)), the authentication context it carries ([note 23](#security-notes)), and the issued token's lifetime;
- the built-in `access_token` validator in [`src/validator/`](./src/validator) (`createSelfIssuedAccessTokenValidator`), which verifies a token this provider issued and consults the access-token denylist and the subject watermark. It reads a token's `family_id`, and its session from `sid` or — for a token that was itself exchanged — `liveness_sid`, but leaves the family and session checks to the handler; and it records, for the handler alone, the `acr`, `amr` and `auth_time` it verified (note 23).

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
import { oauthEndpointsModule } from "@o3co/auth-provider-oauth";
import { tokenExchangeModule } from "@o3co/auth-provider-oauth-token-exchange";

const handle = await createApp({
  modules: [
    oauthEndpointsModule, // serves POST /oauth/token, which dispatches the exchange
    tokenExchangeModule,
    // refreshTokenFamilyRevocation, so an exchange can see a revoked family (note 1).
    // The memory store is single-replica; @o3co/auth-provider-redis ships a shared one.
    memoryRefreshTokenFamilyStoreModule,
    defaultRefreshTokenFamilyRevocationModule,
    // oauthEndpointsModule requires oauth.jwt.issuer, and with an issuer configured the
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

`oauthEndpointsModule` has requirements of its own — a `loginEntry` provider where it builds `/authorize`, and the absence decisions for `auditSink` and the revocation stores — listed in the oauth README's [Composing it](../oauth/README.md#composing-it). What this module requires, what it reads optionally and which absent slots must be declared is its manifest, [`module.mts`](./src/module.mts): it requires `oauthTokenSettings`, `clientRepository` and `keyStore`, and reads nothing of the whole configuration — only its own section and those slots. `oauthTokenSettings` carries the issuer and `legacyTypAccept` a subject token is held to and the lifetimes the grant mints within: `oauthEndpointsModule` provides it, and a composition without the oauth module fills it itself (core's [`OAuthTokenSettings`](../core/src/token-settings/types.mts)); unfilled, boot refuses with `missing-required-component`. `accessTokenDenylist` and `subjectRevocation` are optional to wire but not to decide: an unfilled one must be declared with `oauth.revocation.accessToken = "unsupported"` / `oauth.revocation.subject = "unsupported"`, or boot refuses. `userSessionStore` is optional as it is on `oauthEndpointsModule`, but a wired one requires core's session lifecycle beside it: the `sessionLifecycle` slot, which `sessionLifecycleModule` fills, or boot refuses with `contribute-factory-failed`, naming both slots. The exchange reads a presented token's session through the lifecycle's `liveness`, so a token whose session has ended, or is closing, is refused (note 21). A sessionless composition wires neither.

## Public API

Exported from [`src/index.mts`](./src/index.mts):

- `tokenExchangeModule` — [`module.mts`](./src/module.mts). The module value to install.
- `createTokenExchangeGrant`, `TokenExchangeDependencies`, `TOKEN_EXCHANGE_GRANT_TYPE`, `ACCESS_TOKEN_TYPE` — [`grant.mts`](./src/grant.mts). The handler itself, for a composition that dispatches it from its own route. It takes `oauthTokenSettings`, required, and no `config`; it holds the value to its contract, not to the lifetimes core resolves from the configuration. Within `createApp` boot holds every slot to those before a factory runs; a caller building the handler outside `createApp` owns that bound and passes the snapshot `checkOAuthTokenSettings(value, config)` answers, or a token could be minted to outlive the records that revoke it. `section.maxActorChainDepth` is the module's section's key (3 when not given).
- `createSelfIssuedAccessTokenValidator`, `CreateSelfIssuedAccessTokenValidatorOptions` — [`validator/selfIssuedAccessToken.mts`](./src/validator/selfIssuedAccessToken.mts). The built-in validator. `issuer` is required; the factory throws without a non-empty one, because without it an `at+jwt` signed by the same key store but naming another issuer could pass. It takes no `refreshTokenFamilyRevocation`: the options type declares the key `never`, so a deps object spread into them does not compile, and the factory throws if the key is present, even as `undefined`. The family check is the handler's (note 1), so a composition that dispatches `createTokenExchangeGrant` itself gives that slot to the handler. The validator does not check the family: a caller using it outside `createTokenExchangeGrant` must check `familyId` itself, and refuse the token when it has no family store — and, the same way, check the session its `sid` names against a `UserSessionStore` (note 21), which the validator does not.

The validator contract is not re-exported: import `ExchangeTokenValidator`, `ValidatedToken` and `ExchangeTokenValidationContext` from `@o3co/auth-provider-core`.

## Disabling the module

There is no config-driven switch: installing `tokenExchangeModule` is enabling the grant. To disable token exchange, **leave `tokenExchangeModule` out of the composition**. Per client, a registration that does not name the grant in `allowedGrantTypes` cannot use it (note 15).

## Client configuration

A client registration is the ceiling for an exchange on every axis. Every field below is read by this grant:

```yaml
clients:
  billing-gateway:
    clientSecret: "..."
    allowedGrantTypes: ["urn:ietf:params:oauth:grant-type:token-exchange"]
    allowedScopes: ["read", "write"]
    allowedAudiences: ["billing-service", "inventory-service"]
    # Only for a client that exchanges tokens issued to other clients:
    # allowExchangeOfTokensIssuedToOthers: true
```

- **`allowedGrantTypes` must name the exchange grant type.** This grant denies by absence: a registration that omits the field, or names other grants only, is refused with `unauthorized_client`. See Security note 15.
- **`allowedScopes` bounds the granted scope**, on top of the subject token's own scope. Empty or omitted means no scope is granted. See Security note 2.
- **`allowedAudiences` bounds the audience, requested or granted.** When it is empty or omitted, the only accepted audience is the client's own `clientId`. It bounds the request's `audience` parameter and a `GrantPolicyHook`'s `grantedAudience` alike, each together with the subject token's audience (see Security notes 3 and 5).
- **`allowExchangeOfTokensIssuedToOthers` lets the client present a subject token that does not name it.** By default a `subject_token` is accepted only when its `azp` is the client's id or its `aud` contains it. A gateway or an on-behalf-of service that exchanges tokens issued to other clients sets it to `true`. A boolean, optional, read with a strict `=== true`: absent and `false` keep the default. It is read from the registration only, never from the request. See Security note 18.

## Requesting a lifetime (`expires_in`)

A token-exchange request may carry an optional `expires_in` form parameter: the lifetime, in seconds, the client wants the issued token to have. RFC 8693 defines no such parameter and RFC 6749 §3.2 has a server ignore a parameter it does not recognise, so sending it is safe against any authorization server.

- **Absent, or sent without a value** (`expires_in=`, RFC 6749 §3.2): the token gets `oauth.accessToken.defaultExpiresIn`. Both lifetimes, and the issuer and `legacyTypAccept` a subject token is held to, are the oauth module's, read through the `oauthTokenSettings` slot alone, never from the configuration ([#728](https://github.com/o3co/auth.provider/issues/728)).
- **Present:** honoured up to `oauth.accessToken.maxExpiresIn` — a larger request is **clamped** to the max, not refused — and always capped at the subject token's remaining lifetime (Security note 16). The response's `expires_in` is the lifetime actually minted; read it rather than assuming the request was granted in full.
- **`maxExpiresIn` unset means the default.** Until the operator raises it (`OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN`), a request can shorten a token but not lengthen it. Security note 19 is what raising it costs.
- **Malformed is refused** with `400 invalid_request` naming `expires_in`: sent more than once, zero, longer than 10 digits, or anything but ASCII decimal digits — no sign, decimal point, exponent or whitespace.
- **Only this grant reads it.** Every other grant ignores the parameter and mints the default.
- **The pair is read when the grant is built** (core's `checkOAuthTokenSettings`). A hand-built `oauthTokenSettings` whose lifetimes break the contract makes `createTokenExchangeGrant` throw a `RangeError` naming the member, rather than answering every exchange with a 500.

## External JWT subject_token

The package ships a built-in validator only for the `access_token` token type (tokens issued by this same auth.provider instance). To accept external JWTs as `subject_token`, implement `ExchangeTokenValidator` yourself and contribute it from a sibling module for `urn:ietf:params:oauth:token-type:jwt`:

```ts
import { createApp, defineModule, jwksModule } from "@o3co/auth-provider-core";
// The validator contract is core's, not this package's.
import type { ExchangeTokenValidator, ValidatedToken } from "@o3co/auth-provider-core";
import { oauthEndpointsModule } from "@o3co/auth-provider-oauth";
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
    oauthEndpointsModule,
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

**`familyId` is how a validator tells the handler about a refresh-token family.** A validator that accepts this provider's own family-bearing tokens — under any token type — must fill `ValidatedToken.familyId` from the token's `family_id`: the handler checks it against this provider's family store, refuses the token when none is wired, and copies it into the issued token so a later family revocation reaches that token too (Security notes 1 and 10). A family left only in `claims` is neither checked nor inherited. A validator of foreign tokens, whose families this provider's store does not hold, leaves `familyId` unset. An empty string counts as unset. A `familyId` or `sid` that is present but not a string is no answer: the token is refused as a failed validation (`invalid_request`, `subject_token validation failed` or `actor_token validation failed`).

**`sid` is how a validator tells the handler about a browser session.** The same contract for the `UserSession` a token was minted under: a validator that accepts this provider's own session-bound tokens fills `ValidatedToken.sid` from the token's `sid`, or from the `liveness_sid` of a token that was itself exchanged (core's `livenessSidOf`), and the handler checks it and carries it as `liveness_sid` (note 21). A session left only in `claims` is neither; a validator of foreign tokens leaves `sid` unset, since another issuer's `sid` names no session this provider's store holds.

**`aud` and `claims.azp` are how a validator tells the handler whom a subject token names.** A validator of subject tokens returns the token's audience as `ValidatedToken.aud` and keeps its `azp` in `claims`, as the token carries them: the handler accepts the token only when the calling client's id is `claims.azp` or is in `aud` (Security note 18). An answer that carries neither, such as `{ sub, claims: {} }`, is refused with `subject_token azp and aud do not name this client`, unless the client's registration sets `allowExchangeOfTokensIssuedToOthers: true`.

## Error responses

`/oauth/token` answers with the handler's `error` and `error_description` ([RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)), held to that section's character set as described at the end of this section:

- **`400 invalid_request` when the request is not valid or the `subject_token` or the `actor_token` is refused.** [RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2) requires this one code both when "the request itself is not valid" and when either token is "invalid for any reason, or [...] unacceptable based on policy". A refused token, whichever check refused it: validation (`subject_token validation failed`, note 20), the DPoP and mTLS binding matrices (`subject_token requires a DPoP proof`, `DPoP proof does not match subject_token binding`, `subject_token has compound cnf binding which is not supported` and their `client certificate` and `actor_token` forms), the family rule (note 1), the session rule (`session_invalid`, note 21), a subject token that does not name the calling client (`subject_token azp and aud do not name this client`, note 18), `may_act` (note 8), the actor-chain bound (note 9) and the subject's expiry (note 16). The request itself: a missing parameter, `actor_token` and `actor_token_type` not sent together, a `client_id` or `client_secret` that is not one string, a body `client_id` that is not the authenticated client (`client_id does not match authenticated client`, note 14), a malformed `expires_in`, and a `subject_token_type` or `actor_token_type` no validator is registered for or a `requested_token_type` other than `access_token` (`… '<type>' is not supported`) — RFC 6749 §5.2's "an unsupported parameter value". `unsupported_token_type` is not used: RFC 7009 registers it for the revocation endpoint, and RFC 8693 defines no token-type error.
- **`400 invalid_target`** for a requested `audience` outside the client's allowlist or outside the subject token's audience (`audience_widening_not_allowed`), both refused before the policy runs (note 3), a `resource` that is not the issued audience (note 6), and an `audience` or `resource` the grant cannot read — one that is neither a string nor an array of strings, which only a JSON body can send (`audience must be a string or an array of strings`, `resource must be a string or an array of strings`). Such a `resource` is one the server "fails to parse", which [RFC 8707 §2](https://datatracker.ietf.org/doc/html/rfc8707#section-2) answers `invalid_target`; an `audience` gets the same answer by symmetry, since one reader reads both. Neither is converted to a string: a nested `[["billing"]]` is refused, not read as `billing`. A wrong-type `scope`, `client_id` or `expires_in` is `invalid_request` instead, because each may be sent once and an array is a repeated parameter (RFC 6749 §3.2), while `resource` and `audience` may be repeated (RFC 8707 §2, RFC 8693 §2.1), so a value that is neither a string nor strings is a target that cannot be read. Both parameters are read by core's `readTargetParameter`, which keeps each value whole (no comma-splitting), drops the empty entries of a repeated parameter, and reads one that names nothing (`resource=`, JSON `null`, `[]`) as omitted.
- **`400 invalid_scope`** for a requested `scope` outside the subject token's or the client's (note 2), and for one that is not RFC 6749 §3.3's space-delimited list of scope-tokens — a tab, a quote — which is read strictly (core's `readSpaceDelimitedParameter`) and refused as `scope is not a space-delimited list of scope-tokens`. A repeated `scope`, or any other value that is not a string, is `invalid_request` rather than read as omitted; a value of spaces alone, or a JSON `null` (RFC 6749 §3.2), is still an omitted scope. The subject token's own `scope` claim is read so it never widens (`readIssuedScope`): split on the space alone, and an entry that is not a scope-token is dropped, so a legacy `read<TAB>write` that named no scope when it was minted cannot supply `write` now.
- **`400 unauthorized_client`** when the client's `allowedGrantTypes` does not name the grant (note 15), and **`401 invalid_client`** for a public client or a failed client authentication (note 14).
- **`503 temporarily_unavailable`** when a store cannot answer — the client repository, a revocation store (notes 1 and 20), the session lifecycle (note 21) — or the policy hook throws (core's `policyUnavailable()`, `policy evaluation unavailable`, as for every grant). The token is not judged. Each is logged once at error level: the client repository as `client_repository_unavailable` (`site: "token_exchange"`, `step` `find` or `authenticate`, the client id sanitised and capped), the policy as `grant_policy_unavailable`, the stores as `token_exchange_validation_unavailable` / `token_exchange_family_store_unavailable` / `token_exchange_session_store_unavailable` — on core's console logger when the composition wires no logger, never silently. The exchange is also `503` when it took longer than the lifetime it would issue (`issued token lifetime elapsed during the exchange`, note 16), logged at warn as `token_exchange_lifetime_elapsed`.

The hook's decision is read by core's `readGrantPolicyDecision`, as on every grant: what it accepts as allow or deny, and how it answers, logs and audits an invalid decision (`500 server_error`, `policy_decision_invalid`), are core's, described under [GrantPolicyHook](../core/README.md#grantpolicyhook-scope--audience--token-exchange-policy).

A `GrantPolicyHook` deny is answered by core's `policyDenied`, as on every grant: `400` with the hook's own `error` when it is a token-endpoint code — one of [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)'s other than `invalid_client` (which §5.2 answers `401` with a challenge), or §2.2.2's `invalid_target` — and `invalid_request` for any other code (`invalid_client`, `access_denied`, an RFC 8628 polling code, another extension code, a malformed one), logged, sanitised and capped, as `grant_policy_refusal_rewritten` (warn) — once per policy, code and answer on the composition's logger, on every denial when there is none and the line goes to core's console logger — and audited as `token.issued.failure` with reason `policy_denied`. Its `errorDescription` is sent repaired to §5.2's characters (printable ASCII without `"` and `\`; any other character becomes `?`) and capped at 200 characters; one that is empty or not a string is not sent. A policy that refuses because of a token — a subject or actor it will not accept — should deny with `invalid_request`: §2.2.2 makes that the code for a token "unacceptable based on policy", and a deny with `invalid_grant` would put this grant back outside it. A decision the policy was not entitled to make is `500 server_error` (note 5): a `grantedScope` past the subject token or the registration (`policy returned scopes exceeding the subject_token scope or client allowedScopes: …`), a `grantedAudience` past the subject token's audience or the registration (`policy returned audiences outside the subject_token audience or client allowedAudiences: …`), or a non-array decision. That is core's `policyOutOfBounds`, the answer every grant gives a policy that exceeds its ceiling — the caller did nothing wrong. The request's own `scope` and `audience` are held to the same ceilings before the policy runs (`invalid_scope`, `invalid_target`), so who asked for more decides the answer.

Because `invalid_request` covers both a malformed request and a refused token, the `error_description` is what tells a client which check refused it. The descriptions quoted in this README are part of the contract. They keep to the characters [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) allows in one — printable ASCII without `"` and `\` — and quote a value the client sent with `'`; `/oauth/token` replaces any other character in the value with `?`. Every `invalid_request` this handler returns of its own goes through one function, `invalidRequest` in [`answers.mts`](./src/answers.mts). `/oauth/token` records a refusal in the `token.issued.failure` audit event with its `error` and, as `details.reason`, its `error_description` capped at 200 characters, so a refused token and a malformed request stay apart in the audit stream too. A grant policy's deny is the exception: core's `policyDenied` answers it, not `invalidRequest`, and it is recorded with `details.reason` `policy_denied` and the policy's own code, sanitised and capped, as `details.policy_error`, beside the answered `error`. The `refresh_token` grant answers the same binding and family rows `invalid_grant`, which is RFC 6749's code for a refresh token.

## Security notes

1. **Wire `refreshTokenFamilyRevocation`, or this provider's family-bearing access tokens cannot be exchanged.** A self-issued access token carrying `family_id` — every token the `authorization_code` and `refresh_token` grants mint — is accepted as `subject_token` or as `actor_token` only when its family's revocation state can be read. The handler owns this check, for both tokens; the built-in validator does not read the slot. The answers (for the `actor_token`, each description is prefixed `actor_token `):

   - **No `refreshTokenFamilyRevocation` in the module graph:** `invalid_request` / `refresh token family revocation not configured (revocation cannot be verified)` (fail-closed). Core's `defaultRefreshTokenFamilyRevocationModule` provides the slot over a refresh-token family store (see [Register the grant](#register-the-grant)).
   - **The family is revoked** (logout, refresh-token replay): `invalid_request` / `family_revoked` (`actor_token family_revoked`) — the description the `refresh_token` grant gives a revoked family on the same endpoint, where its code is `invalid_grant` (see [Error responses](#error-responses)). A client seeing it needs the user to authenticate again; retrying the exchange will not help.
   - **The store cannot answer:** `503 temporarily_unavailable` / `refresh token store unavailable`, logged as `token_exchange_family_store_unavailable` with `store: "refresh_token_family"`, the role and core's [`loggableError`](../core/README.md#logger) projection of the store's error — never the error, which for an ioredis reply carries the command it answered, the family's key included.

   The check keys on the family the validator reports (`ValidatedToken.familyId`), not on the token type: the built-in validator registered under another type, or a validator of your own that reports a family, is held to the same answers, because the issued token inherits the subject's `family_id` whichever validator produced it. A token without a family (a `client_credentials` token, say; an empty `familyId` counts as none) has nothing to check. The answers depend only on the `refreshTokenFamilyRevocation` handed to the handler, so they hold as well for a composition that dispatches `createTokenExchangeGrant` itself.

2. **Scope is bounded by two ceilings, always.** `granted scope ⊆ subject_token.scope ∩ client.allowedScopes` is enforced unconditionally, and a `GrantPolicyHook` cannot bypass either **through the request parameter** (point 5 covers the policy-level override, which is re-checked against both). An explicitly requested scope outside either ceiling is refused with `invalid_scope` naming it; an omitted `scope` inherits the subject token's, clamped to the registration.

   **An absent or empty `allowedScopes` grants no scope at all.** A registration that names no scope may receive none — deny by absence, not a permissive "unrestricted" reading. The exchange still succeeds; the issued token simply carries no `scope` claim. Without this ceiling a client registered for `read` that obtained a subject token carrying `admin` could exchange it and receive `admin`, its own registration bounding nothing.

3. **Audience ceilings — the registration and the subject token.** The `audience` request parameter must be in `client.allowedAudiences ∪ { client.clientId }` — otherwise `400 invalid_target` / `audience '<aud>' is not allowed for this client` — and in the subject token's audience (its `aud`, or the client's own id when it names none) — otherwise `400 invalid_target` / `audience_widening_not_allowed: <audiences>`, the code RFC 8693 §2.2.2 gives a target the server will not issue for. Both are checked before the policy hook runs, so what a policy does afterwards cannot change the answer to the client's own request. Empty `allowedAudiences` means only the client's own `clientId` is a valid exchange audience. A policy's `grantedAudience` is held to the same two ceilings (note 5). The policy is handed the subject token's audience, as this note reads it, as `GrantPolicyRequest.originalAudience`, beside its scope as `originalScope`.

4. **Cross-client audience confusion defense.** When the `audience` request parameter is omitted, the handler inherits `subject_token.aud` only if it is in `client.allowedAudiences ∪ { client.clientId }`. Otherwise it falls back to `clientId`. This prevents a malicious client from exchanging a stolen token outside its intended audience just by omitting the audience parameter.

5. **Policy hook widening is always rejected.** The `GrantPolicyHook.evaluate()` result's `grantedScope` and `grantedAudience` may narrow the request-derived values, never widen them. Each is checked before it replaces the request's value, against the ceilings the request met: `grantedScope` against **both** the subject token's scope and `client.allowedScopes` (note 2), `grantedAudience` against **both** the subject token's audience and `client.allowedAudiences ∪ { client.clientId }` (note 3) — the registration bound core's `boundPolicyAudience` applies for every other grant, plus the subject token's. A decision past either is the deployment's policy exceeding its authority, not the caller's mistake, and is answered as every other grant answers it, with core's `policyOutOfBounds`: `500 server_error` / `policy returned scopes exceeding the subject_token scope or client allowedScopes: <scopes>` or `policy returned audiences outside the subject_token audience or client allowedAudiences: <audiences>`, logged as `token_exchange_policy_scope_refused` / `token_exchange_policy_audience_refused`. An empty `grantedAudience` is no decision, as `boundPolicyAudience` reads it: the request's audience, or the default of note 4, stands. An empty `grantedScope` strips every scope. There is no opt-in to bypass either check.

6. **Resource indicators must equal the issued-token audience.** When the request includes RFC 8707 `resource`, every requested resource must equal `audienceForToken` — the single value that will be minted into the issued token's `aud` claim (typically `grantedAudience[0]`). Multi-resource requests whose resources cannot all be represented in the single-valued `aud` are rejected with `invalid_target` / `requested_resources_not_in_audience`. This avoids issuing a token whose `aud` silently disagrees with the requested resource (RFC 8707 §3). A resource no issued audience could equal — neither the client's own id nor an audience both its registration and the subject token carry (note 3) — is refused before the policy hook runs, so what a policy does with the resource cannot turn the caller's `400` into a `500`, and a policy deny is not reached. That early refusal names every requested resource the audience the request itself asks for would not equal: the same list the check after the policy gives, unless a policy would have replaced the audience — then the later check would have compared against the policy's audience, and the early one compares against the request's. Either refusal is logged once at warn as `token_exchange_resource_not_in_audience`, with `audienceForToken` and `missingResources`, the resources it names: an array, as always, but through core's `auditErrorList` — the first ten, each sanitised and capped at 200 characters — with `missingResourceCount`, how many there were, when it had to cut. They are the caller's own values, and the caller chooses how many it sends.

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

9. **Actor chains are bounded.** `oauth-token-exchange.maxActorChainDepth`, the module's own section, defaults to `3` in the package's [`config/reference.conf`](config/reference.conf), which a composition root layers because the module declares it, and can be overridden with `OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH`. A key unknown to the section refuses boot, and `oauth.tokenExchange`, its old path, refuses boot naming the new one. When an `actor_token` would add to an already-full nested `act` chain, the handler rejects the request with `actor_chain_too_deep`.

10. **Family cascade.** Issued access_tokens inherit the subject's `family_id` claim. Revoking the subject's family (e.g. on logout) automatically invalidates every token exchanged from it. This is the same mechanism auth.provider's introspect and userinfo endpoints use.

    The cascade follows the subject only. Revoking an **actor's** family refuses that actor_token in later exchanges (note 1), but does not reach tokens it already acted on: a delegated token carries the subject's `family_id` alone, and the actor appears only in its `act` claim, whose family nothing checks. When that token is exchanged again, the earlier actor becomes a nested `act`, which RFC 8693 §4.1 makes informational only.

11. **Refresh / ID tokens are never issued.** Per RFC 8693 §4.2.2 the handler only returns an access_token. The response always carries `issued_token_type: "urn:ietf:params:oauth:token-type:access_token"`.

12. **Missing subject claim rejection.** Self-issued access_tokens without a `sub` claim (or with an empty-string `sub`) are rejected with `invalid_request` / `subject_token validation failed` (`actor_token validation failed` for an `actor_token`). This prevents a silently-anonymous token from reaching downstream services.

13. **Validator contributions are immutable after boot.** The boot planner aggregates `tokenExchangeValidators` contributions, freezes the world during activation, and exposes only a read-only resolver to the grant handler. Post-boot mutation cannot replace the built-in validator at runtime.

14. **Confidential clients only.** A public client (`tokenEndpointAuthMethod: "none"`) is refused with `401 invalid_client`. Through `/oauth/token` the client has already been authenticated by the oauth package's client authentication — `client_secret_basic`, `client_secret_post` or `private_key_jwt` — and the handler uses that identity, re-reading the record with `clientRepository.findById()`. A body `client_id` that disagrees with the authenticated client is refused there by client authentication itself (`401 invalid_client`); the handler's own `400 invalid_request` for a mismatch applies only where something other than that middleware supplied `ctx.authenticatedClient`. A composition that dispatches the handler without client-authentication middleware (`ctx.authenticatedClient === null`) must send `client_id` and `client_secret` in the body, which the handler checks with `clientRepository.authenticate()`: a missing secret is `401 invalid_client`, and so is a failed authentication — and so is a `client_id` that cannot name a client (a control character, or past 256 characters; core's `isWellFormedClientId`), refused before the repository is asked. A client-repository failure is `503 temporarily_unavailable` on either path.

15. **The grant denies by absence of `allowedGrantTypes` (#326).** Token exchange mints a fresh credential out of one a client already holds — a standing capability of a registration, not a per-user ceremony — so it is never acquired by omission. The handler declares `requiresExplicitGrantAllowlist`, which `/oauth/token` dispatch enforces before `handle` runs, and repeats the check itself for a composition that dispatches it without client-authentication middleware (`ctx.authenticatedClient === null`), where no dispatch rule runs at all. Both paths refuse with `400 unauthorized_client` / `client is not authorized for grant_type 'urn:ietf:params:oauth:grant-type:token-exchange'`, the words every `/oauth/token` allowlist refusal uses. This does not depend on `oauth.requireGrantTypeAllowlist`, which defaults off; the two compose to the stricter rule.

16. **The issued token never outlives the subject token (RFC 8693 §2.2.1), nor exceeds `oauth.accessToken.maxExpiresIn`.** The issued lifetime, `exp − iat`, is `min(requested expires_in ?? oauth.accessToken.defaultExpiresIn, oauth.accessToken.maxExpiresIn, subject_token exp − now)`, where `now` is the one issuance instant the minted `iat` and `exp` are also measured from — so the cap and the stamp cannot land in different seconds and put `exp` past the subject's. That instant is fixed before the presented tokens are validated, so a subject revocation recorded after the exchange read the watermark also covers the issued token. The answer's `expires_in` is what is left of that lifetime once the token is signed (RFC 6749 §5.1 counts it from the response), so it is shorter than `exp − iat` by the time the exchange took. A lifetime the exchange itself used up — a requested `expires_in` no longer than the exchange took — is not answered already expired: it is `503 temporarily_unavailable` / `issued token lifetime elapsed during the exchange`, logged at warn as `token_exchange_lifetime_elapsed`, and a retry can succeed. A chain of exchanges therefore cannot refresh the clock past the credential it descends from, and a client cannot ask its way past the operator's max (see [Requesting a lifetime](#requesting-a-lifetime-expires_in)). A subject token with no remaining lifetime when the token is minted — already expired, expired while the exchange ran, or expiring within the current second — is refused with `invalid_request` / `subject_token has expired` rather than minting a token with a zero or negative lifetime. A subject token carrying **no `exp` claim at all** leaves `min(requested ?? default, max)` standing: there is no lifetime for the cap to descend from. The built-in validator never produces one (jose rejects an expired token before the handler sees it); a consumer-implemented validator that returns an `exp`-less `ValidatedToken` is asserting an unbounded credential, and should not do so lightly.

17. **A DPoP-bound issued token is advertised as `token_type: "DPoP"` (RFC 9449 §5).** The response envelope names the mechanism the issued `cnf` actually binds, read off the confirmation stamped into the token. mTLS-bound tokens keep `"Bearer"` — RFC 8705 §3 does not redefine the wire-level type. A client must read `token_type`: this provider's own protected-resource middleware refuses a `cnf.jkt` token presented as Bearer (RFC 9449 §7.1).

18. **Token exchange requires the caller to be an audience of the subject token by default.** A `subject_token` is accepted only when it names the calling client: its `azp` is the client's id, or its `aud` — a string or an array — contains it. A resource server exchanging a token it received is named in `aud`; the client the token was issued to is its `azp`. Otherwise the exchange is refused with `400 invalid_request` / `subject_token azp and aud do not name this client`, logged at warn as `token_exchange_subject_not_for_client` with the subject and the client id. The comparison is exact. A `client_id` claim is not read: every token this provider stamps with one carries the same value as `azp`. The check reads the validator's answer — its `aud`, and `azp` from its `claims` — so a token a contributed validator accepts is held to it too. It runs right after the `subject_token` is validated, whether or not an `actor_token` is sent. `may_act` (note 8), the actor chain (note 9) and the DPoP and mTLS matrices apply as before, and the issued token's audience is selected as before (notes 3 and 4): the check decides only whether the subject token is accepted.

    **A client that exchanges tokens issued to others** — a gateway, or an on-behalf-of service handed tokens that name neither it nor its audience — is registered with `allowExchangeOfTokensIssuedToOthers: true` ([Client configuration](#client-configuration)). Only a strict `true` counts, and it is read from the operator's client registration, never from the request. Everything else still holds for such a client: `may_act`, the scope and audience ceilings of its registration (notes 2 and 3), the lifetime cap (note 16) and the grant allowlist (note 15). Set it only for a client trusted to choose whose tokens it exchanges; a `GrantPolicyHook` (`grantPolicy`), which has both identities in hand, can narrow that further.

    The built-in validator does not pin `aud` itself: `ExchangeTokenValidationContext` deliberately carries no client identity, and the central verifier records `jwt_verify_aud_skipped`. The grant, which has authenticated the client, applies the check.

19. **`oauth.accessToken.maxExpiresIn` bounds the offline-revocation window of an exchanged token.** Revoking the subject's family (note 10) stops an exchanged token wherever the family is consulted — introspection, userinfo, a verifier that checks revocation. A resource server that validates the JWT offline, by signature and `exp` alone, cannot observe that and keeps accepting the token until it expires. The longest that can be is the issued lifetime, and the longest a token-exchange request can make the issued lifetime is `maxExpiresIn`. Unset, it equals `defaultExpiresIn`, so the window is the default lifetime. Raise it only as far as you accept an exchanged token outliving its revocation at such a resource server.

20. **A revoked access token cannot be exchanged, and a keystore or revocation store that cannot answer is `503 temporarily_unavailable`, not a verdict on the token.** The built-in validator consults the access-token denylist (by `jti`) and the subject watermark for the `subject_token` and the `actor_token`, as userinfo and introspection do, so revoking an access token also stops it being exchanged: a denylisted or watermarked token is `invalid_request` / `subject_token validation failed` (`actor_token validation failed` for the actor). When either store cannot be read, or the keystore cannot answer the key lookup, the token is still refused, but the answer is `503 temporarily_unavailable` / `subject_token validation store unavailable` (`actor_token …` for the actor), logged as `token_exchange_validation_unavailable` with the role and the error's projection: an outage says nothing about the token, and an answer that judged it would tell the client to discard a credential that may be perfectly good. A kid the keystore does not hold is still `subject_token validation failed`. The validator follows core's `ExchangeTokenValidator` contract — `null` for a token that is not acceptable, a throw for an answer that is not knowable — and tells the two apart with core's `isVerificationUnavailable`, as the `refresh_token` grant does. The family store's answers are note 1's.

21. **A token minted from a browser session ends with that session, exchanged or not — and an exchanged token reaches none of the session's capabilities.** A token this provider minted from a browser session — the `session` grant's, the `authorization_code` grant's — carries the session's `sid`, and a logout ends the `UserSession` it names, after which `/oauth/introspect`, `/oauth/userinfo` and the refresh grant treat the token as inactive. The issued token carries the subject token's session (reported as `ValidatedToken.sid`) **as `liveness_sid`, never as `sid`** (core's `grants/sessionClaims.mts`): introspection and userinfo read it for liveness, so the same logout ends the exchanged token, and nothing a `sid` authorises is reachable with it — `/oauth/userinfo` answers it `{ sub }` alone whatever its scope, and `POST /oauth/federation/:name/logout` and the federation token route refuse it (`missing sid claim`), so a downstream holder can neither read the session's claims, nor disconnect its federation, nor fetch its upstream token. A re-exchanged token's `liveness_sid` is carried on the same way. The actor's session is not carried, as the issued token speaks for the subject. Where a `userSessionStore` is wired, core's session lifecycle (the `sessionLifecycle` slot, filled by `sessionLifecycleModule`) is required beside it, or the grant refuses to build (`contribute-factory-failed` at boot). The handler reads the session behind the `subject_token` and the `actor_token` through the lifecycle's `liveness`: a session closing or closed is not live from the closing commit on, though its `UserSession` is still there.
   - **The session has ended, is closing, or is recorded for another subject** (the session grant's rule): `invalid_request` / `session_invalid` (`actor_token session_invalid`) — the description the `refresh_token` grant gives the same finding.
   - **The lifecycle cannot answer:** `503 temporarily_unavailable` / `session store unavailable` (`actor_token session store unavailable`), logged once at error as `token_exchange_session_store_unavailable` with `store: "session_lifecycle"`, `step: "liveness"`, the role and, for a read that rejects, the error's projection. A `sid` the lifecycle cannot hold names no session: `session_invalid`, never an outage.
   - **No session link, or a sessionless composition (neither the lifecycle nor a store wired):** nothing to check — the rule introspection applies. Without a reader no surface judges one; the issued token still carries it.

   The actor's session is checked only at the exchange: the issued token carries no link to it, so a delegated token outlives the actor's later logout, as it outlives a later revocation of the actor's family (note 10).

   Like note 19's family revocation, this binds only the surfaces that ask: a resource server validating the JWT offline sees no logout, and `maxExpiresIn` is the lever there. `/session/logout` and `/oauth/logout` both close the session through core's session lifecycle, which revokes the session's refresh-token families. A token exchanged from a session-grant token has no family, so what ends it at either logout is the session it carries as `liveness_sid`.

22. **The presented tokens are checked again as the last step before minting.** After the policy and the target checks, the `subject_token` and then the `actor_token` are validated again by the same validator (the denylist and the subject watermark, for the built-in one), and the family rule (note 1) and the session rule (note 21) are applied again to the family and session the first validation reported, which are the ones the issued token carries. A refusal or an outage there is answered and logged exactly as at the first check (notes 1, 20 and 21). Each exchange therefore asks each validator, and reads each store, twice.

23. **The issued token carries the subject's authentication context only when this provider issued the subject token.** When the built-in validator verified the `subject_token` against the issuer the exchange mints for, the issued token carries the subject token's `acr`, `amr` and `auth_time` (RFC 9470 §6.1), each read in core's one shape (`wellFormedAcr`, `wellFormedAmr`, `wellFormedAuthTime`) and omitted when malformed, so a resource server's step-up challenge can be met by an exchanged token as by a refreshed one, and a chain of exchanges carries it on. `auth_time` is copied, never moved later: it is capped at the subject token's own `iat` and at the issuance instant, as the `refresh_token` grant caps it. A `subject_token` another validator answered for — a contributed `tokenExchangeValidators` entry, whatever `iss` its answer names, or one that copies the built-in validator's answer — carries nothing: another issuer's authentication is not this provider's to vouch for, as a federation's upstream `amr` is not unless `trustUpstreamAmr` says so. Nor does a token the built-in validator verified for another issuer, or a request with no issuer to compare against. The `actor_token`'s context is never carried: the issued token speaks for the subject.

## What it does not do

- `saml1` / `saml2` subject token types.
- Token type conversion (access ↔ id, access → refresh): answered `invalid_request` / `requested_token_type '<type>' is not supported`.
- Validate external JWTs out of the box: implement a validator ([above](#external-jwt-subject_token)).

Sender-constrained exchange is supported: the handler enforces the DPoP and mTLS `cnf` matrices on the `subject_token` and the `actor_token`, stamps the proven binding into the issued token, and advertises `token_type: "DPoP"` for a `cnf.jkt` token (Security note 17). [`senderConstraint.test.mts`](./src/__tests__/senderConstraint.test.mts) holds the matrix rows.

## Tests

[`grant.test.mts`](./src/__tests__/grant.test.mts) and [`hardening.test.mts`](./src/__tests__/hardening.test.mts) pin the handler's refusals, [`act.test.mts`](./src/__tests__/act.test.mts) the actor chain and `may_act`, [`callerBinding.test.mts`](./src/__tests__/callerBinding.test.mts) note 18, [`selfIssuedAccessToken.test.mts`](./src/__tests__/selfIssuedAccessToken.test.mts) the built-in validator, and [`grant-integration.test.mts`](./src/__tests__/grant-integration.test.mts) the module's manifest, the family answers of note 1, the store-outage answers of note 20, the code and description of every token refusal in [Error responses](#error-responses), and which answer a scope or audience past the ceilings gets depending on whether the request or the policy asked for it, with `tokenExchangeModule` booted through `createApp`. [`oauth-token-route.test.mts`](./src/__tests__/oauth-token-route.test.mts) makes the exchange over HTTP, through `oauthEndpointsModule`'s `POST /oauth/token` in the composition [Register the grant](#register-the-grant) shows: client authentication, the allowlist answers of note 15, the response the route writes, the §5.2 character set of a description that quotes the request, and how `resource` and `audience` are read from a form or JSON body — a malformed one refused, an empty one omitted. [`published-files.test.mts`](./src/__tests__/published-files.test.mts) holds that every source file the build publishes is reached from the entry point. Note 21's logout case is pinned end to end, through the real session, oauth and token-exchange modules, by the repository's `tools/composition` suite; its answers are in `grant.test.mts`. [`grant.beforeMint.test.mts`](./src/__tests__/grant.beforeMint.test.mts) pins note 22 and the issuance instant of note 16, and [`authenticationContext.test.mts`](./src/__tests__/authenticationContext.test.mts) note 23.

## RFC references

- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — OAuth 2.0 Token Exchange (§2.2.2: `invalid_request`, `invalid_target`)
- [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) — Resource Indicators (`invalid_target`)
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0 core
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) — Token Introspection
