# repositories

Last updated: 2026-09-25

## Responsibility

The three data-access ports and their records: `ClientRepository` (`findById`, `authenticate`), `UserRepository` (`authenticate`, `authenticateByToken`, and the optional `linkFederatedIdentity`, `supportsFederatedIdentityLookup`, `findSubjectByFederatedIdentity`), `CodeRepository` (`createCode`, `findByCode`, `consumeByCode`, `removeByCode`); `Client`, `PublicClient`, `User`, `CodeData`, `Code`, `TokenEndpointAuthMethod`. Beside them: the YAML / in-memory adapters with their entry schemas, `createRepositoryFactories`, `loadYamlMap`, and `isGrantTypeAllowed` — the one central grant-type allowlist rule (#268).

The Store — the consumer's user service — is the system of record; this directory reads what it publishes and never writes it (the `User` doc in `types.mts` is the term's definition). The bundled adapters are for development and tests; a deployment brings its own (`packages/foundation` for the HTTP user repository, `packages/redis` for codes). Request-time policy is not decided here: `/authorize` and `/token` in `packages/oauth` consume the ports and apply the field semantics documented on `Client`.

It is separate because the Store's data model is read by `oauth`, `session`, `foundation` and `redis`: the records are where each field's meaning is written down once, and the ports are what a deployment's own adapter implements.

## Public contract

- The ports are [`ClientRepository.mts`](./ClientRepository.mts), [`UserRepository.mts`](./UserRepository.mts) and [`CodeRepository.mts`](./CodeRepository.mts); each declaration-merges its `ComponentMap` slot (`clientRepository`, `userRepository`, `codeRepository`).
- [`types.mts`](./types.mts) — the records. Each field's semantics are documented once, on the field: deny-by-absence for `defaultScopes`, `allowedFederationGrantConnections`, `federationGrantRedirectUris` and `allowedAzpForFederationToken`; strict `=== true` for `firstParty` and `allowPlainPkce`; the `allowedAudiences` fallbacks. `allowedGrantTypes` is the exception and reads the other way: absent admits every grant type, while a list admits exactly the entries it names and nothing else, so an empty one admits none — unless `oauth.requireGrantTypeAllowlist` is on, or the handler declares `requiresExplicitGrantAllowlist` (#326), either of which turns absence into a denial at dispatch. See the invariant below and [`allowedGrantTypes.mts`](./allowedGrantTypes.mts).
- [`clientId.mts`](./clientId.mts) — `isWellFormedClientId` and `MAX_CLIENT_ID_LENGTH` (256): what a `client_id` from a request must look like before a `ClientRepository` is asked for it (no control character, at most 256 characters; core's identifier rule in `../security/identifier.mts`). The oauth routes screen with it, so a client cannot make a repository throw — which they answer as an outage — with a malformed id. `assertRegistrableClientIds` holds registered ids to the same rule: `InMemoryClientRepository` (and so the `yaml` / `static` adapters) refuses at construction an id no request could name, reporting its position rather than the id itself; a custom repository can call it over its own registrations.
- The bundled registration schemas (`ClientEntrySchema`, `UserEntrySchema`) sit beside the in-memory adapters that read them; the factories are [`RepositoryFactory.mts`](./RepositoryFactory.mts).
- Package README: [Repositories](../../README.md#repositories).

## Inputs and outputs

- Ports answer public projections: `PublicClient` omits `clientSecret`; a `User` from the bundled adapter omits `password`. Lookups are fail-soft (`null`); `authenticate` on a public client (`tokenEndpointAuthMethod: "none"`) returns `null` rather than throwing.
- A `ClientRepository` throws only when its store cannot answer: an unknown client and a wrong secret are `null`. Client authentication and `/authorize` in `packages/oauth` answer a throw `503 temporarily_unavailable`, so a repository that throws for a finding turns the client's mistake into an outage. The `clientId` it is handed is the client's input — screened by `isWellFormedClientId` first, but otherwise any character — so an adapter binds it as a parameter and never interpolates it. The contract is written on the port in [`ClientRepository.mts`](./ClientRepository.mts).
- `Client.clientSecret` is optional: required for `client_secret_basic` / `client_secret_post`, forbidden for `none`; `private_key_jwt` takes exactly one of `jwks` / `jwksUri`, public keys only.
- `createCode` requires `client_id` and `redirect_uri` — the code exchange's identity binding — and `consumeByCode` is its single-use authenticity gate. `grantedScope` / `grantedAudience` on the code record are what the token endpoint reads.
- Every field of `Code` is a required key, `undefined` where `/authorize` recorded nothing, and `createCode` takes `CreateCodeInput` — the same keys but `code`, with only `expiresIn` optional (#626). A repository's copy that forgets a field, or an `/authorize` that forgets to pass one, fails to compile.
- The bundled registration path (`ClientEntrySchema`, read by the `yaml` / `static` adapters) holds every registered redirect-URI list to `../net/redirect-uri` at boot. A custom `ClientRepository` bypasses that schema by design; `checkRedirectUri` is exported so it can hold its own registrations to the same rules, and nothing in the port makes it. The federation-grant flow does not rely on either: at request time it checks the redirect URI it was handed against the registration and refuses one that already carries the flow's result parameter (`../federation-grants/lodge.mts`).
- `findSubjectByFederatedIdentity` must change nothing — no login, link or provisioning — and answers `linked` / `unlinked` / `indeterminate`; `linkFederatedIdentity` answers `refused` or `conflict`. Both are the Store's decisions, not core's.
- Record types are readonly; a consumer that wants to mutate copies.

## Dependencies

- Depends on: `adapters/`, `net/` (loopback and the redirect-URI grammar), `grants/` (`SenderConstraint`, type-only) and `federation-grants/` (one value: the reserved-parameter check on a registered federation-grant redirect URI, which loads the lodging module with it — a judgement call recorded in [the directory map](../README.md#where-a-boundary-is-a-judgement-call)); `bcrypt`, `js-yaml`, `zod`, `node:crypto`, `node:fs`.
- Depended on by: `grants/` (type-only) and the root barrel; downstream, `packages/oauth`, `session`, `foundation`, `redis` and `federation-grants`.
- Must never import `boot/`, `middleware/`, `routes/`, `testing/`, or an adapter package. The `grants` edge is type-only in both directions.

## Invariants

- `consumeByCode` returns a record exactly once and refuses an expired code, burning it on the way out; expired codes never presented are swept — [`InMemoryCodeRepository.test.mts`](./__tests__/InMemoryCodeRepository.test.mts). Omitting `client_id` or `redirect_uri` in `createCode` is a compile error (this file is typecheck-included). Every field round-trips with its own value through `createCode`, `findByCode` and `consumeByCode` — the swap the types cannot see, since `nonce`, `sid`, `acr` and the challenge are all strings. Which keys are required is pinned in [`code-fields.types.test.mts`](./__tests__/code-fields.types.test.mts).
- `tokenEndpointAuthMethod` is required and enforced against `clientSecret` at construction; `authenticate` on a public client returns `null` — [`InMemoryClientRepository.test.mts`](./__tests__/InMemoryClientRepository.test.mts).
- `ClientEntrySchema` refuses private or symmetric JWK members, a secret beside `private_key_jwt`, `defaultScopes` outside `allowedScopes` and a `javascript:` redirect URI, and reports every bad entry — [`ClientEntrySchema.test.mts`](./__tests__/ClientEntrySchema.test.mts).
- Every `Client` / `User` field round-trips through its entry schema, and a new optional field fails typecheck until the fixture covers it (#343) — [`entrySchemaConformance.test.mts`](./__tests__/entrySchemaConformance.test.mts) (typecheck-included).
- The federation-grant fields are absent by default, exact-spelled, refused for public clients, and reach both projections — [`federationGrantClientFields.test.mts`](./__tests__/federationGrantClientFields.test.mts).
- `isWellFormedClientId` admits an id at 256 characters and non-ASCII, and refuses one past 256, an empty one, and any C0, DEL or C1 control character — [`clientId.test.mts`](./__tests__/clientId.test.mts). The bundled repository and the yaml adapter refuse to register such an id, naming its position and never echoing a control character — [`registeredClientIds.test.mts`](./__tests__/registeredClientIds.test.mts).
- `isGrantTypeAllowed`: absent → allowed unless `requireAllowlist`; `[]` → denied; exact string match — [`allowedGrantTypes.test.mts`](./__tests__/allowedGrantTypes.test.mts).
- The bundled user adapter runs a bcrypt compare for unknown users and on the plain-text path, never returns `password`, and its identity lookup covers no registration and changes nothing — [`InMemoryUserRepository.test.mts`](./__tests__/InMemoryUserRepository.test.mts).
- Factories: `register` throws on a duplicate type, an unregistered type is `AdapterFactoryError`, the `memory` code builder validates `defaultExpiresIn` — [`createRepositoryFactories.test.mts`](./__tests__/createRepositoryFactories.test.mts); `loadYamlMap` refuses non-mapping YAML and invalid entries — [`loadYamlMap.test.mts`](./__tests__/loadYamlMap.test.mts).
- Records are readonly at compile time — [`../__tests__/repository-types-readonly.test.mts`](../__tests__/repository-types-readonly.test.mts).

## Failure and lifecycle

- Absence is `null`; a malformed registration throws at construction (schema, and the client-id rule), so a bad entry refuses boot rather than a request. A Store that cannot answer `findSubjectByFederatedIdentity`, or whose data names more than one owner, throws: an arbitrary pick is worse than an outage.
- `InMemoryCodeRepository` owns a GC interval; the `memory` builder registers `dispose()` with `BuilderContext.lifecycle` so `AppHandle.dispose()` clears it. `InMemoryUserRepository` links are process-local and lost on restart.
- Nothing here retries, waits or times out.

## Contract tests

[`__tests__/`](./__tests__/) — the files cited above, plus [`nested-migration-error.test.mts`](./__tests__/nested-migration-error.test.mts) (builder-level self-diagnosis for the nested `repositories.*` config shape).
