# Upgrading: store records name every field (#626)

The records a store, registry or repository hands back now name every field as a **required key** whose value may be `undefined`, instead of an optional field that may be left out. A copy of such a record, built as an object literal of its type, fails to compile when it forgets a field. Before, it dropped that field without an error.

That compile error is the whole guarantee. It does not stop:
- a copy that names a field and writes the wrong value;
- a copy behind a cast, or written in plain JavaScript;
- a write that spreads the old record and forgets to clear a field.

For the ports that ship a conformance suite, the suite checks those cases at runtime. It round-trips whole records, and where a field is cleared it checks that the field reads back as cleared.

This guide is for you if you:
- implement one of these ports yourself;
- call a store directly;
- build these records, test fixtures included;
- compile with `exactOptionalPropertyTypes`;
- rely on whether a key is present on these records.

A deployment that only wires the bundled stores and modules has nothing to change.

## What changed

| Type | Fields that are now required keys (`T \| undefined`) | PR |
|---|---|---|
| `FederationTokens` | `refreshToken`, `idToken`, `tokenType`, `scope`, `grantedScope`. `rawParams` is **removed**. | #651 |
| `AssertionIssuerEntry` (what a registry returns) | `allowedSubjects`, `allowedScopes`, `allowedAudiences`, `allowedClients`, `expiresAt`, `profile`, `clockToleranceSeconds`. What you *write*, `AssertionIssuerEntryInput`, keeps them optional. | #652 |
| `RegisteredRP` | `backchannelLogoutUri`, `backchannelLogoutSessionRequired`, `frontchannelLogoutUri`, `frontchannelLogoutSessionRequired` | #653 |
| `ConsentRecord`, `PendingConsentRecord` | `expiresAt`; `state` | #654 |
| Redis `GrantConsentInput`, `ConsentRecordFields` | `expiry`; `expiresAt` | #654 |
| `CodeData`, `Code` | `code_challenge`, `code_challenge_method`, `nonce`, `sid`, `acr`; `expiresIn`, `grantedScope`, `grantedAudience` | #655 |
| `CreateCodeInput` (new: what `createCode` takes) | every field of `Code` but `code`, all required except `expiresIn` (left out, the repository's default applies) | #655 |
| `CodeData`, `Code`, `CreateCodeInput` (later) | `amr`: what the session vouched for at `/authorize`, which `/token` stamps on the code's tokens. A `CodeRepository` of your own records it and returns it; one that drops it yields tokens without `amr`, and their refresh tokens carry none forward. `createCode` is handed it, `undefined` without a user-session store. | — |
| `DeviceAuthorization`, `CreateDeviceAuthorizationInput` | `requestedScope`, `subject`, `grantedScope`; `requestedScope`. `ApproveDeviceAuthorizationInput.grantedScope` stays optional: leaving it out grants `requestedScope` whole. | #656 |
| `DeviceAuthorization` (later) | `approvedAtMs`: the instant an approval was given, the `nowMs` `approve` was handed; `undefined` before. A `DeviceCodeStore` of your own records it and returns it — the device grant holds it against the subject's sessions boundary at the poll. A record approved before the upgrade (the bundled Redis store's included) reads it as `undefined` — and under `core.deployment.mode = "multi"` so does every approval a replica not yet upgraded writes during the rollout. A poll refuses such an approval only while the subject has a sessions boundary in force; the device is answered `invalid_grant` and simply restarts the flow. Nothing needs migrating. | — |
| `DeviceAuthorization` (later) | `amr`, `authTimeMs`: the approving session's vouched `amr` and when it authenticated (epoch milliseconds), recorded when `approve` is handed them; `undefined` otherwise. `ApproveDeviceAuthorizationInput.amr` and `authTime` stay optional. A `DeviceCodeStore` of your own records what core's `recordableDeviceApproval({ amr, authTime }, nowMs)` answers — never its own input — and returns it. The function refuses with a `RangeError` an `amr` that is not a non-empty list of non-empty strings, and an `authTime` that is not a valid `Date` at or after the epoch or is further ahead of `nowMs` than `DEFAULT_CLOCK_SKEW_MS`; it answers a frozen copy of the `amr` and the instant no later than `nowMs`. A refused approval records nothing; the conformance suite checks all of this. A Redis `DeviceCodeStoreClient` of your own writes both fields in `decide`'s same atomic write as the approval, or every approval reads both as absent. A record approved before the upgrade, or by a replica not yet upgraded, reads both as `undefined`, which reads as "cannot tell" and fails closed downstream. Nothing needs migrating. | — |
| `FederationGrantIntent` | `resource`, `upstreamSubject` | #658 |
| `FederationGrantAuthorization`, `FederationGrantUsage`, `FederationGrantCredentials` | `resource`; `lastUsedAt`, `ineligible`, `refreshFailure`; `accessToken` | #657 |
| `FederationGrantCredentialsInput` (new: what `FederationGrantStore.activate` / `replaceCredentials` take) | the access token's `effectiveExpiresAt`, as a `Date`: when the token ends. What a store answers, `FederationGrantCredentials`, keeps it optional — a record written before the field, or rewritten by an earlier release during a rolling deploy, has none, and ends at `obtainedAt + issuedLifetime`. A store of your own keeps it as given and reads it back absent when it has none, as before. | — |
| `FederationGrantRefreshFailure` (the stored stamp) | `retryAfterSeconds`, `upstreamCode`. It no longer `extends` `FederationGrantRefreshFailureInput`, whose fields stay optional. | #657 |
| Redis `NoteFederationGrantRefreshFailureInput` | `retryAfterSeconds`, `upstreamCode` | #657 |
| `UserSession`, `CreateUserSessionInput` | `amr` | #659 |
| `UserSession`, `CreateUserSessionInput` (later) | `authentication`: how the session was established (the MFA ADR's D9), a `SessionAuthentication` whose four fields are themselves required keys. See [`UserSession.authentication`](#usersessionauthentication). | — |

Some types that the library means these records to flow into now accept an explicit `undefined` (`?: T | undefined`). This only widens them:
- `AssertionIssuerEntryInput` (#652);
- `BroadcastRP`, `FrontchannelRP` (#653);
- `CreateCodeInput.expiresIn` (#655);
- `GenerateIdTokenOptions.amr` / `acr` (#659);
- `FederationGrantRefreshFailureInput.retryAfterSeconds` / `upstreamCode` (#660).

## If you implement a store, registry or repository

Return every field, naming it `undefined` where there is no value:

```ts
// before: a field with no value was left out
return { sid: s.sid, sub: s.sub, /* … */ ...(s.amr ? { amr: [...s.amr] } : {}) };

// now: every field is named
return { sid: s.sid, sub: s.sub, /* … */ amr: s.amr ? [...s.amr] : undefined };
```

Run the port's conformance suite against your adapter. The suites compare whole records with `toStrictEqual`. An unset field must come back *named*, as `undefined`, and the values that are set must round-trip. See "Proving an implementation" in [adapter-surface.md](adapter-surface.md).

`CodeRepository`, `FederationTokenStore` and `AssertionIssuerRegistry` ship no suite yet. For those, check that a record with every optional field unset reads back with each key present.

## If you call a store or build these records

Inputs that were optional are now keys you name:
- `createCode` takes every field but `expiresIn`;
- `UserSessionStore.create` takes `amr` and `authentication`;
- `DeviceCodeStore.create` takes `requestedScope`;
- `ConsentStore.grant` takes `expiresAt` (`undefined` means until revoked);
- `PendingConsentStore.set` takes `state`;
- the Redis consent client's `grant` takes `expiry`;
- the Redis grant client's `noteRefreshFailure` takes `retryAfterSeconds` / `upstreamCode`;
- `FederationGrantStore.activate` / `replaceCredentials` take `authorization.resource` / `credentials.accessToken`;
- and, later, an access token's `effectiveExpiresAt` as a `Date`. Build the token with `federationGrantAccessToken(token, lifetime)` from a lifetime reading, as the bundled writers do.

Write `undefined` where you have nothing. That makes "no expiry", "no state" or "no access token" something the code says, not something it arrives at by leaving a field out. The one exception is an access token's `effectiveExpiresAt` on what you write: it is a `Date`, never `undefined`.

## What is observable at runtime, not only in the types

**JSON is unchanged, except for `rawParams`.** `JSON.stringify` leaves out a key whose value is `undefined`, so the bytes the Redis stores write are what they were. A record written before these changes reads back with the same values, though not always the same keys: the key-presence change below applies to it too. The exception is `FederationTokens.rawParams`, covered below.

**Key presence is not unchanged.** Anything that looks at keys rather than values can see a difference:

- **Records the bundled stores return** now carry the key with `undefined` where they used to leave it out. This applies to these returned types, from the memory store and, where there is one, the Redis store:
  - `AssertionIssuerEntry`;
  - `ConsentRecord` and `PendingConsentRecord`, and the `ConsentRecordFields` the Redis consent client returns;
  - `DeviceAuthorization`;
  - `FederationGrantIntent`;
  - a federation grant's authorization, usage and credentials;
  - `UserSession`.

  `FederationTokens`, `RegisteredRP` and `Code` were already returned with every key named. For them only the types changed, apart from `rawParams`. The input types in the table are not read back; the next item covers them.

  `"k" in record`, `Object.keys` / `Object.entries`, `structuredClone` and `toStrictEqual` see the key. A spread that merges defaults *underneath* a record, `{ ...defaults, ...record }`, now lets an `undefined` override the default. Fill a default with `record.k ?? fallback` instead.
- **Inputs the library hands to ports you implement** now carry these keys, `undefined` included:
  - `ConsentStore.grant` gets `expiresAt` (`POST /oauth/consent`);
  - `PendingConsentStore.set` gets `state` (`/authorize`);
  - `CodeRepository.createCode` gets `acr` (`/authorize`; `nonce` and `sid` were already named), and later `amr`;
  - `DeviceCodeStore.create` gets `requestedScope` (`/device_authorization`);
  - `FederationTokenStore.attach` gets `tokenType` (the federation callback);
  - `FederationGrantIntentStore.putIntent` gets `resource` and `upstreamSubject` (lodging);
  - `FederationGrantStore.activate` gets `authorization.resource` (the grant callback);
  - `FederationGrantStore.replaceCredentials` gets `credentials.accessToken` (a refresh).

  An implementation that fills defaults with `{ expiresAt: policyExpiry, ...record }` now gets `undefined` for `expiresAt`. Use `{ ...record, expiresAt: record.expiresAt ?? policyExpiry }`. Putting the default after the spread instead would override an expiry the record does carry.
- **`FederationTokens.rawParams` is gone.** The library no longer writes it, so an envelope written from tokens that carried it now has different bytes. A Redis envelope that still carries it is read, and the field is ignored. That includes one whose `rawParams` is malformed, which was refused before.
- **The Redis RP registry treats a stored RP record with a wrong-typed logout field as corrupt.** `listRPs` leaves the record out, with a `shape_invalid` warning when a logger is configured, as it already did for a bad `clientId` (#653). The stored record is not deleted.

The behaviour of the library itself is otherwise unchanged. For example, a device authorization created by an untyped caller with a `null`, `""`, `false` or `0` `requestedScope` is still a request with no scope, as before.

## `UserSession.authentication`

Since the MFA ADR's build-order step 5, a session says how it was established: `authentication: { primary, federation, upstreamAmr, mfaAt }` — `"pwd"` or `"fed"`, which federation, what an untrusted upstream IdP asserted (kept for the record, never stamped), and when a second factor was last verified. Its `amr` holds only what this provider vouches for.

- **A login path of your own** passes it. Core composes the pair with `amr` for the two login paths this library has: `...passwordSessionAuthentication()` for a password login, `...federatedSessionAuthentication({ federation, upstreamAmr, trusted })` for a federated one, with `trusted` from `federationTrustsUpstreamAmr(config, name)`. `undefined` writes a session read as one from before the key existed.
- **A store of your own** round-trips all four fields, `mfaAt` as a `Date`, naming each one `undefined` where it has no value, and keeps its own copies of `upstreamAmr` and `mfaAt`. Its `create` records what core's `recordableSessionAuthentication(sid, authentication, now)` answers — never its own input. The function refuses with a `RangeError` what `SessionAuthentication` does not admit and an `mfaAt` that is an Invalid Date, before the epoch, or further ahead of `now` than the clock skew tolerated between hosts (`DEFAULT_CLOCK_SKEW_MS`), and answers a copy, its `mfaAt` no later than `now` — as the bundled stores record it, so a store of yours refuses and records what they do. The conformance suite reads the stored `mfaAt` back, so a store that records its input fails it. A record written before the key existed must read back as `authentication: undefined` — never as some default — because that is how `sessionAuthentication` / `vouchedAmr` know to split it: a pre-upgrade federated session then vouches for `fed` alone.
- **Read a session through `sessionAuthentication` / `vouchedAmr`,** never its own `amr` or `authentication`: the record's `amr` still holds an untrusted IdP's values in a session written before the key.
- **The step-up capability** is optional: `SupportsSecondFactorUpdate.recordSecondFactor(sid, { amr, at })`, detected by `supportsSecondFactorUpdate(store)`. A store that has it writes what core's `sessionAfterSecondFactor(session, event, now)` computes — which checks the event, and splits a pre-upgrade session first — changes nothing else (never the session's lifetime), and is safe against two calls at once. It answers `null`, and writes nothing, for a gone session, and whenever `sessionAfterSecondFactor` answers `null`: the session's primary cannot be told, or the record's `authentication` or `amr` is not in a shape the types admit. It lets the `RangeError` of a bad event through before it reads anything: the caller's fault, not an outage. Where admission itself picks the second-factor authority to step a session up for a request's `acr_values`, it reads the same condition and answers a new login (`reauthenticate`) rather than a step-up that could not be recorded. A store without it keeps working; a step-up asks for a re-authentication instead. Both bundled stores have it, and the Redis one needs a new client method, `UserSessionStoreClient.replaceIfUnchanged` (`makeIoredisClients` provides it).
- **The conformance suites** in `userSessionStore.contract.mts`: `runUserSessionStoreContract`, for every store, now covers `authentication` and what `create` refuses; `runSecondFactorUpdateContract` covers the step-up capability and runs only against a store that claims it. Run the second only if your store implements `recordSecondFactor`.
- **What sessions already minted keeps what it carries.** The split applies to sessions as they are read. An authorization code or refresh token issued before the upgrade — or by a replica on the older release during a rolling one — keeps its `acr` (and a refresh token its `amr`), untrusted upstream values included, until the code is spent or the refresh family ends (`oauth.refreshToken.expiresIn` after the login; no bound under `unknownFamilyPolicy = "accept"`). The [operator runbook](operator-runbook.md#before-you-upgrade) has the remedy — `revokeAllForSubject` for the affected subjects — and what it reaches: not an access token a resource server validates offline, which lives until its `exp`.

## `UserSession.enrollmentFacts`

Since the MFA ADR's build-order step 9, a session also records what its login's `User` said that a first binding is decided on: `enrollmentFacts: { witness, mailAddress }` — the enrollment witness as `readMfaEnrollmentWitness` reads `User.mfaEnrolled` (`"enrolled"`, `"not_enrolled"` or `"malformed"`), and what `User.email` is (`"none"` when it is absent, `null` or empty; `"address"` when the provider reads one address; `"unreadable"` for anything else). Never the address itself.

- **Unlike the keys above, it is optional.** A session written before it, or by a store that drops it, has no such key. It is a session that recorded nothing — never one "not enrolled". A reader decides what that means; the MFA ADR's D12 has the `mfa` requirement send such a session to log in before a first binding, so a store that drops the key fails closed, visibly.
- **A store of your own round-trips it.** Its `create` records what core's `recordableEnrollmentFacts(sid, enrollmentFacts)` answers — `undefined` for none, else a copy of the two fields and nothing else — and refuses anything else with that function's `RangeError`, recording nothing; its `get` answers the two fields back, leaving the key out when none was recorded, and `recordSecondFactor`, where the store has it, keeps them. `readEnrollmentFacts` reads a stored value back. `runUserSessionStoreContract` checks all of it, and `runSecondFactorUpdateContract` that a step-up keeps them.
- **A login path of your own** does not pass it: `establishSession` writes it from the primary core's builders made, which derive it from the `User` and never read one handed in.
- **Sessions that already exist carry none**, and are read as sessions that recorded nothing; a fresh login records them. On Redis, a release before this one reads an envelope that has the key and ignores it.
- **The `User` a repository answers is plain data**: its own enumerable data properties, holding primitives, arrays and plain objects — what JSON parses to, as `HttpUserRepository` answers. A login refuses anything else (a class instance, an accessor, an inherited or non-enumerable field, a `Date`, a `Map`) with a `500`: the facts are derived from a copy, and a copy would drop such a field and read the witness as not enrolled.

## If you compile with `exactOptionalPropertyTypes`

Under that option, `k?: T` refuses an explicit `undefined`. A record from the table above names `k` as `T | undefined`. So assigning, passing or spreading the whole record into a type that declares `k?: T` no longer compiles. Reading a single field is unchanged: `record.k` was already `T | undefined`.

**The flows the library intends still compile.** Each of these has a probe that compiles with the option on:

| Flow | Probe |
|---|---|
| a registry's entry back into `add()` | `packages/core/src/assertions/__tests__/entry-exact-optional.test.mts` |
| a registered RP into the logout helpers | `packages/oauth/src/logout/__tests__/rp-exact-optional.test.mts` |
| a session's `amr`, a code's `acr` into `GenerateIdTokenOptions` | `packages/core/src/grants/__tests__/idtoken-exact-optional.test.mts` |
| a stored `Code` into `createCode` | `packages/core/src/repositories/__tests__/create-code-input-exact-optional.test.mts` |
| a stored refresh-failure stamp where a report is taken | `packages/core/src/federation-grants/__tests__/refresh-failure-exact-optional.test.mts` |

The library's own sources were also compiled with the option on, before and after the series. No whole-object flow of a changed record newly fails.

**Pairs that only share field names were not widened.** For example, a `Code` is no longer assignable to `SessionData`, and a `FederationTokens` is no longer assignable to `DelegatedTokens`. No API passes one to the other. Widening a type has a cost of its own: that type's values stop being assignable to `?: T` types further on.

**What to do in your code:**
- Widen a type of your own that receives one of these records to `k?: T | undefined`.
- If you can't widen the receiving type, build the object without the unset keys. For example, write `...(record.k !== undefined && { k: record.k })` for each such field.

## Checklist

1. Build against the new version. Every compile error on a record or input literal is a field to name. Add `field: undefined` where there is no value.
2. Run the conformance suite for each port you implement.
3. Search your store implementations and their callers for `in` checks, `Object.keys`, and spreads that merge defaults underneath one of these records or inputs.
4. If you stored `rawParams`, stop reading it.
5. If you use `exactOptionalPropertyTypes`, widen your own types that receive these records. Where you pass a whole record to a type that is not yours, build the object instead.
