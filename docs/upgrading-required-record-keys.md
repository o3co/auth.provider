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
| `DeviceAuthorization`, `CreateDeviceAuthorizationInput` | `requestedScope`, `subject`, `grantedScope`; `requestedScope`. `ApproveDeviceAuthorizationInput.grantedScope` stays optional: leaving it out grants `requestedScope` whole. | #656 |
| `FederationGrantIntent` | `resource`, `upstreamSubject` | #658 |
| `FederationGrantAuthorization`, `FederationGrantUsage`, `FederationGrantCredentials` | `resource`; `lastUsedAt`, `ineligible`, `refreshFailure`; `accessToken` | #657 |
| `FederationGrantRefreshFailure` (the stored stamp) | `retryAfterSeconds`, `upstreamCode`. It no longer `extends` `FederationGrantRefreshFailureInput`, whose fields stay optional. | #657 |
| Redis `NoteFederationGrantRefreshFailureInput` | `retryAfterSeconds`, `upstreamCode` | #657 |
| `UserSession`, `CreateUserSessionInput` | `amr` | #659 |

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
- `UserSessionStore.create` takes `amr`;
- `DeviceCodeStore.create` takes `requestedScope`;
- `ConsentStore.grant` takes `expiresAt` (`undefined` means until revoked);
- `PendingConsentStore.set` takes `state`;
- the Redis consent client's `grant` takes `expiry`;
- the Redis grant client's `noteRefreshFailure` takes `retryAfterSeconds` / `upstreamCode`;
- `FederationGrantStore.activate` / `replaceCredentials` take `authorization.resource` / `credentials.accessToken`.

Write `undefined` where you have nothing. That makes "no expiry", "no state" or "no access token" something the code says, not something it arrives at by leaving a field out.

## What is observable at runtime, not only in the types

**JSON is unchanged.** `JSON.stringify` leaves out a key whose value is `undefined`. The bytes the Redis stores write are what they were, and records written before these changes read back as they did.

**Key presence is not unchanged.** Anything that looks at keys rather than values can see a difference:

- **Records the bundled stores return** now carry the key with `undefined` where they used to leave it out. This applies to the memory and Redis stores for every type above. `"k" in record`, `Object.keys` / `Object.entries`, `structuredClone` and `toStrictEqual` see the key. A spread that merges defaults *underneath* a record, `{ ...defaults, ...record }`, now lets an `undefined` override the default.
- **Inputs the library hands to ports you implement** now carry these keys, `undefined` included:
  - `ConsentStore.grant` gets `expiresAt` (`POST /oauth/consent`);
  - `PendingConsentStore.set` gets `state` (`/authorize`);
  - `CodeRepository.createCode` gets `acr` (`/authorize`; `nonce` and `sid` were already named);
  - `DeviceCodeStore.create` gets `requestedScope` (`/device_authorization`);
  - `FederationTokenStore.attach` gets `tokenType` (the federation callback);
  - `FederationGrantIntentStore.putIntent` gets `resource` and `upstreamSubject` (lodging);
  - `FederationGrantStore.activate` gets `authorization.resource` (the grant callback);
  - `FederationGrantStore.replaceCredentials` gets `credentials.accessToken` (a refresh).

  An implementation that fills defaults with `{ expiresAt: policyExpiry, ...record }` now gets `undefined` for `expiresAt`. Put the defaults last, or use `record.expiresAt ?? policyExpiry`.
- **`FederationTokens.rawParams` is gone.** The library no longer writes it. A Redis envelope that still carries it is read, and the field ignored.
- **The Redis RP registry treats a stored RP record with a wrong-typed logout field as corrupt.** It drops the record with a `shape_invalid` warning, as it already did for a bad `clientId` (#653).

The behaviour of the library itself is otherwise unchanged. For example, a device authorization created by an untyped caller with a `null`, `""`, `false` or `0` `requestedScope` is still a request with no scope, as before.

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
