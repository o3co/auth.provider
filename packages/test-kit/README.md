# @o3co/auth-provider-test-kit

Last updated: 2026-10-03

Contract suites for what code outside `@o3co/auth-provider-core` implements
of auth.provider's ports, and the fakes they run against. Test code imports
it; production code never does.

## Responsibility

**Role.** The executable specification of a port or capability whose
implementations live outside core: a suite that an adapter in this repository
and a deployment's own implementation run alike, and the fakes a suite needs.
It depends on core alone — `@o3co/auth-provider-core`, as a peer — and no
package depends on it at run time: a package's tests list it among their
devDependencies.

**Owns:**

- `mfaFactorStoreContract`, the contract suite of `MfaFactorStore`, where a
  subject's enrolled second factors are kept (the MFA ADR's D7), in
  [`src/mfa/factorStore.contract.mts`](src/mfa/factorStore.contract.mts);
- `mfaFactorStoreConditionalContract`, `MfaFactorStore`'s binding of the
  conditional-write contract: the cases that hold a subject's factor set to
  its store generation, in
  [`src/mfa/factorStoreConditional.contract.mts`](src/mfa/factorStoreConditional.contract.mts);
- `webAuthnCredentialStoreContract`, the contract suite of
  `WebAuthnCredentialStore`, where the passkeys the WebAuthn grant signs in
  with are kept, in
  [`src/webauthn/credentialStore.contract.mts`](src/webauthn/credentialStore.contract.mts);
- `mfaEnrollmentWitnessContract`, the contract suite of the MFA enrollment
  witness — a `UserRepository` that writes it with `markMfaEnrolled` and
  answers it back as `User.mfaEnrolled` on `authenticate` and on
  `authenticateByToken` (the MFA ADR's D12) — in [`src/mfa/enrollmentWitness.contract.mts`](src/mfa/enrollmentWitness.contract.mts);
- `startFakeStore`, a fake Store that answers the Store's MFA endpoints and
  its two login endpoints over HTTP, in [`src/mfa/fakeStore.mts`](src/mfa/fakeStore.mts);
- `mfaFactorContract`, the conformance suite of a second factor — a value of
  core's `mfaFactors` contribution kind — in
  [`src/mfa/factor.contract.mts`](src/mfa/factor.contract.mts);
- `mailSenderContract`, the conformance suite of a mail sender — the value of
  core's `mailSender` slot — in
  [`src/mail/mailSender.contract.mts`](src/mail/mailSender.contract.mts);
- `conditionalRecordContract` and `conditionalSetContract`, the generic suites
  of core's conditional-write convention, which a port's binding runs over its
  conditional members, in
  [`src/conditionalWrite/conditionalWrite.contract.mts`](src/conditionalWrite/conditionalWrite.contract.mts);
- `federationTokenStoreConditionalContract`, `FederationTokenStore`'s binding
  of the record suite, in
  [`src/federationTokens/federationTokenStoreConditional.contract.mts`](src/federationTokens/federationTokenStoreConditional.contract.mts);
- `attemptCounterContract`, the contract suite of `AttemptCounter`, the
  counter behind a verifier's own attempt limits, in
  [`src/attempts/attemptCounter.contract.mts`](src/attempts/attemptCounter.contract.mts).

**Does not own:** the ports, their types and the reading of the witness
(core); the wire format of the Store's MFA endpoints (core's
[`mfa/storeWire.mts`](../core/src/mfa/storeWire.mts)) and what each answer
means ([`@o3co/auth-provider-foundation`](../foundation/README.md#the-stores-mfa-endpoints));
any adapter, core's in-process ones included (the kit's own tests run
`mfaFactorStoreContract`, `mfaFactorStoreConditionalContract`, `federationTokenStoreConditionalContract`, `webAuthnCredentialStoreContract` and `attemptCounterContract` over core's); the doubles a factor's tests use — `createTestMfaFactor`,
`testMfaFactorProofs` and `createTestMfaDigests` — which stay on
`@o3co/auth-provider-core/testing`, since core's own tests use them and core
cannot depend on this package. The other ports' suites are core's, on
`@o3co/auth-provider-core/testing` and in core's own tests.

**Why a separate package.** Core's tests test core. A contract suite is the
specification of a port implemented elsewhere, so it ships where every
implementation — in this repository or in a deployment — can import it while
depending on core alone, rather than copying it.

## Install

```sh
npm install --save-dev @o3co/auth-provider-test-kit @o3co/auth-provider-core
```

Peer dependency: `@o3co/auth-provider-core`. No dependency of its own.

## The enrollment witness's contract suite

A suite is a list of `{ name, run }` cases (core's `ContractCase`, which the
kit re-exports), as the slot suites on `@o3co/auth-provider-core/testing` are,
so any test runner runs it:

```typescript
import { mfaEnrollmentWitnessContract } from "@o3co/auth-provider-test-kit";
import { describe, it } from "vitest";

describe("my repository keeps the MFA enrollment witness", () => {
  for (const contractCase of mfaEnrollmentWitnessContract({ build, withOutage: true })) {
    it(contractCase.name, contractCase.run);
  }
});
```

`build` answers a fresh harness for each case
(`MfaEnrollmentWitnessHarness`): the repository under test; two users the
backend holds, neither marked, each as its subject, username and password,
and `token`, a handle `authenticateByToken` resolves to it (required); a
subject the backend does not hold; `outage`, which makes every later mark
fail, when `withOutage` is `true`; and `close`, called when the case ends.

It holds the repository to: `supportsMfaEnrollmentWitness` answering `true`;
a user nobody marked read as not enrolled, through `authenticate` and through
`authenticateByToken`; a mark resolving to nothing, and the next
`authenticate` answering it, `true` and `false` alike; after each mark,
`authenticateByToken` answering every user's witness as `authenticate` does;
a mark of the value already held succeeding and keeping it; the last of
successive marks holding; a mark reaching its own subject alone; concurrent
marks of one value all succeeding; a mark of either value for a subject the
backend does not hold throwing, with a witness held true and one held false
both left as they were; and, with `withOutage`, a mark during an outage
throwing. The witness is read as the provider reads it, through core's
`readMfaEnrollmentWitness`, so a backend answering anything but a boolean
fails.

**What a Store must do.** Answer `mfaEnrolled` on `authenticateByToken` as
on `authenticate`. A federated login records the witness from the `User`
that `authenticateByToken` answers; a Store that answers it on
`authenticate` alone leaves every federated session reading "not enrolled",
so a lost factor store lets whoever holds the federated identity make a
first binding. The harness's `token` is required for this reason: no
harness passes the suite without proving both reads. Everything a Store
does before `mfa.mode = "required"` is the
[Store implementer checklist](../../docs/upgrading-from-v0.16.0.md#store-implementer-checklist-before-switching-to-required).

## The factor store's contract suite

`mfaFactorStoreContract({ build, supports })` holds an `MfaFactorStore` to
what "only zero records open a first binding" relies on. `build` answers a
fresh harness for each case (`MfaFactorStoreHarness`): `store`, the store
under test, holding nothing; `second`, optional, a second instance on the
same backend — another connection, pool or adapter — which the concurrent
cases split their writers across (absent, `store` again, which proves no
fence across processes); `unreachable`, optional, a store over the same
backend that cannot reach it; `forceExpire`, optional, which
moves the backend's clock past any retention deadline the store set — it
never judges membership or deletes, so that an emptied set's tombstone
expires and a set holding a record does not is the store's own doing (only
the factor set's binding below uses it); and `close`, called when the case ends.
`supports: { unreachable: true, forceExpire: true }` declares the hooks up
front, so the case list is fixed when the suite is built: a declared hook's
cases run, and fail for a harness that lacks it. A hook not declared leaves
its cases out, and one passing case, `not run: …`, names them. One `build`
serves this suite and the factor set's binding below.

```typescript
import { mfaFactorStoreContract } from "@o3co/auth-provider-test-kit";
import { describe, it } from "vitest";

describe("my store keeps the MfaFactorStore contract", () => {
  for (const contractCase of mfaFactorStoreContract({
    build: async () => ({ store: createMyStore(), close: () => cleanUp() }),
  })) {
    it(contractCase.name, contractCase.run);
  }
});
```

It holds the store to: nothing listed for a subject with none; a created
record listed whole, as plain data, its undefined fields named; `data` kept
byte for byte; every binding and any kind round-tripped; a duplicate
`(subject, id)` refused at the current generation and the record kept, and
one of ten concurrent creates at one generation let through; subjects kept
apart; an update at the current version
replacing `data`, `label` and `lastUsedAt` and nothing else, at version + 1,
and clearing what it says `undefined`; `null` for a version that moved or a
record that is gone, nothing changed; a `RangeError` for an update at
`Number.MAX_SAFE_INTEGER`; one winner among ten concurrent updates at one
version; a successful update reaching no other record — the same id under
another subject, the subject's other factors; removal of one record, once,
and of a subject's records, idempotently, and no further; a removed record
taken again; and, with `unreachable`, every member rejecting rather than answering
"no factors", `null` or done. Every record id is 22
base64url characters, the shape the provider makes and the Store's wire
codec requires. Core's in-process store, the Redis store and foundation's
Store-backed store run it. It writes and removes records through the
factor set's `createIf` and `removeIf`, at the generation the set is at.

## The factor set's conditional writes

`mfaFactorStoreConditionalContract({ build, supports })` holds an
`MfaFactorStore`'s set members — `listVersioned`, `createIf` and `removeIf` —
to the factor set's store generation, which is what lets a writer fence its
write against the set it read. It takes the harness the factor store's suite
takes. Give it `second`, a second instance on the same backend, so the
concurrent cases, which split their writers across `store` and `second`,
prove the fence across processes rather than by an in-process lock. A store
with one instance per process, as core's in-process one, gives none, which
proves no fence across processes.

```typescript
import { mfaFactorStoreConditionalContract, mfaFactorStoreContract } from "@o3co/auth-provider-test-kit";
import { describe, it } from "vitest";

const input = {
  build: async () => ({
    store: createMyStore(firstPool),
    second: createMyStore(secondPool),
    unreachable: () => createMyStore(refusedPool),
    forceExpire: (subject) => moveClockPastDeadlines(firstPool, subject),
    close: () => truncate(firstPool),
  }),
  supports: { unreachable: true, forceExpire: true },
};

describe("my store keeps the MfaFactorStore contract", () => {
  for (const contractCase of [
    ...mfaFactorStoreContract(input),
    ...mfaFactorStoreConditionalContract(input),
  ]) {
    it(contractCase.name, contractCase.run);
  }
});
```

It maps the store onto
[`conditionalSetContract`](#the-conditional-write-suites)'s target and runs
that suite, so the factor set is held to every rule of a set the suite
holds: a subject is the scope, a record the item, `removeAllForSubject` the
reset, `update` the member's own update, and `removeAllForSubject` the
unconditional membership write. Every versioned
listing is read with core's `readMfaFactorSet`, so a record that is not a
whole record of its subject, or an id listed twice, fails the case that read
it. The unreachable store is mapped bare: each member is the port's call
alone, so its rejection reaches the outage case unchanged, and an answer it
resolves, whatever it is, fails the case.
`second`, `forceExpire`, `unreachable` and `close` pass through, bound to the
harness, so a hook that uses `this` keeps working, and
`supports` is the suite's; the port has `list`, `update` and its
unconditional reset, so their cases always run. Beside the suite, it holds
the store to the factor set's own: an update keeping the generation, so a
write at it still lands; a tombstone standing — a late first binding and a
late write at a generation read before the reset refused, nothing written;
and, with `forceExpire`, a reset's tombstone expiring across the two
instances — reset through one, of a set written and of one never written,
read as absent through the other, a re-create then repeating neither
tombstone's generation. The generic expiry case runs on one instance; this
one holds an expired tombstone's visibility across instances. A store reached over HTTP runs many requests per race case: give
its cases a longer per-case timeout.

The rules are core's conditional-write convention for a set
([`docs/adapter-surface.md`, "Conditional writes"](../../docs/adapter-surface.md#conditional-writes));
`MfaFactorStore` says what they mean for the factor set. What the generic
suite cannot see, the binding cannot either: a set that exists without a
generation is out of every case's reach, so that only `listVersioned` mints
one is the Store's own tests' to prove. No case can prove the write-lifetime
bound either: the adapter's write lifetime and the MFA package's factor-set
writer, which issues a conditional write only inside its subject lease's
window, keep it.

## The WebAuthn credential store's contract suite

`webAuthnCredentialStoreContract({ build })` holds a `WebAuthnCredentialStore`
to what the WebAuthn grant relies on. The grant's assertion finds a
credential by its id alone and signs in the user its record names, so a
credential id belongs to one user. `build` answers a fresh harness for each
case (`WebAuthnCredentialStoreHarness`): the store under test, holding
nothing, and `close`, called when the case ends.

```typescript
import { webAuthnCredentialStoreContract } from "@o3co/auth-provider-test-kit";
import { describe, it } from "vitest";

describe("my store keeps the WebAuthnCredentialStore contract", () => {
  for (const contractCase of webAuthnCredentialStoreContract({
    build: async () => ({ store: createMyStore(), close: () => cleanUp() }),
  })) {
    it(contractCase.name, contractCase.run);
  }
});
```

It holds the store to: a non-empty `kind`; nothing found for an id it does
not hold; a registered credential found by its id, with the user, public key
and sign count it was registered with; every credential of a user listed,
and no other user's; a credential id held by one user — registering it for
another user, or again for its own, throws core's
`WebAuthnCredentialStorageError` with reason `duplicate-credential` and
changes nothing, the holder's record kept and the other user listing
nothing; one of fifty concurrent registrations of one id let through, the
rest `duplicate-credential`, and the record the one that went through; a
sign count updated by compare-and-set at the expected current count,
answering `true` and writing the `lastUsedAt` it was given, and at another
count answering `false`, the count unchanged; a sign count update of an id
it does not hold answering `false`; a removed credential found no more, and
gone from its user's list while the user's other credentials stay; a
removal of an id it does not hold a no-op; and a credential's `transports`,
`backedUp` and `nickname` kept as registered. Core's in-process store runs
it.

## A second factor's contract suite

`mfaFactorContract(input)` holds a factor, whatever its kind, to what the
MFA coordinator relies on: a kind a hint can carry; `amrValues` it can vouch
for — no primary's marker, no `mfa` — and `amrFor` answering at least one of
them; boolean flags; state and data that survive the JSON round trip sealing
puts them through, and are handed back after it; a code an enrollment or a
challenge asks to be mailed only for the call's purpose —
`email_factor_enrollment` for an enrollment, `login_code` for a challenge —
never empty, with an expiry after the call's time when it gives one, another
code at each challenge, and in no form in the page's response; a login code
with the keyed digest of the account's address, normalised
(`normaliseMailAddress`); the digest a factor records exactly the one it is
handed (`addressDigest`) — of the address its code went to, as the
coordinator kept it at the send — never one of the address the account
answered at the start or answers by the completion, and no completion
without one; a digest a verification is handed under a newer key kept in
its next data and mailed by the next challenge; over data
whose digest is gone or unreadable, a login code still asked for, with a
`null` digest and no throw, so the coordinator refuses the factor; nothing
kept — the pending enrollment's state, the enrolled data and label, a
challenge's state, a verification's next data — and no challenge's answer,
which at a login goes to whoever holds the password, carrying the account's
address, as given or as `normaliseMailAddress` spells it, since the
provider keeps none and the coordinator mails a code to the address on the
user record at the time, only while it matches that digest; an
enrollment's answer, which goes to the account's own browser, naming the
account only by its username, verbatim — the address in it nowhere else; an
error the factor throws, probed over a canary account, quoting neither its
address nor its username; a hint that never shows the account's address; a proof the factor cannot read answered
`malformed`, never thrown; a valid proof that completes an enrollment and
verifies the factor it enrolled; and, for a factor that answers `identity`, a
non-empty string for its enrolled data, the same at each reading, through a
JSON round trip and for a verification's next data, and over data it cannot
read a non-empty string or `undefined`, never one string for two such data
unless it is the enrolled data's own, never a throw. Given
`secondEnrollmentProof` — the proof of possession of an authenticator other
than the one `enrollmentProof` proves — the suite enrolls it through the
same factor beside the first one's record (`factors`), as the coordinator
does, and holds their data to two different identities, neither `undefined`,
each the same however a factor — the one that enrolled it or a fresh one —
reads it, in either order, once both are enrolled: an identity too coarse —
a constant, or one two authenticators share — judges every second enrollment
of the kind a duplicate, and `undefined` is a duplicate of none, never a
distinct authenticator. Without it the suite enrolls one authenticator alone
and cannot tell, so the factor's own tests must show two authenticators
answer two identities. An identity is a duplicate key, not an assurance
signal: two identities do not show two devices, since one authenticator can
hold two credentials.
A code and an address are looked for in the
strings an answer holds as a reader decodes them — object keys, map and set
entries included — in any case, an address with its percent-escapes decoded
too, never in its JSON text, so no escaping hides one. It enrolls at one instant and verifies an hour later,
every call made for the account's `User.id` as its subject; state and data
are held to the rule the coordinator seals them by — JSON values JSON gives
back as they are, in plain or null-prototype objects.

```typescript
import { mfaFactorContract } from "@o3co/auth-provider-test-kit";
import { describe, it } from "vitest";

describe("my factor keeps the MFA factor contract", () => {
  for (const contractCase of mfaFactorContract({
    build: () => createMyFactor(settings),
    user: { id: "u-1", username: "alice", email: "alice@example.com" },
    enrollmentProof: (start, context) => proofOfPossession(start, context.nowMs),
    verificationProof: (enrolled, challenge, context) => proofFor(enrolled, challenge, context.nowMs),
    // Optional, for a factor with `identity`: another authenticator's proof.
    secondEnrollmentProof: (start, context) => otherAuthenticatorProof(start, context.nowMs),
  })) {
    it(contractCase.name, contractCase.run);
  }
});
```

Every call is handed core's test digests for the factor's kind
(`createTestMfaDigests`). The MFA package's TOTP factor runs it.

## A mail sender's contract suite

`mailSenderContract(input)` holds a `MailSender` to what the provider relies
on: a `kind`; a send the relay accepts answered `{ outcome: "delivered" }`,
the relay then holding one mail whose envelope names the recipient alone —
no Bcc — and that carries the code, for every purpose — the relay copied
before the send and compared whole after it, so it then holds that one mail
more and nothing else new; a relay refusing at a limit answered
`{ outcome: "refused_at_limit" }`; each answer read as the provider reads it,
through core's `mailSendOutcome`, so an extra key or an accessor is an
outage and a null-prototype record is an answer; under each other way a
relay refuses (`MAIL_RELAY_REFUSALS`: the recipient, the message, the relay
unreachable, the sender's credentials, a transient failure) a rejection,
never an answer; and the mail left as it was. The suite writes each refusing
relay's reply; every text field of the mail and the reply carry one mark, and
no rejection's `loggableError` projection — its message and its causes' —
carries the mark — in text, or in base64 at any of the three offsets a field
may start at — a field of the mail in base64 or the expiry, searched in
lower case over letters and digits alone.

`build()` answers a sender over a relay that accepts, and `relayed()`, what
that relay holds (`RelayedMail`: the recipients its envelope named, in
order, and the whole message as text); `refusing(refusal, reply)` answers a sender over a
relay that refuses as `refusal` names, answering `reply` as its own text.

What it cannot see, and a sender's own tests must: what the sender logs
itself (a transport's debug transcript, say), an error's properties outside
the projection, and an encoding of the mail other than base64.

## The conditional-write suites

The generic suites of core's conditional-write convention (core's
`adapters/conditionalWrite.mts`; the rules in
[docs/adapter-surface.md](../../docs/adapter-surface.md#conditional-writes)).
A port with conditional members has a binding that maps them onto a target
and runs the suite; the suite reads every answer through core's readers, so
an answer outside its type fails the case.

- `conditionalRecordContract(input)`, for a generation that guards one
  record. The target (`ConditionalRecordTarget`) is `put`, the port's
  create path, `getVersioned`, `replaceIf`, `removeIf`, and its
  unconditional writes of a key by name. Each writes the value it is given, or, named in the input's
  `removals` (a logout-style delete), removes the key. `values()` answers
  two distinct values, equal on every call; `mutate`, when given, changes a
  value in place, each mutable part on its own and leaving a frozen part
  without throwing, to prove the store keeps its own copy.
- `conditionalSetContract(input)`, for a generation that guards a set's
  membership. The target (`ConditionalSetTarget`) is `listVersioned`,
  `createIf`, `removeIf`, `reset`, and, when the port has them, `list`,
  `updateMember` and its unconditional membership writes. `items(scope, n)`
  answers `n` distinct items of a scope, equal on every call; `idOf` and
  `scopeOf` read an item, and every item `items` answers is checked to be of
  the scope asked for. `mutate`, when given, changes an item in place, never
  its id or scope, to prove the store keeps its own copy, as the record
  suite's does.

`build()` answers a fresh harness for each case (`ConditionalRecordHarness`,
`ConditionalSetHarness`):

- `store`;
- `second`, the same backend through a second instance (another connection,
  pool or client). The races and the cross-instance case run across the two;
  absent, `store` is used again, with no cross-process proof;
- `forceExpire`, which **moves the backend's clock past any retention
  deadline the store set; it never judges membership or deletes**. The key
  or scope it is given names what the case expires, for a backend whose clock
  is per key. What then reads as expired is the store's own doing: a record
  past its deadline, an emptied set's tombstone (whether removals or a reset
  emptied it, or a reset of a set never written left it), and never a set
  that holds a member, one revived from its tombstone included. A hook that
  deletes the key, or decides by itself what expires, proves nothing of the
  store;
- `unreachable`, a target over the backend that cannot reach it. It fails
  fast: a closed port or a refused connection, not an address that drops
  packets until a timeout;
- `close`.

`supports` declares, when the suite is built, what every harness and target
has, so the case list is fixed at registration:

| Key | Suite | Declared | Undeclared |
| --- | --- | --- | --- |
| `forceExpire` | both | the expiry cases run | `not run: …` |
| `unreachable` | both | the outage case runs | `not run: …` |
| `unconditional` | both | the unconditional-write case runs, over every write the target's `unconditional` names (an empty map fails it) | `not run: …` |
| `updateMember` | set | the member-update case runs | `not run: …` |
| `list` | set | the plain-listing case runs | `not run: …` |

A key declared and missing from the harness or the target fails its case. A
suite's aliasing case runs only with `mutate`, and says so otherwise. A
binding declares every hook and member its port and backend have.

The races run either operation first, over every delay of up to 8
microtasks and one macrotask, through `store` and `second`: a conditional
write against another, and an unconditional write (an unconditional removal,
say, as a logout makes; a set's reset) against a conditional one. A race's
loser that meets a record already removed may answer `missing` or
`conflict`; there is always exactly one winner, and the state is the
winner's. A set race's winner answers the generation the set is then read
at.

Notes for a binding:

- The record suite's create-over-a-live-record case assumes the target's
  `put` overwrites a live record in place, as a relink does. A port whose
  create refuses a live record maps `put` to its overwriting write.
- A store reached over HTTP runs many requests per race case. Give its cases
  a longer per-case timeout (`it(name, run, timeoutMs)`) rather than fewer
  rounds.

What the suites cannot see, and a store's own tests must:

- the isolation a real engine gives under schedules the races do not force;
- anything a store keeps outside its members (an index, a listing);
- minting a generation into state written without one, and that a
  conditional write against such state answers `conflict` without minting
  (rule 8);
- how a store keeps generations from coming back after a failover or a
  restore (rule 8);
- the retention's length, the write-lifetime bound, and that a set's
  retention starts again at each emptying write (rule 6): each needs a clock
  moved short of a deadline, and `forceExpire` only moves it past every one;
- that the retention is the store's own, never a domain field such as an
  access token's `expiresAt` (rule 3);
- an HTTP adapter's mapping of statuses: a bare `404` or `409`, without its
  body, throws (the status table in "Conditional writes");
- a set's unconditional membership writes other than the reset raced
  against conditional ones (rule 1); the record suite races every
  unconditional write;
- with `forceExpire` undeclared, expiry (rule 3), and with `unreachable`
  undeclared, the outage (rule 4): the suite then names those cases as not
  run.

## The federation token store's conditional writes

`federationTokenStoreConditionalContract({ build, supports })` binds a
`FederationTokenStore` to `conditionalRecordContract`: one
`(sid, federationName)` record, a case's key as its sid, `attach` as the
create path, and `attach`, `delete` and `removeBySid` as the unconditional
writes, the last two removals. `values()` are two complete records, every key
named; `mutate` moves their `Date`s in place.

`build()` answers a fresh `FederationTokenStoreConditionalHarness`: `store`;
`second`, the same backend through another instance, which the races run
across; `forceExpire(sid, federationName)`, which moves the backend's clock
past that record's retention deadline; `unreachable()`, a store over the
backend that cannot reach it; and `close`. `supports` declares `forceExpire`
and `unreachable` as the record suite's does; the unconditional writes are
always run.

Beside the record suite's cases it holds the store to: `get` and
`getVersioned` answering the same record; a replace or a removal of one
record leaving the session's other federations and other sessions' records
at their generations; `removeBySid` ending every federation of the session
and no other session's record; a replace at a generation read before a
`removeBySid` answering `missing` and restoring nothing; and a record with no
`obtainedAt` read back, after `attach` and after `replaceIf`, with the key
named as `undefined`, never left out and never `null`.

## The attempt counter's contract suite

`attemptCounterContract({ build, supports })` holds an `AttemptCounter` to
what a verifier's attempt limit relies on. `build()` answers a fresh
`AttemptCounterHarness`: `counter`; `second`, the same backend through
another instance, which the concurrent case splits its attempts across;
`clock`, optional, the counter's clock as `now()` and `advance(ms)` —
absent, the window cases wait out a one-second window in real time and judge
a window's end within `REAL_CLOCK_TOLERANCE_MS` (one second, so a counter on
the real clock is held to its window's end only that closely); `unreachable()`, a counter
over the backend that cannot reach it, declared with
`supports: { unreachable: true }`; and `close`.

It holds the counter to: a limit allowing exactly that many attempts in a
window, `remaining` counting down to 0 and every answer, refusals included,
naming the same end, `windowSeconds` after the window's first attempt; the
first attempt after that end starting another window; keys counted apart,
however much of one another they share; each key counted against the spec
handed in with its attempt, never one of the counter's own, so a limit
lowered or raised on a live key applies at once, a shortened or lengthened
window keeps a running window's end, and a refused attempt counts nothing; concurrent attempts on one key counted exactly, each allowed one
answered its own `remaining`; a key of up to 512 characters counted, and a
longer key, or any other key or spec it cannot count, rejected, counting
nothing; and,
declared, an outage rejected rather than answered as a count. Every answer
is read through core's `readAttemptCount`, on the counter's clock, as the
attempt guard reads it, so a window's end more than 5 s past, or more than a
day and 5 s ahead (a spec's window is at most a day), is not a count.

## The fake Store

`startFakeStore({ users, bearerToken, now, requestNow })` starts an in-memory HTTP server on
`127.0.0.1`, on a port of its own, answering each endpoint as
[the contract](../foundation/README.md#the-stores-mfa-endpoints) says, with
the bodies of core's `mfa/storeWire.mts`:

- `urls` — each endpoint's URL, named as the configuration names it:
  `listUrl`, `createUrl`, `updateUrl`, `deleteUrl`, `markMfaEnrolledUrl`,
  `authenticateUrl` and `authenticateByTokenUrl`;
- `authenticateUrl` answers `{ email, password }` of a user in `users` with
  its `User` — `id`, `username`, its `claims`, and `mfaEnrolled` once marked —
  a body that is not a JSON object `400`, and anything else `401`;
  `authenticateByTokenUrl` answers `{ token }` of a user whose `tokens` hold
  it with the same `User`, a body that is not a JSON object `400`, and
  anything else `401`;
- every record it holds is answered back as held, one the provider cannot
  read included; an update writes its changes and nothing else at the
  expected version plus one; each request is answered from state it reads
  and writes without yielding, so concurrent updates are a compare-and-set;
- a subject's records are one set at a store generation, as the contract's
  table says: a list answers it with the records, `null` for an absent set;
  every membership write mints a fresh one and an update keeps it; a create
  or a removal of one record is a conditional write, which checks it and
  answers `200`, `404` or `409` with its outcome body, and concurrent ones are
  atomic too, while one without `expectedGeneration` is `400` and writes
  nothing (`null` is a create's "only while the set is absent"), the reset
  alone going without one; an emptied set
  stays as its tombstone until `BUNDLED_STORE_WRITE_LIFETIME_MS` has passed
  since its last membership write on the Store's clock, `now` (default
  `Date.now`); a set held without a generation is given one by its first
  list, a conditional write against it answering `conflict`; and a
  conditional write whose `deadlineMs` is at or before the request clock,
  `requestNow` (default `Date.now`, apart from `now` so moving the
  tombstones' clock makes no write late), is answered `408` and not applied,
  checked in the same step as the write;
- a body the contract does not give an endpoint is `400`, a method but `POST`
  `405`, an unknown path `404`; with `bearerToken`, a request without
  `Authorization: Bearer <token>` is `401` with
  `WWW-Authenticate: Bearer error="invalid_token"`;
- before it records a request, it refuses an absolute or odd request target
  (`400`), a `Host` other than its own `127.0.0.1:<port>` (`421`), a body over
  `FAKE_STORE_MAX_BODY_BYTES` (1 MiB; `413`, the rest read and dropped) and a
  body not declared `application/json` (`415`).

To test how an adapter reads a Store that breaks the contract:
`answer(endpoint, answerer)` answers an endpoint with what `answerer` returns
(`{ status, headers?, body? }`), or by the contract when it returns
`undefined` — at once, or through a promise that settles later or never, for
a slow or hung Store — until released with `answer(endpoint, undefined)`; and
`holdFactor(subject, record)` holds a record as it is, readable or not, and
leaves the set without a generation, as an older writer's rewrite of the
whole set would: its next list mints one, and a conditional write at the one
it had answers `conflict`. What
it received is `requests` (the endpoint, the headers, the body as parsed);
what it holds is `factors(subject)` and `enrolled(subject)`. `close()` stops
it. It keeps every request it records, headers included — the bearer token
too — for as long as it runs: give it test data only.

## Public API

Exported from [`src/index.mts`](src/index.mts):

- `ContractCase`, core's type of a suite's case;
- `attemptCounterContract`, with `AttemptCounterContractInput`,
  `AttemptCounterHarness` and `REAL_CLOCK_TOLERANCE_MS`;
- `conditionalRecordContract`, with `ConditionalRecordContractInput`,
  `ConditionalRecordHarness` and `ConditionalRecordTarget`;
- `conditionalSetContract`, with `ConditionalSetContractInput`,
  `ConditionalSetHarness` and `ConditionalSetTarget`;
- `federationTokenStoreConditionalContract`, with
  `FederationTokenStoreConditionalContractInput` and
  `FederationTokenStoreConditionalHarness`;
- `mailSenderContract`, with `MailSenderContractInput`, `MAIL_RELAY_REFUSALS`,
  `MailRelayRefusal` and `RelayedMail`;
- `mfaFactorStoreContract`, with `MfaFactorStoreContractInput` (`build` and
  `supports`) and `MfaFactorStoreHarness`;
- `mfaFactorStoreConditionalContract`, over the same input;
- `mfaEnrollmentWitnessContract`, with `MfaEnrollmentWitnessContractInput`,
  `MfaEnrollmentWitnessHarness` and `MfaEnrollmentWitnessUser`;
- `mfaFactorContract`, with `MfaFactorContractInput`,
  `MfaFactorEnrollmentStart` and `MfaFactorChallenge`;
- `webAuthnCredentialStoreContract`, with
  `WebAuthnCredentialStoreContractInput` and `WebAuthnCredentialStoreHarness`;
- `startFakeStore`, with `FAKE_STORE_MAX_BODY_BYTES`, `FakeStore`,
  `FakeStoreOptions`, `FakeStoreUser`, `FakeStoreUrls`, `FakeStoreEndpoint`,
  `FakeStoreRequest`, `FakeStoreAnswer` and `FakeStoreAnswerer`.

## Tests

| Test file | Pins |
| --- | --- |
| [`enrollmentWitness.contract.test.mts`](src/mfa/__tests__/enrollmentWitness.contract.test.mts) | the witness's suite over an in-process repository and over the fake Store; each broken repository — one that erases or sets every witness when it refuses a subject, or whose `authenticateByToken` answers no witness, answers it as text, resolves no token or answers another user, among them — refused by the case that names what it breaks; the outage case present only with `withOutage`; the kit's `ContractCase` core's |
| [`factorStore.contract.test.mts`](src/mfa/__tests__/factorStore.contract.test.mts) | the factor store's suite over core's in-process store; each broken store — one that drops an undefined field, rewrites data, overwrites a duplicate, lets every writer win, changes a field an update does not carry, reaches another subject's record, removes every subject's records, writes the same id under another subject or the subject's other factors on a successful update, or answers an update at `Number.MAX_SAFE_INTEGER` with `null` rather than a `RangeError` — refused by the case that names what it breaks; an unreachable store that answers as if empty refused by the outage case, which runs only when declared and is otherwise named as not run; the concurrent creates split across the store and the second; every record id in the provider's shape; a harness built and closed per case |
| [`factorStoreConditional.contract.test.mts`](src/mfa/__tests__/factorStoreConditional.contract.test.mts) | the factor set's binding over core's in-process store, run on its own clock with `forceExpire`; the binding is the generic set suite with every case run, then the factor set's own; a model store with no fault passed, and a store without the set's members refused by every case; the model store, which keeps an emptied set's deadline on a clock `forceExpire` moves, with one fault each — checking then writing after an await, a generation that is a digest of the set, a reset that deletes the set, an update that moves the generation, a snapshot torn records first or generation first, a removal of a record not there that moves the generation, a create that overwrites a held id at the current generation, a counter generation, which repeats once its tombstone expires, a reset of an emptied set that keeps its generation, a removal that answers another generation than it wrote, a re-create after expiry that answers another generation than it wrote, a tombstone that never expires, a reset's tombstone that never expires, a deadline kept on a set written to after it, a race winner that answers a stale generation under contention — refused by the case that names what it breaks, the concurrent ones forced by explicit barriers; an unreachable store that answers as if empty, lists a versioned `undefined`, or resolves an update, refused by the outage case; a harness whose hooks use `this`, run through both MFA suites and closed each time; the outage and expiry cases run only when their hook is declared, fail when it is declared and not given, and are otherwise named in passing cases; a race split across the store and the second; every record id in the provider's shape; a harness built and closed per case |
| [`credentialStore.contract.test.mts`](src/webauthn/__tests__/credentialStore.contract.test.mts) | the WebAuthn credential store's suite over core's in-process store; each broken store — one that lets a registration take a credential id another user holds, overwrites a held credential's record and then throws `duplicate-credential`, refuses a held id with another error, lists a credential under the user it refused, lets a user register a held id again over its record, checks for a held id and inserts in two steps, finds a credential with a sign count of 0, lists every credential whoever's, updates a sign count whatever the count it expects, leaves a removed credential, keeps the `lastUsedAt` it held, answers `true` to a sign count update of an id it does not hold, throws on or empties itself at a removal of an id it does not hold, keeps a removed credential in its user's list, removes every credential of the user, or drops a credential's transports, backup state or nickname — refused by the case that names what it breaks; a store that answers transports in another order accepted; a harness built and closed per case |
| [`factor.contract.test.mts`](src/mfa/__tests__/factor.contract.test.mts) | the factor suite over core's double, with and without a challenge, and mailing its codes, for accounts whose address is padded, internationalised or decomposed; each broken factor — a code in any spelling or escaping in a response, an address in any case, escaping or normalised spelling in what it keeps, in a challenge's answer, or in an enrollment's answer beside a username that is not it, an error quoting the account, the address kept where its keyed digest belongs, a digest of the address the account answered at the start or answers by the completion rather than the one handed, a completion that completes with none handed, a verification that keeps no digest handed under a newer key or keeps the old one, a challenge over an unreadable digest that throws or mails no `null`, a code for another purpose, an expiry already past, one code at two challenges, an identity two authenticators share — read from the record already held, or the latest enrollment's answered for every record — one keyed per factor instance, or one that answers none for the second — refused by the case that names what it breaks |
| [`mailSender.contract.test.mts`](src/mail/__tests__/mailSender.contract.test.mts) | the mail sender suite over core's recording sender; each broken sender — an old answer, a lost mail, a mail to another mailbox too, a limit read as an outage, an outage or a transient failure answered, a rejection carrying the mail or the relay's reply in any case or in base64, the mail changed — refused by the case that names what it breaks |
| [`conditionalWrite.contract.test.mts`](src/conditionalWrite/__tests__/conditionalWrite.contract.test.mts) | both suites over a reference record store, whose writes take a lock per key, and a reference set store, each serving two instances over one backend and keeping retention deadlines on a clock of its own, which `forceExpire` moves; every case refuses a store broken one way (a write that skips the lock, an unconditional delete among them, a counter or a digest as the generation, a torn versioned read, a write on `conflict`, a create that upserts a held id, a reset or a last removal that leaves no tombstone, a reset in two steps, a store that ignores its own deadline, a set revived from its tombstone that keeps the tombstone's deadline, a re-create after expiry at a generation seen before, a reset's tombstone that never expires, of a set written or never written, a re-create after it answering the tombstone's generation, a race winner answering a stale generation under contention, an outage answered as absent, writes that skip the expiry check, a second instance reading from a cache, a member update that changes nothing, a value or a member shared with the caller, or only a member after the first, among them); stores answering frozen values, listing members in another order, or labelling a losing write from a read taken before their lock pass; an undeclared hook's or member's cases left out and named; a declared one missing fails its case; items of another scope fail the case |
| [`federationTokenStoreConditional.contract.test.mts`](src/federationTokens/__tests__/federationTokenStoreConditional.contract.test.mts) | the federation token store's binding over core's in-process store; a store without the conditional members refused by every case; a `get` that answers another record than `getVersioned`, a replace that moves a sibling federation's generation, a `removeBySid` that leaves a federation of the session or reaches another session's, a replace that restores a record a logout removed, and a store that drops `obtainedAt`, leaves an unset one out or answers it as `null`, each refused by the case that names it; the outage and expiry cases named as not run when undeclared |
| [`attemptCounter.contract.test.mts`](src/attempts/__tests__/attemptCounter.contract.test.mts) | the attempt counter's suite over core's in-process counter, on a fake clock and on the real one; each broken counter — one that applies a limit of its own, counts every key as one or only a key's first segment, never ends a window or ends it late or far late, is not atomic, keeps the limit a key's window started with, starts a new window when a spec changes the window, or only when it lengthens it, counts refused attempts, answers `remaining` one off, a refusal with attempts remaining or `resetAt` as a number, counts a key or spec it should reject or a key past 512 characters, or answers an outage as an allowed attempt — refused by the case that names it; the outage case run only when declared, failing when declared and not given, and otherwise named as not run |
| [`fakeStore.test.mts`](src/mfa/__tests__/fakeStore.test.mts) | each endpoint's answers over real HTTP: every record answered back, the update's compare-and-set and what it writes, `409` / `404`, changes carrying another field refused, the witness mark's `204` / `404` and idempotence, `authenticateByToken` answering the user a token names with the witness as `authenticate` does and `401` otherwise, the credential, what it refuses before it records a request, what it records, and an endpoint answered as told — at once, later, or never; a create or a removal of one record without `expectedGeneration` refused `400` and writing nothing, the reset still applied; the factor set's generation: a list's, a conditional create's and a conditional removal's answers, an update keeping it and every membership write moving it, the tombstone a last removal or a reset leaves and its expiry on the Store's clock, a set held without a generation, a record held into a set dropping its generation, `400` for an expected generation or a `deadlineMs` that is none, a late conditional write answered `408` and not applied while one before its deadline is, a deadline checked on the request clock and never the tombstones', and one winner among concurrent conditional writes |

## See also

- [`@o3co/auth-provider-core`](../core/README.md) — the ports, the witness's
  reader, the MFA endpoints' wire format, and the slot suites on its testing
  entry
- [`@o3co/auth-provider-foundation`](../foundation/README.md) — the Store
  client, the contract of the Store's MFA endpoints, and the Store-backed
  factor store
- [auth.provider](../../README.md) — top-level repository documentation
