# @o3co/auth-provider-test-kit

Last updated: 2026-10-01

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
  [`src/mail/mailSender.contract.mts`](src/mail/mailSender.contract.mts).

**Does not own:** the ports, their types and the reading of the witness
(core); the wire format of the Store's MFA endpoints (core's
[`mfa/storeWire.mts`](../core/src/mfa/storeWire.mts)) and what each answer
means ([`@o3co/auth-provider-foundation`](../foundation/README.md#the-stores-mfa-endpoints));
any adapter, core's in-process ones included (the kit's own tests run
`mfaFactorStoreContract` and `webAuthnCredentialStoreContract` over core's); the doubles a factor's tests use — `createTestMfaFactor`,
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
harness passes the suite without proving both reads.

## The factor store's contract suite

`mfaFactorStoreContract({ build })` holds an `MfaFactorStore` to what "only
zero records open a first binding" relies on. `build` answers a fresh harness
for each case (`MfaFactorStoreHarness`): the store under test, holding
nothing, and `close`, called when the case ends.

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
`(subject, id)` refused and the record kept, and one of ten concurrent
creates let through; subjects kept apart; an update at the current version
replacing `data`, `label` and `lastUsedAt` and nothing else, at version + 1,
and clearing what it says `undefined`; `null` for a version that moved or a
record that is gone, nothing changed; a `RangeError` for an update at
`Number.MAX_SAFE_INTEGER`; one winner among ten concurrent updates at one
version; a successful update reaching no other record — the same id under
another subject, the subject's other factors; removal of one record and of
a subject's records, idempotent and no further; and a removed record taken
again. Every record id is 22
base64url characters, the shape the provider makes and the Store's wire
codec requires. Core's in-process store, the Redis store and foundation's
Store-backed store run it.

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
answering `true`, and at another count answering `false`, the count
unchanged; and a removed credential found no more. Core's in-process store
runs it.

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
`malformed`, never thrown; and a valid proof that completes an enrollment and
verifies the factor it enrolled. A code and an address are looked for in the
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

## The fake Store

`startFakeStore({ users, bearerToken })` starts an in-memory HTTP server on
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
`holdFactor(subject, record)` holds a record as it is, readable or not. What
it received is `requests` (the endpoint, the headers, the body as parsed);
what it holds is `factors(subject)` and `enrolled(subject)`. `close()` stops
it. It keeps every request it records, headers included — the bearer token
too — for as long as it runs: give it test data only.

## Public API

Exported from [`src/index.mts`](src/index.mts):

- `ContractCase`, core's type of a suite's case;
- `mailSenderContract`, with `MailSenderContractInput`, `MAIL_RELAY_REFUSALS`,
  `MailRelayRefusal` and `RelayedMail`;
- `mfaFactorStoreContract`, with `MfaFactorStoreContractInput` and
  `MfaFactorStoreHarness`;
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
| [`factorStore.contract.test.mts`](src/mfa/__tests__/factorStore.contract.test.mts) | the factor store's suite over core's in-process store; each broken store — one that drops an undefined field, rewrites data, overwrites a duplicate, lets every writer win, changes a field an update does not carry, reaches another subject's record, removes every subject's records, writes the same id under another subject or the subject's other factors on a successful update, or answers an update at `Number.MAX_SAFE_INTEGER` with `null` rather than a `RangeError` — refused by the case that names what it breaks; every record id in the provider's shape; a harness built and closed per case |
| [`credentialStore.contract.test.mts`](src/webauthn/__tests__/credentialStore.contract.test.mts) | the WebAuthn credential store's suite over core's in-process store; each broken store — one that lets a registration take a credential id another user holds, overwrites a held credential's record and then throws `duplicate-credential`, refuses a held id with another error, lists a credential under the user it refused, lets a user register a held id again over its record, checks for a held id and inserts in two steps, finds a credential with a sign count of 0, lists every credential whoever's, updates a sign count whatever the count it expects, or leaves a removed credential — refused by the case that names what it breaks; a harness built and closed per case |
| [`factor.contract.test.mts`](src/mfa/__tests__/factor.contract.test.mts) | the factor suite over core's double, with and without a challenge, and mailing its codes, for accounts whose address is padded, internationalised or decomposed; each broken factor — a code in any spelling or escaping in a response, an address in any case, escaping or normalised spelling in what it keeps, in a challenge's answer, or in an enrollment's answer beside a username that is not it, an error quoting the account, the address kept where its keyed digest belongs, a digest of the address the account answered at the start or answers by the completion rather than the one handed, a completion that completes with none handed, a verification that keeps no digest handed under a newer key or keeps the old one, a challenge over an unreadable digest that throws or mails no `null`, a code for another purpose, an expiry already past, one code at two challenges — refused by the case that names what it breaks |
| [`mailSender.contract.test.mts`](src/mail/__tests__/mailSender.contract.test.mts) | the mail sender suite over core's recording sender; each broken sender — an old answer, a lost mail, a mail to another mailbox too, a limit read as an outage, an outage or a transient failure answered, a rejection carrying the mail or the relay's reply in any case or in base64, the mail changed — refused by the case that names what it breaks |
| [`fakeStore.test.mts`](src/mfa/__tests__/fakeStore.test.mts) | each endpoint's answers over real HTTP: every record answered back, the update's compare-and-set and what it writes, `409` / `404`, changes carrying another field refused, the witness mark's `204` / `404` and idempotence, `authenticateByToken` answering the user a token names with the witness as `authenticate` does and `401` otherwise, the credential, what it refuses before it records a request, what it records, and an endpoint answered as told — at once, later, or never |

## See also

- [`@o3co/auth-provider-core`](../core/README.md) — the ports, the witness's
  reader, the MFA endpoints' wire format, and the slot suites on its testing
  entry
- [`@o3co/auth-provider-foundation`](../foundation/README.md) — the Store
  client, the contract of the Store's MFA endpoints, and the Store-backed
  factor store
- [auth.provider](../../README.md) — top-level repository documentation
