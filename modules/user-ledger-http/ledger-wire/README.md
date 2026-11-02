# ledger-wire

## Responsibilities
- Holds the words of two of the wires the provider speaks with the operator's HTTP ledgers: the user ledger's calls (`users-http`'s) and a witness ledger's (`mfa-witness-http`'s, `passkey-witness-http`'s). The modules that speak it and the fakes that answer it read them here, from one place.

## Not here
- Making the calls, reading an answer into users or factors, logging and outages: the module that speaks each wire.
- Where a deployment's ledger serves each call: its settings' URLs, sent to as given.
- The words of the subject-revocation route and of the signer-keys call: `subject-revocation-http`'s and `signer-keys-http`'s, each in its own module.
- A fake ledger: the verification packages'.

## Offers
- `usersWire`: the password call's body (`verify`, the identifier as `email`), a lookup's (`bySubject`, `byUpstream`), what a `404` and `410` say to mean no such user, for the lookups and the password call (`noUser`), and the password call's refusal (`refused`, `401`; deprecated as no such user: answer `noUser` instead).
- `LedgerUserAnswer`: a user as the ledger answers it, `id` the subject.
- `witnessWire`: each call's body (`read`, `enroll`, `withdraw`, `clear`, a write naming its `deadline`), the answers' schemas (`readAnswer`, `markAnswer` where withdraw is offered, `enrollAnswer`) and a write's answer once done (`written`, `204`).
- `ledgerRoutes`: the route of each call, as a fake ledger and the examples serve it.

## Invariants
- A protocol (G33): types, frozen constants, fixed schemas and the functions that build a body; no I/O, clock, randomness or state.
- A `404` or `410` means no such user only with its `error` word; unsaid, it means nothing.
- A marked answer names a token of one character or more.

## Depends on
- Nothing in the workspace; `zod` (a peer).
