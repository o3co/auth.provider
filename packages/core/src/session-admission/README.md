# session-admission

Last updated: 2026-09-28

## Responsibility

The one decision that an authenticated browser session — or the primary authentication about to become one — may proceed with an action ([the session-admission ADR](../../docs/adr/2026-09-28-session-admission.md)). Every consumer of a session (`/authorize`, consent, the session-bound grants, the refresh grant, device verification, the federation-grants browser half, the link flow, WebAuthn registration) calls `admitSession` with its own slots and a claim core built; the login route calls `admitPrimary` before anything is written, a requirement's completion route `resumePrimary`, and the federation callback `establishWithoutAsking`. An extension that changes what "logged in" means — MFA first — is a `SessionRequirement` contributed under the `sessionRequirements` kind and reaches every consumer through the synthetic key `sessionRequirementResolver`, never through a consumer's manifest.

It owns the decision and its vocabulary: the claim builders (one reading of each carrier), the actions and their grades, the seven steps and the merge, the requirement contract with its registration copy and resolver, the establishment half (the primary, the continuation, the interruption's validated answer, the `Establishment` capability), the provider's `acr` vocabulary (`acr.mts`), and the contract suite requirements run (`testing/`). It owns no protocol: what a consumer answers for an outcome — a redirect, an RFC 6749 error, a `403` — is the consumer's, and how a requirement decides is the requirement's.

It is a directory of its own so that the consumers cannot disagree on what a live session is, and so that a second extension touches this port's contributors and nothing else.

## Public contract

- `admit.mts`: `admitSession`, `admitPrimary`, `resumePrimary`, `establishWithoutAsking`, `passwordPrimary`, `isEstablishment`, `cookieClaim` / `codeClaim` / `linkClaim` / `tokenClaim`, `ADMISSION_ACTIONS`; for the boot planner and the test resolver alone, `sessionRequirementResolverOver`.
- `requirement.mts`: the types, `checkStepUpPage`, `registeredRequirement`, `checkRegisteredReach`, the hint grammar (`isHintKey`, `isHintToken`), `MFA_REQUIREMENT_NAME`.
- `primary.mts`: `checkPrimaryAuthentication`, `checkPrimaryAdditions`, `checkPrimaryContinuation`.
- `acr.mts`: `readAcrTable`, `selectAcr`, `stepUpReach`, `producibleAmr`, `vouchableAcrTable`, `SECOND_FACTOR_AMR`.
- `testing/`: `resolverForTests` and `sessionRequirementContract`, published on `@o3co/auth-provider-core/testing`.

## Dependencies

- Imports values from `user-sessions/` (the D9 readers and what each login path records), `federation-grants/` (`coveredByRevocationBoundary`, the boundary reading — kept there because moving it here would close a value cycle through `user-sessions/`), `grants/` (the `amr` constants, `composeAmr`), `jwt/` (the revocation skew), `audit/`, `errors/` and `logging/`.
- Imported by `boot/` (the resolver's builder and the registration checks), `mfa/` (the transaction's continuation check), `user-sessions/` (types only) and `modules/manifest/` (types only). Never by a consumer's package directly: they take the barrel.

## Invariants

- A claim, a resolver, a primary and an establishment are branded at the type level and checked at runtime through module-private sets: an object shaped like one, or a copy of one, is refused with a `RangeError` before anything is read — [`__tests__/admit.test.mts`](./__tests__/admit.test.mts), [`__tests__/primary.test.mts`](./__tests__/primary.test.mts).
- Every step fails closed. A store or a requirement that throws is `unavailable`, never a verdict, logged once at error as `session_admission_unavailable` with `store`, `action` (a bundled action's name, else `custom`) and `loggableError`'s projection — never the `sid`. A record without a `sub` or past its `expiresAt` is `not_live`; a claim's subject that is not the record's is `not_live`, logged at warn as `session_admission_subject_mismatch` and audited as `session.admission.subject_mismatch`; the subject-revocation boundary is read against a live record, never for a token carrier — [`__tests__/admit.test.mts`](./__tests__/admit.test.mts).
- A requirement is asked only about a live session, only for `use` and `credential_change`, in registration order, with a view of the record and the D9 reading — for a token carrier, the token's own `amr` — and the first verdict that is not `met` wins; a `step_up` answers the requirement's registered page, or is `unmet` when it registered none; a `remediation` no requirement declared is `credential_change` — [`__tests__/admit.test.mts`](./__tests__/admit.test.mts).
- The merge is the MFA ADR's step-4 table under D2's stated mapping, with no row lost — [`__tests__/admit.merge.test.mts`](./__tests__/admit.merge.test.mts).
- `selectAcr` has one product caller, this directory, over `requirementSession(session)?.amr`; every read of a record's `amr` or `authentication` here is pinned by receiver — [`../__tests__/designVocabulary.drift.test.mts`](../__tests__/designVocabulary.drift.test.mts).
- A registered requirement is a copy: its page, remediations and hint keys are validated and copied once; its `reach` is a getter read live — at request time, and once at the end of boot's stage 4, where a second-factor value under any name but `mfa`, a primary's marker, or a page inconsistent with the reach is refused — [`__tests__/requirement.test.mts`](./__tests__/requirement.test.mts).
- A password login's primary is built by `passwordPrimary` alone and records `pwd`; a completion adds a second-factor value or an `mfaAt` under the name `mfa` alone; a persisted continuation is read back through `checkPrimaryContinuation`; an interruption's answer is held to the closed body and core's hint grammar before the route sees it — [`__tests__/primary.check.test.mts`](./__tests__/primary.check.test.mts), [`__tests__/primary.test.mts`](./__tests__/primary.test.mts).
- The contract suite fails each way a requirement can break the contract — [`__tests__/contract.test.mts`](./__tests__/contract.test.mts).
