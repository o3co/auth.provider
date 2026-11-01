# faults

Internal module of `conformance-second-factor`: what the area's fault scenes share in its words, its scene and the store writes a fault is about; the deployment, the waits and the repointing around a fault are `conformance`'s (`fault-scene`).

## Responsibilities
- Gives a password login a second factor holds, on the Redis store, for one user, the ledger revoking subjects where a scene says, and runs a scene on a deployment of its own on that scene unless it names another.
- Binds TOTP for the user at an instance and gives its recovery codes, each to a scene once; holds a login at an instance; moves a browser, its cookies and all, behind another instance; lets a held login in by a recovery code.
- Names, in `test/wire.ts` alone, the write that uses a recovery code up as the relay matches it: the subject's factor list in `mfa-store.factors` with the code's digest last among the recovery codes used; and which commands are store calls.
- There too: any write to a subject's factor list (a factor bound or removed, codes reissued, the fence a revocation moves), a read of a subject's revocation boundary, a session's check, its writes, and the boundaries each puts.

## Offers
- `faultScene`, `on` (`conformance`'s, on `faultScene` unless it names another), `enrolledAt`, `heldAt`, `movedTo`, `usedAt`, `said`, and the types `Codes` and `Browser`.
- From `test/wire.ts`: `useOf`, `isStoreCall`, `factorListWritten`, `boundaryRead`, `boundaryOf`, `boundariesPut` and the deployment's `prefix`.

## Invariants
- The store's own names (spaces, record fields, operations, how a code is kept, the commands it sends) are written in `test/wire.ts` alone, never in a scene's file.
- A code's use puts its digest last among those used, so a match on one code's use never takes a later code's; a rewrite of the list for another reason would match it too, and no scene makes one.
- The scene's login attempts are its own value, not the default, so the logins of one scene stay within one window.

## Depends on
- The package's scene builder and test tools; `conformance-identity`, `conformance-keys` (the user and the keys); `conformance` (the fault scene's deployment, the relay and store-wire)
