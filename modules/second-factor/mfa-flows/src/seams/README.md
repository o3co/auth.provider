# seams

Internal module of `mfa-flows`: the shapes of what the module binding factors gives this package, and takes of it.

## Responsibilities
- Defines the enrollment flow's shape (`enrollmentFlow`'s contribution) and the parts (`flowParts`), and builds the parts from what the package already has.

## Not here
- Declaring the contract and the extension point (the package's contract). Pulling the contracts the parts are built from (`wiring`). What the enrollment flow does (its contributor, `mfa-enrollment`).

## Offers
- `EnrollmentFlow`: the handlers of `POST enrollment` and `POST enrollment/complete`, and the answer to a challenge in an enrollment's transaction.
- `FlowTransactions`: a transaction's lifecycle as the module binding factors uses it (start, next deadline, find, spend, judged, take, `keep`, cleared), and no more.
- `FlowParts`, its own interface, not shaped from this package's internals: `transactions` (`FlowTransactions`), `askedFrom`, the resume of a held login (below), `record` (through the package's declaration of its audit events), `answers` (unknown transaction, login required, unavailable), `requests` (`field`, `proofOf`, `postedTransaction`, `revokedSince`, `managing`), and `lockout` (its name and policy).
- The parts' resume of a held login: `resume`, carrying nothing; `resumeWith`, with what its maker makes once the login opens, marked (`ResumeMade`: an `answer`, which closes the session, or what it `adds`).
- `flowPartsOf` (the transactions, the resume, `audit`'s record, the lockout policy) → the parts.

## Invariants
- The parts are built from nothing that asks for an enrollment flow, so a flow's factory may take them.
- Its types are what the package's contract takes, by type alone.

## Depends on
- `audit`, `http`, `rate-limit` (types); the package's `proof` (the resume), `recording`, `transactions`, routing helpers and section (the lockout's name).
