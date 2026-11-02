# intents

Internal module of `federation-grants`: a grant's intent through the browser, as the package owns it.

## Responsibilities
- Offers the browser half each step of an intent as one change of the grant and its steps, or one read of them: the records, sealing, retention, listing and audit stay here.

## Not here
- Sessions, the round trip, the upstream's start and exchange, and whose upstream account a callback reached: the browser half's (`federation-grants-connect`). When an intent is lodged or renewed (`api`).

## Offers
- `intentsWith` (clients, upstreams, the store interfaces, `grant`'s parts, audit, settings, origin, runtime) and `intentsOver` (the build context) → `grantIntents`, the package's contract for the browser half; `browserBase`.

## Invariants
- A link is read, never spent: a login or a step-up comes back to it. A question is spent by a denial, of the intent `asked` read, or by an acceptance once the upstream start is built or refused.
- A trip to raise the session is marked once per requirement and login, and the mark answers true only to the request that wrote it.
- Binding the first session and making its question are two writes: a session that loses the binding is stale, and a failed question leaves the binding for that session to try again.
- The upstream's tokens are judged here, writing nothing; the browser half ends an intent they refuse.
- An activation writes only over its own intent, unended and within its time as read then, never over a revoked grant, and seals the tokens as judged, at the time judged. A race that refuses it ends the intent and is audited.
- Only an intent still the grant's current one, unended and within its time, is read or changed, at the change too; ending one with an error is written past its time as well.

## Depends on
- `clients`, `upstreams` (the delegation), `audit`, `kernel`; `grant`, the package's store interfaces
