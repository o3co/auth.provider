# upstream-handoff

## Responsibilities
- Hands the upstream tokens of a login to the modules that receive them, once its session opens.
- Keeps the tokens of a login a gate holds, sealed, until the gates let it open.

## Not here
- When a login or a link happens, and its checks of the session: the caller's (`federation`).
- What a receiver keeps, and what a receipt means: the receiver's (`upstreams`' receivers).
- How sealing works (`seal`), and how a held login resumes (`login-gates`).

## Offers
- `handoff.of` (IdP, local subject, the upstream's tokens, a lifetime): none where there are no tokens; else the carry and deadline for the caller to hand its gates, and what follows the login's outcome.
- `handoff.opened` (session, carry): the gates' news that a held login opened.
- `handoff.joined` (session, IdP, tokens): a link's tokens, handed at once to the open session it joined, answering what it gave each receiver; `handoff.withdrawn` (session id, IdP, that answer) takes them back.
- `noHandoff`, where no module receives upstream tokens.
- Extension point `handoffSealing`: the seal a held login's tokens are kept under, at most one (two refuse boot where some module receives upstream tokens).
- Composition definition (`./module`): provides `handoff` over the receivers in name order, taking the held login store and the sealing contributed, else `seal`, only where some module receives upstream tokens.
- Store interface for held logins, its needs (survives failover, names from the secret) and contract test (`./testing`).

## Invariants
- Only a login whose upstream gave tokens carries anything; any other keeps nothing.
- Receivers are told in name order. One that throws is logged by name and error kind (`upstream-handoff.receiver_failed`); the others are still told.
- A login that opens at once hands its tokens over at once.
- A held login's tokens are kept for the caller's lifetime, under a carry of 256 random bits, sealed and taken once (the internal module `held`).
- A login a gate refused keeps nothing: it opens no session, now or later.
- The deadline is that lifetime on from the hold, before the kept tokens are gone.
- They go only to a session of the subject that logged in (else `upstream-handoff.held_login_refused`), their lifetime counted from the hand-over.
- A join's receiver that fails undoes those given before it (`withdrawn`, each with its receipt) and is unavailable (`upstream-handoff.link_join_failed`).
- An undo that fails is logged (`upstream-handoff.link_join_undo_failed`), and the rest still go.

## Data
- The held login record: the internal module `held`'s.

## Depends on
- `kernel`, `upstreams` (the receivers, the tokens), `seal` (only with token receivers), `login-gates` (a login's outcome), `session` (the session)

## Vocabulary
- held login: a login a gate held, its tokens sealed until it opens.
- carry: the held login's name, 256 random bits, carried by the gates and read only here.
