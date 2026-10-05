# ADR 2026-10-05 — Session lifecycle: one record per session, active → closing → closed

## Status

Accepted (2026-10-05). The port, its readers, the in-process store and the
contract suite land first; nothing reads the slot yet. The service, the Redis
store and the callers' switch follow in the order below
([#1030](https://github.com/o3co/auth.provider/issues/1030)).

- Written against: `develop` at `72ba648aa`.
- Amended 2026-10-05: the service, its answers, the close work, resumption,
  the cause policy, the relying-party notifier and the bridge (D8–D14).
  Written against `develop` at `5871ff698`.

## Context

Joining a session and closing it are spread across four sid-keyed stores —
`UserSessionStore`, `SessionRPRegistry`, `SessionFamilyIndex` (with the
`SupportsSessionEnd` mark) and `SessionFederationIndex` — and the order
between a join and a close is kept by callers in `packages/oauth`. Each store
writes on its own, so:

- a close can write its mark and fail before it lists what to end, leaving the
  session half-ended with nothing to resume it;
- a join and a close on Redis are separate commands on different slots, so a
  join can land after the close listed;
- some paths join or close outside that fence (`/session/logout`, subject
  revocation, the federation link callback);
- liveness reads see the `UserSession` alone, never a close in progress;
- the end mark lapses at `expiresAt + skew`, the RP hash and the family set at
  `expiresAt`, so one session's parts lapse apart.

Only a write the store owns can fence another write to it; an ordering across
stores cannot.

## Decision

**D1. One owner, its own slot.** The lifecycle is core's, in
`src/user-sessions/lifecycle/`, behind a port of its own,
`SessionLifecycleStore`, in the `sessionLifecycleStore` slot — not a member of
`UserSessionStore`, whose `recordSecondFactor` is MFA's write path, so a
lifecycle change and a step-up change stay apart.

**D2. One record per sid.** It holds the subject, the state, the session's
`expiresAt`, the participants (`rp`, `family`, `federation`, each unique by
kind and id, with an opaque `data` the store keeps byte for byte) and, from
the close on, the close: its cause, the time of the closing commit and the
work items still pending.

**D3. States only move forward:** `active → closing → closed`.
- `open` writes the record `active`; it never writes over another record, and
  refuses an `expiresAt` already past on the store's clock.
- `join` adds a participant only while the record is `active` and the
  session's `expiresAt` is after the store's clock, else `closed`.
- `beginClose` moves `active → closing` in one commit: it keeps the
  participants as the snapshot and saves the close work — one item per step
  the caller names, and one per participant of the kinds it names. A record
  already closing or closed is answered as it is, so the call is idempotent
  and resumable: a repeat answers the saved work at the current generation. A
  close that makes no item is `closed` at once.
- `completeIf` marks one item done at the generation the caller read; the
  record is `closed` in the step that completes the last one. A failed item
  never moves the state back.

**D4. The conditional-write convention, reused.** Every write issues a fresh
random `StoreGeneration`; `read` answers `Versioned<SessionLifecycleRecord>`;
`completeIf` is a record-scoped replace answering `ConditionalReplaceAnswer`
(`updated`, `missing`, `conflict`), the generation checked before the item.
Every answer is read through core's readers, so a malformed one is a
`TypeError` the caller treats as an outage. An outage rejects; it never
answers `missing`, `null`, `closed` or `refused`. `join` and `beginClose`
need no generation: the state check is inside their atomic step and both are
idempotent, so a late or resent copy that lands after a close answers
`closed`. Only core's service holds a generation.

**D5. One retention for the whole record**, on the store's clock: `expiresAt +
DEFAULT_CLOCK_SKEW_MS` while active, and from the closing commit the later of
that and the commit plus the `retainMs` the caller hands in — the longest
refresh-token lifetime, since token lifetimes are not clamped to the session —
kept through `closed`. Past it, every part of the record is gone at once.

**D6. A listing of closing records,** `listClosing(limit, after)`, for
whatever resumes pending work: closing sids in ascending order of their UTF-8
bytes, after the cursor. Paging with the last sid answered reaches every
record that stays closing, however many records whose work keeps failing
stay ahead of it; an order by closing time would let a thousand stuck
records hide every later one. A sid is well-formed text, no lone surrogate,
so its UTF-8 bytes name it alone and the order is strict; a Redis adapter
keeps the same order with `ZRANGEBYLEX`. It never names a record that left `closing`
before the call began.

**D7. The service is the port's only caller** (the next steps). It decides
the close causes' policy (which causes notify the relying parties; `expiry`
does not), answers a logout whose close work is still pending, resumes
pending work, and decides whether the session grant joins. The port only has
to make those possible: a cause per close, steps and per-participant work the
caller names, and `listClosing`. Two constraints carry to it: `join` replaces
a participant's `data`, so a late copy of an older join can put older data
back while the record is active — the service keeps in `data` only what a
participant's identity fixes; and `completeIf` fences the bookkeeping, not
the work, so every work item is safe to run more than once.

## Consequences

- The memory store (`createInMemorySessionLifecycleStore`) runs each member as
  one synchronous step, holds at most `maxEntries` records and
  `maxParticipants` per record, and when full refuses rather than evicts: an
  evicted record would let a closed session be joined again.
- `sessionLifecycleStoreContract` in `@o3co/auth-provider-test-kit` holds a
  store to the rules a suite can observe; a Redis store runs it on two
  connections.
- Until the service lands, nothing reads the slot and no behaviour changes.

## Order of the remaining steps

Add: the Redis store (one slot per sid, one script per member, one shared
expiry), the service (close runner, cause policy, the RP-notification
contract, resumption), its Redis wiring, and oauth's notifier. Switch: the
callers, one module at a time. Remove: the old fence and stores, once old
nodes are gone and the longest session lifetime has passed.

## Amendment 2026-10-05 — the service

**D8. The service and its answers.** `SessionLifecycle`
(`src/user-sessions/lifecycle/service.mts`) fills the `sessionLifecycle`
slot through `sessionLifecycleModule`, which nothing installs until the
callers switch. `join(sid, { rp?, familyId?, federation? })` answers
`joined`, `refused` or `unavailable`; on `refused` the service revokes the
family and deletes that federation's tokens it was handed, and the caller
hands out nothing. `close(sid, cause)` answers `done`, `pending` or
`unavailable`, with the snapshot's relying parties and federations.
`liveness(sid)` answers `live` with the user session, or `not_live`, or
`unavailable`. `resumePending()` runs the close work of every closing
record. A participant's `data` is `""`: its kind and id are all it holds
(D7).

**D9. A close whose commit landed answers `pending`, never `unavailable`.**
From the closing commit on, liveness answers `not_live` and nothing joins,
so a close with work still outstanding has ended the session; it answers
`pending`, distinct from `done`. `unavailable` means the commit did not land,
or whether it did could not be read. How a route answers `pending` (the
logout's 200 and a `logout.close_pending` audit event) is decided when that
route switches.

**D10. The close work.** One item per family (`revokeFamily`), then
`remove_federation_tokens` (`federationTokenStore.removeBySid`),
`remove_subject_session` (`subjectSessionIndex.removeSid`, where a subject
index is wired), one item per relying party (`SessionCloseNotifier`),
`remove_session_indexes` (the per-session stores of D14), and
`delete_user_session` last, run only once every other item is recorded.
Each item that ran is recorded with `completeIf` at the generation read; a
conflict re-reads the record and goes on with what is still pending, so two
closes of one session and the sweep may overlap. A failed item stays
pending and the record stays `closing`.

**D11. Resumption.** A later close of the same sid resumes the saved work,
whatever its cause (the first cause is kept). A sweep owned by core,
`resumePending`, pages `listClosing` by its `after` cursor every
`core.sessionLifecycle.sweepIntervalSeconds` — whole seconds, read through
`configuredNumber`, refused at boot naming the key otherwise — one sweep at a
time, stopped on dispose. Unwritten, there is no sweep: a deployment without
relying parties leaves it so.

**D12. The cause policy.** Every cause runs the work of D10. `rp_logout`,
`session_logout`, `subject_revocation` and `operator_reset` also tell the
relying parties; `expiry` tells none, as natural expiry never has. Without a
notifier no relying-party item is saved.

**D13. The relying-party notifier.** `SessionCloseNotifier`
(`src/user-sessions/lifecycle/notifier.mts`, the `sessionCloseNotifier`
slot) is core's contract; the module that issues to relying parties
implements it. `notify` resolves once a notice is settled — delivered, or
given up by its own policy — and rejects only to be tried again; it may be
called more than once for one notice. `sessionLifecycleModule` refuses to
boot where the `clientRepository` slot is filled and no notifier is. Boot
orders modules, not components, so the module that fills the notifier must
not itself require `sessionLifecycle`, and the closing record's `retainMs` —
`oauth.refreshToken.expiresIn` plus `DEFAULT_CLOCK_SKEW_MS`, within the
port's year, and 0 without a refresh-token lifetime — is read from the
configuration, not from the oauth module's slot. The session grant joins
nothing: it mints access tokens only, which die with liveness.

**D14. The bridge to the per-session stores, and adoption.** While
`SessionRPRegistry`, `SessionFamilyIndex` (with its end mark) and
`SessionFederationIndex` are still read elsewhere, the service writes them
too (`src/user-sessions/lifecycle/bridge.mts`). A join writes the relying
party, then the family through `addFamilyIdUnlessEnded`, then the
federation, before the lifecycle join; an `ended` refuses the join. A close
writes the end mark (`endSession`) and lists the three stores before its
commit, and joins what they hold to the record, so the snapshot holds what
joined through them. A session with no lifecycle record is adopted — opened
from its user session's subject and end: by a close always, since closing is
never unsafe; by a join only where no end mark can be present — its family
passed `addFamilyIdUnlessEnded`, or the family index keeps no mark. A join
with no family, on an index that keeps the mark, cannot read it and is
refused with nothing written: the conservative reading of "only when no old
mark is present". Liveness of a session with no record reads its user
session alone. The bridge and adoption go with the old stores; an absent
record then reads as closed.

The service's one read of a user session is a token-side site of the
session-admission ADR's D9, registered in its guard; the token-side reads
listed there move to `liveness` as their callers switch.
