# ADR 2026-10-05 — Session lifecycle: one record per session, active → closing → closed

## Status

Accepted (2026-10-05). The port, its readers, the in-process store and the
contract suite land first; nothing reads the slot yet. The service, the Redis
store and the callers' switch follow in the order below
([#1030](https://github.com/o3co/auth.provider/issues/1030)).

- Written against: `develop` at `72ba648aa`.

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

## Amendment 2026-10-05 — the Redis store's closing index

The Redis store keeps a session's whole record in one hash on the sid's hash
tag, with one expiry, so D5's single retention holds by construction. D6's
listing cannot be kept that way: an index of every closing sid is one key on
a slot of its own, and on Redis Cluster no script writes it together with a
record. The index is therefore kept correct by order, not atomicity:

- **Added before the commit.** `beginClose` adds the sid, with the close's
  write deadline, before the closing commit, which carries the same deadline
  and is refused at or after it on the server's clock. A close that cannot
  add the sid rejects without committing, so every closing record has an
  entry.
- **Stale entries are filtered, then removed only when dead.** The listing
  re-reads each entry's record and names only closing ones, reading on until
  it has `limit` of them. It removes an entry whose record is not closing only
  when the index's clock was past the entry's deadline plus the declared skew
  before that read: no close that added it can commit afterwards, and a later
  close raises the stored deadline, which the removal checks.
- **The closing step removes its own entry** when the closed record outlives
  that deadline plus the skew, since every close that added the entry then
  finds the record closed.

So paging `listClosing` reaches every record that stays closing, under the
store's stated assumptions: the clocks agree within the declared skew,
acknowledged writes are not rolled back, and nothing is evicted (the store's
boot check refuses an eviction policy). The index has no TTL: it shrinks only
as those steps remove entries, so the service's resumption must page through
`listClosing`.

Sharding the index across a fixed number of hash tags was not taken: it
spreads the one hot slot, but each listing must then merge the shards' orders
and gains nothing in correctness. It stays possible behind the same port.
