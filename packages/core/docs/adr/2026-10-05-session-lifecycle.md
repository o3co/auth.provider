# ADR 2026-10-05 — Session lifecycle: one record per session, active → closing → closed

## Status

Accepted (2026-10-05). The port, its readers, the in-process store and the
contract suite land first; nothing reads the slot yet. The service, the Redis
store and the callers' switch follow in the order below
([#1030](https://github.com/o3co/auth.provider/issues/1030)).

- Written against: `develop` at `72ba648aa`.
- Amended 2026-10-05: the service, its answers, the close work, resumption,
  the cause policy, the relying-party notifier, the bridge and where the
  service lives (D8–D15); and how the notifier is wired (D16).
  Written against `develop` at `5871ff698`.
- Amended 2026-10-05: the service opens a record where a session is
  established (D8).
- Amended 2026-10-06: the memory store, full, evicts a closed record.
- Amended 2026-10-06: an outage rejects with the store's own error and is
  logged by the caller; the service never answers `unavailable` (D8, D9).

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
  evicted record would let a closed session be joined again (superseded by
  the 2026-10-06 amendment).
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

## Amendment 2026-10-05 — the Redis store: records and closing indexes in fixed shards

The Redis store keeps a session's whole record in one hash with one expiry,
so D5's single retention holds by construction. D6's listing needs an index
of closing sids, and on Redis Cluster a script can write only keys of one
slot, so where that index lives decides whether it is kept atomically.

**Decision.** Records are spread over sixteen fixed shards: a sid's shard is
the 32-bit FNV-1a hash of its UTF-8 bytes modulo 16, and each shard's records
and its closing index (a sorted set of sids, every score 0, ordered by their
bytes) share one hash tag. The closing commit adds the sid to its shard's
index, and the completion that closes the record removes it, in the script
that writes the record; nothing about the index is judged by a clock.
`listClosing` merges the sixteen indexes in byte order after a plain-sid
cursor, and checks each sid's record in its shard's own step, dropping an
entry whose record is no longer closing (one that lapsed while closing). So
paging reaches every record that stays closing, assuming only that
acknowledged writes are not rolled back and nothing is evicted (the store's
boot check refuses an eviction policy).

The shard count is a constant of the key layout, not a setting: changing it
moves every record, a breaking change with a migration. Sixteen spreads the
store over up to sixteen Cluster primaries and keeps a listing to sixteen
index reads per page.

**Rejected: one slot per sid with a separate index.** An index on a slot of
its own can only be kept by order: add the sid before the closing commit,
then remove a stale entry once no close that added it can still commit,
judged by write deadlines and a clock-skew allowance. That judgement needs
clocks that never step backward. A record server whose clock steps back
within the allowed skew still accepts a delayed closing commit after the
listing judged its deadline passed and removed the entry, and the record is
then closing with no entry, never listed again. Fencing each entry with a
token on the record avoids the clock but adds a protocol with its own edge
(a lapsed sid opened again). Fixed shards trade one slot per sid for an
index kept in the same atomic step as the record.

## Amendment 2026-10-05 — the service

**D8. The service and its answers.** `SessionLifecycle`
(`src/session-lifecycle/service.mts`) fills the `sessionLifecycle`
slot through `sessionLifecycleModule`, which the standalone template
installs. `open(sid, { sub, expiresAt })`, called where a session is
established, writes its record active and answers `opened` (a repeat for the
same subject and end too), `refused` or `unavailable`: the service is the
port's one writer, so no caller opens a record through the port.
`join(sid, { rp?, familyId?, federation? })` answers
`joined`, `refused` or `unavailable`; on `refused` the service revokes the
family and deletes that federation's tokens it was handed, and the caller
hands out nothing. `close(sid, cause)` answers `done`, `pending` or
`unavailable`, with the snapshot's relying parties and federations.
`liveness(sid)` answers `live` with the user session, or `not_live`, or
`unavailable`. A sid the port cannot hold names no session, so the reads
answer it as one never opened — `liveness` `not_live`, `federations` none —
and reach no store; the writes, `join` and `close`, refuse it with a
RangeError. `resumePending()` runs the close work of every closing
record. A participant's `data` is `""`: its kind and id are all it holds
(D7).

**D9. A close whose commit landed answers `pending`, never `unavailable`.**
From the closing commit on, liveness answers `not_live` and nothing joins,
so a close with work still outstanding has ended the session; it answers
`pending`, distinct from `done`. `unavailable` means the commit did not land,
or whether it did could not be read. A commit that finds no live record —
the session's end passed on the store's clock before its record could be
opened, or since it was read, which the clock skew between the hosts and
the store allows while the user session is still read — has no record to
save the work in. The close runs that work at once, in its phases, over the
record the commit would have saved (the read record's participants, or
none), without `completeIf`, and answers `done`; an item that fails makes it
answer `unavailable`, so a later close runs it all again — except once the
user session is deleted: a close then finds neither a record nor a user
session and answers `done`, and an entry the last phase left in the
subject's index lapses at its retention or goes with a subject-wide
revocation. How a route
answers `pending` (the logout's 200 and a `logout.close_pending` audit
event) is decided when that route switches.

**D10. The close work, in phases.** An item runs only once no item of an
earlier phase is pending in the record, so no phase runs over work an
earlier one has not durably done:
1. one item per family (`revokeFamily`), `revoke_bridged_families` (D14)
   and `remove_federation_tokens` (`federationTokenStore.removeBySid`);
2. one item per relying party and `notify_bridged_rps` (D14), through
   `SessionCloseNotifier`; an item this code does not know waits here;
3. `remove_session_indexes` (the per-session stores the bridge steps read);
4. `delete_user_session`;
5. `remove_subject_session` (`subjectSessionIndex.removeSid`, where a
   subject index is wired), last: a close still pending keeps the sid in
   the subject's index, which a subject-wide revocation enumerates, so
   where subject revocation closes through the lifecycle (#1455) a retry of
   that revocation finds the sid and resumes its close. The index is read
   only to enumerate the sessions to revoke, never as a sign that one is
   live.

The items of a phase run together, and one close run makes at most eight
notices and family revocations at once (`CLOSE_CONCURRENCY`), those of the
record's participants and those a bridge step reaches sharing the eight
places; an item or a bridge step holds no place itself. A notice waits on
its relying party, so relying parties that do not answer hold a close for
about one notifier timeout per eight, not one each. Each item that ran is
recorded with `completeIf` at the generation read, one at a time once its
phase's run has settled; a conflict re-reads the record and goes on with
what is still pending, so two closes of one session and the sweep may
overlap. A run that overlaps another, or one that stops before it records,
may so run a whole phase's items again, which every item allows and the
notifier allows for a notice (D13). A failed item, or one whose completion
could not be recorded, stays pending and the record stays `closing`; the
other items of its phase still run.

**D11. Resumption.** A later close of the same sid resumes the saved work,
whatever its cause (the first cause is kept). A sweep owned by core,
`resumePending`, pages `listClosing` by its `after` cursor every
`core.sessionLifecycle.sweepIntervalSeconds` — whole seconds, read through
`configuredNumber`, refused at boot naming the key otherwise — one sweep at a
time, stopped on dispose. Core's `reference.conf` ships 60, and a
configuration without it reads 60 too; 0 turns the sweep off. A close
left pending once its user session is gone has no later close to resume it,
so without the sweep it would stay pending until the record lapses. A
subject index that keeps failing leaves records `closing` on their last item
that only the sweep or their retention ends, so with
`sweepIntervalSeconds = 0` they stay until they lapse.

**D12. The cause policy.** Every cause runs the work of D10. `rp_logout`,
`session_logout`, `subject_revocation` and `operator_reset` also tell the
relying parties; `expiry` tells none, as natural expiry never has. Without a
notifier no relying-party item is saved.

**D13. The relying-party notifier.** `SessionCloseNotifier`
(`src/session-lifecycle/notifier.mts`; how it is wired is D16) is core's
contract; the module that issues to relying parties
implements it. `notify` resolves once a notice is settled — delivered, or
given up by its own policy — and rejects only to be tried again; it may be
called more than once for one notice. With `sessionLifecycleModule`
installed, boot refuses a composition where the `clientRepository` slot is
filled and no notifier is (D16). Boot
orders modules, not components, so the closing record's `retainMs` —
`oauth.refreshToken.expiresIn` plus `DEFAULT_CLOCK_SKEW_MS`, within the
port's year, and 0 without a refresh-token lifetime — is read from the
configuration, not from the oauth module's slot. That read is a known
coupling to the oauth module's section; it moves to a core slot when oauth
exposes token lifetimes through one that the lifecycle module can read
without a cycle. The module is eager: installed, it is built at boot whether
or not anything requires the slot, so the refusal and the sweep do not wait
for a consumer. The session grant joins nothing: it mints access tokens
only, which die with liveness.

**D14. The bridge to the per-session stores, and adoption.** While
`SessionRPRegistry`, `SessionFamilyIndex` (with its end mark) and
`SessionFederationIndex` are still read elsewhere, the service writes them
too (`src/session-lifecycle/bridge.mts`). A join writes the relying
party, then the family through `addFamilyIdUnlessEnded`, then the
federation, before the lifecycle join; an `ended` refuses the join. A close
writes the end mark (`endSession`) before its commit, so nothing joins
through them after. What joined through them is not imported into the
record, since an import would be a join and could be refused (by capacity,
or by the session's end passing): two steps read them when they run instead.
`revoke_bridged_families` revokes every family the index lists that is not
the record's own, and `notify_bridged_rps` tells every relying party the
registry lists that is not the record's own. The close that commits also
answers the relying parties and federations they listed after the mark. A session with no lifecycle record is adopted — opened
from its user session's subject and end: by a close always, since closing is
never unsafe; by a join only where no end mark can be present — its family
passed `addFamilyIdUnlessEnded`, or the family index keeps no mark. A join
with no family, on an index that keeps the mark, cannot read it and is
refused with nothing written: the conservative reading of "only when no old
mark is present". A join that adopts is refused when the store refuses its
open, and reads the user session again once it has opened the record and
joined: a close that completed since its first read, and whose closed
record then left the store, let the open land, and the close deleted the
user session before it closed the record, so a join that finds it gone, or
finds another session created under the sid since (another subject,
authentication time or end), is refused and withdrawn like one the record
refuses. A join refused there leaves the record it opened active, with what
it joined, until the record lapses; the withdraw revokes the family and
removes the federation's tokens, and no live session is read for the sid.
Liveness of a session with no record reads its user session alone. The
bridge and adoption go with the old stores; an absent record then reads as
closed.

Two known limitations of the bridge are accepted as interim. It exists only
between this amendment and the removal of the bridge and adoption, which
lands in the same release
([#1030](https://github.com/o3co/auth.provider/issues/1030)), so neither
reaches a released version, and closing either would change a store
contract for a component that is removed:
- **Bridged targets lapse with the old stores.** The bridge steps read the
  per-session stores when they run, and those lapse at the session's
  `expiresAt`, before the closing record does. A bridge step that fails
  until then finds nothing left and is recorded done: those families are
  not revoked by it (refresh needs a live session, which they no longer
  have), and those relying parties are not told.
- **A join without a family is not fenced by the old end mark.** The mark is
  read only through `addFamilyIdUnlessEnded`, so on a record that already
  exists such a join (a federation link) lands while a close begun through
  the old stores is under way; tokens attached for it are then outside that
  close's cleanup.

**D15. Where the service lives.** The service, its module, the bridge, the
notifier contract and the sweep are in `src/session-lifecycle/`, apart from
the port in `src/user-sessions/lifecycle/`. The service reads a session
record only through `session-admission/`'s `readRecord`, the one read of a
record admission makes, so no new site reads a session outside admission;
and since `session-admission/` imports values from `user-sessions/`, the
service inside `user-sessions/` would close a value cycle between the two.
`session-lifecycle/` imports `session-admission/` and `user-sessions/`, and
neither of those imports it. So admission's own `not_live` read, when it
learns the lifecycle state, reads the port in `user-sessions/`, never the
service. The token-side liveness reads move to `liveness` as their callers
switch.

**D16. The notifier is a contribution, read when a close runs.** The module
that tells relying parties (the oauth module) is also the one that, once its
logout route switches, requires `sessionLifecycle`. Boot orders modules by
what they `require` and take `optional`, so a notifier filled in a slot the
lifecycle module reads at construction would order the notifier's module
before the lifecycle's, and that module could read nothing of a module
requiring the lifecycle — the issuer in `oauthTokenSettings` among it —
without a cycle. So the notifier is contributed under the
`sessionCloseNotifiers` contribution kind, at most one per composition,
and the service reads it through the synthetic `sessionCloseNotifierResolver`
when a close runs, never while modules are built, as other contributions are
read through their resolvers. A contribution kind rather than a getter handed
to the service: core has no lazily readable channel but a synthetic resolver
over contributions, so a getter would need the same plumbing. The notifier is
its contributor's, switched off only by not installing its module: a factory
answering anything but a notifier fails its contribution (never `null`), and
at stage 1 a container that is no record is refused
(`contribution-malformed`), any override of the kind is refused
(`contribution-kind-guarded`, channel `overrides`), and so is a second
notifier under any name (`duplicate-contribute`); a host may not supply the
collector (`contribution-kind-guarded`). The rule that a composition serving
relying parties needs a notifier is judged at the end of the contributions,
once the notifier would have registered, and only where
`sessionLifecycleModule` built the `sessionLifecycle` slot — a value the host
filled it with is the host's. It is refused as before, as that module's
provider failing (`provides-factory-failed`, naming
`core-session-lifecycle`), its remedy now naming the contribution: install a
module that contributes a `sessionCloseNotifiers` entry, as `oauthEndpointsModule`
does.

**D17. Join order, and the federations a logout reads first.** A record's
participants are answered in the order each first joined; a repeat join
replaces its `data` and does not move it — the order the per-session
federation index has always kept, which a logout reads to pick the
federation it ends upstream. The in-process store keeps that order; the
Redis store keeps it from the join ordinal its join script writes, and
until then answers byte order. `SessionLifecycle.federations(sid)` answers
the federations in the order they joined: while the bridge stands, the
index's first, in its insertion order — every join writes the index before
the record, so that is the order of joining, a federation joined before the
switch included — then the record's, each once. That is the union and order
the close that makes the closing commit answers; a later close answers the
snapshot's. Once the bridge goes, the record's order alone holds it. A logout reads it before the close, since the close removes the
federation tokens that carry the upstream `id_token_hint`. A logout whose
close commits with work still pending is audited as `logout.close_pending`.

## Amendment 2026-10-06 — the memory store, full, evicts a closed record

The memory store no longer only rejects when full. It drops lapsed records
and, if that makes no room, evicts the `closed` record whose retention ends
first; it rejects when there is none. A login and logout loop on one
account would otherwise fill it with closed records and refuse every login
until they lapsed. Closing records are never evicted, so a loop whose
closes stay pending still fills the store until their retention.

A closed record may so go before its retention. What makes that safe is
the service's re-check on a join that adopts a session (#1468): the service
closes a record only after deleting its user session, and a join that
finds no record, opens one and joins is refused unless the user session it
read first is still there, so a closed session is not joined again through
a record that left the store. A repeated close or `federations` then
answers no snapshot, as after the record's retention. An active or closing
record is never evicted: that would drop a live session's fence, or leave
its close work undone. A close run overlapping one that completed may
answer `pending` once the closed record has left the store, as after its
retention; a subject revocation may then report that sid not revoked until
a retry. The port and its contract are unchanged.

## Amendment 2026-10-06 — an outage rejects with the store's own error

`open`, `join`, `close`, `federations` and `liveness` no longer answer
`unavailable` (D8). A store that cannot answer rejects the call with its own
error, unwrapped, and the service logs nothing for it: the caller logs the
outage once, at error, with the error's projection, where it used to log an
`unavailable` answer beside the service's own warn. Where D9 says a close
answers `unavailable` — the closing commit did not land, whether it did could
not be read, or an item of the close work run with no record to save it in
failed — the close now rejects. `pending` and `done` are unchanged.
`unavailable` stays in the answer types until it is removed. The close work's
and the sweep's own lines are unchanged: `session_lifecycle_unavailable`
(warn) is still logged where a close's item ran but recording it failed, or a
closing record could not be re-read by a close or the sweep.
