# promotion

Internal module of `conformance`: promoting a replica of a Redis topology's primary without losing what the primary took.

## Responsibilities
- Decides whether a replica may be promoted, holds the primary's writes while it catches up, and moves the topology's membership to the new primary.

## Offers
- `promote` (on a topology's membership: its nodes, whom each follows, those killed, the primary; a replica only once it has caught up with the primary, within a wait given), killing the old primary or keeping it on, and reattaching the replicas named to the new one; a step a scene takes while writes are held (`between`); the barrier's span.

## Invariants
- A replica that has not caught up, or follows another replication history than the primary, is never promoted; its refusal says it is not eligible.
- Writes to the primary are held from the barrier at which the target is taken until the old primary is killed or, kept on, released. The hold lapses on its own (`holdMs` past the catch-up), so a promotion still holding writes a second before it lapses, `between` included, fails rather than lose what the old primary took after the target.
- Keeping the old primary on needs a replica reattached to the new one and one of its own to stay with it; a choice that leaves either without is refused before anything changes.
- A promotion that fails after the barrier leaves an old primary it did not kill taking writes again.
- With the old primary kept on, each primary keeps a replica online.

## Depends on
- The relay's answer.
