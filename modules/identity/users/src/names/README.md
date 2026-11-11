# names

Internal module of `users`: what an IdP name stands for, within one boot and across boots.

## Responsibilities
- Refuses names that stand for two issuers within one boot, and a name standing for another issuer than the one kept for it.
- Keeps each declared name's issuer, and moves it as the operator states: in the link store, and, where a name store is offered, a copy there.

## Not here
- Which names exist (the declaring modules). Links and what they match by (`links`).

## Offers
- `namesRefused` (the declarations) → reasons, for one boot.
- `nameRecordsOver` (the link store) → where names are kept: its `names` and `unowned`, or the link space alone; `issuersJudged` (the declarations, `issuer-moved`, those records, the log) → refusals, across boots, reading alone, and `settle`: what to write once no module refuses the boot, answering what is refused of what it finds written.

## Invariants
- A name's issuer is compared as written.
- Nothing is written while a boot is built: a boot refused by any module's build, this one's judgment among them, writes nothing and applies no stated move, and a new name beside a refused one is not kept either. A write is made once every build passed (`kernel`'s `onBuilt`), and is not taken back if a later such hook refuses, nor where `start` then fails.
- A name not written is read again then, so a move another instance made during this build is judged. Writes are per name: where a later one cannot answer, the boot is refused and what was written of an earlier one stays.
- One name is one record, saved if absent, so of instances starting at once the first writer's issuer is what the rest are judged by. It is kept once no module refuses the boot. A store that does not keep it across a restart says so at every start (`store.volatile_accepted`, `redis.durability_none`), and a change of issuer then goes unseen.
- With a name store, the link space keeps the record until the one migration takes names out of it: every write goes there first (a first save through `unowned`, a move as an update), and the name store is a copy, brought in step at each write and at every boot, so a write cut short between the two heals at the next.
- Where `unowned` answers `closed`, the link space keeping no names any more, the name store is the record. A name kept in the name store alone is read as kept, and no record is made in the link space again.
- A store that cannot answer, at the read or the write, is a refusal, as is a record of another shape; neither reads as no record.
- An entry passes where the kept issuer is its `from` and the declared one its `to`, rewriting the record over that `from` alone, or where both are its `to`; any other, no record kept or no such name among them, is refused at its key.
- A refusal holds the declaring modules or a key path, never a name or an issuer; `users.issuer_moved` names the IdP of each entry, at every assembly no module refuses, an entry's that never starts too, once it is written, and never an issuer.

## Data
- Format 1: `{ issuer }`, under `{"idp":<name>}`, which no link's key can be (a link's is a list); kept without end.

## Depends on
- `kernel`; users' contract and link store (its `names` and `unowned`)
