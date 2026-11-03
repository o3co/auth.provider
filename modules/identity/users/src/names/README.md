# names

Internal module of `users`: what an IdP name stands for, within one boot and across boots.

## Responsibilities
- Refuses names that stand for two issuers within one boot, and a name standing for another issuer than the one kept for it.
- Keeps each declared name's issuer in the link store, and moves it as the operator states.

## Not here
- Which names exist (the declaring modules). Links and what they match by (`links`).

## Offers
- `namesRefused` (the declarations) → reasons, for one boot.
- `issuersJudged` (the declarations, `issuer-moved`, the link store, the log) → refusals, across boots, reading alone, and `settle`: what to write once no module refuses the boot, answering what is refused of what it finds written.

## Invariants
- A name's issuer is compared as written.
- Nothing is written while a boot is built: a boot refused by any module's build, this one's judgment among them, writes nothing and applies no stated move, and a new name beside a refused one is not kept either. A write is made once every build passed (`kernel`'s `onBuilt`), and is not taken back if a later such hook refuses.
- One name is one record, saved if absent, so of instances starting at once the first writer's issuer is what the rest are judged by.
- A store that cannot answer, at the read or the write, is a refusal, as is a record of another shape; neither reads as no record.
- An entry passes where the kept issuer is its `from` and the declared one its `to`, rewriting the record over that `from` alone, or where both are its `to`; any other, no record kept or no such name among them, is refused at its key.
- A refusal holds the declaring modules or a key path, never a name or an issuer; `users.issuer_moved` names the IdP of each entry, at every start that passes, once it is written, and never an issuer.

## Data
- Format 1: `{ issuer }`, under `{"idp":<name>}`, which no link's key can be (a link's is a list); kept without end.

## Depends on
- `kernel`; users' contract and link store
