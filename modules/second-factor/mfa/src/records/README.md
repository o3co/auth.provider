# records

Internal module of `mfa`: how the factor lists and the claims on unique values are kept in `factorStore`, and sealed again.

## Responsibilities
- Keeps each subject's factor list, and each claim on a value no two factors may hold, in the store, by keys it makes.
- Seals again, for `seal`'s resealers, the secrets a `previous` key sealed.

## Not here
- What the factors decide: `mfa`'s `factors`. Sealing itself: `seal`.

## Offers
- `factorRecords` (store): a subject's list, and a decision written over the list it read; whether a unique value is taken, and a claim on it.
- `resealerOver` (store, seal): the resealer `mfa` contributes.
- `sealContext`, `listKeyOf`, `storedList`, `factorsOf`, `subjectOf`: the keys, contexts and record shapes the two share.

## Invariants
- A factor list's record holds its subject, so its secrets can be sealed again; the store's key is the subject's hash.
- A secret, and what a challenge kept, are sealed to the subject and the factor; a pending binding, to the subject.
- A factor is written before its claim, so a claim whose list lacks its factor is stale.
- A secret a `previous` key sealed is sealed again in the write a proof of its factor makes, and by the resealer, which walks every list and writes only over the secret read; one no key opens, or a list whose subject is not its key's, is left.

## Depends on
- `kernel`, `seal`; `mfa` (its store interface).
