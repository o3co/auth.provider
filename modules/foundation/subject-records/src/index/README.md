# index

Internal module of `subject-records`: where a space keeps its subjects' index, and how it is named.

## Responsibilities
- Names a space's index space, and each subject's tombstone and buckets in it.

## Not here
- Writing them: the package's builders, through `records`' `changeRecords`.

## Offers
- `indexSpaceOf` (a space) → its index space: `.index` after its name, its guarantees, `internal`; `isIndexSpaceOf` checks one.
- `indexOver` (a place, its space, its index space) → `tombOf` (a subject), `bucketOf` (a subject, a key), `bucketsOf` (a subject: all 16) and `entryAt` (a partition, as a scan finds it), each a target of the index space.
- `entriesIn` (a bucket's value) → its entries; `listedWith` and `listedWithout` → the bucket's next with an entry, or without those picked; `targetOf` (an entry) → what it lists; `bucketNames`, the 16.
- `SubjectPlace` and `Phase`, as the package offers them; `checkedSubjectPlace` (a place, the categories a builder writes) → its category, refusing at build, through the builder's `refuse`, a store with no batch across, an index not the space's, and another category.

## Invariants
- A subject's part of the index is named by the SHA-256 of the space's name, a line feed and the subject, so no key holds a subject; its tombstone is `<part>.tomb`, its buckets `<part>.m0` to `<part>.mf`.
- A key's bucket is the first hex digit of the key's SHA-256; a bucket holds its entries sorted, each `[key, "record" | "set"]`, and anything else is no entry; it is removed with its last.

## Depends on
- `records` (targets and places), `store` (spaces, the JSON type)
