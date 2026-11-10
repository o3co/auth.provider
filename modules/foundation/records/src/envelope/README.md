# envelope

Internal module of `records`: the envelope an indexed record is kept in, its owner's subject beside its value.

## Responsibilities
- Tells a stored value's envelope from a raw value, and makes the one written back.

## Not here
- Which records are enveloped and indexed, and when: the package's. What a value holds: its owner's.

## Offers
- `opened` (a stored value) → its value and, in an envelope, its subject.
- `kept` (a value, a subject or none) → what to store.
- `ownersValue` (an owner's value) → the same, refused where it holds the envelope's mark at its top.

## Invariants
- An envelope is `{ "records:v": 1, subject, value }`, told by that exact shape: three members, the mark 1, the subject a string. Any other value is raw and has no subject.
- A value written back keeps the envelope it was read in, the same subject, so a write that is not indexed never drops the subject an indexed one kept.
- An owner's value holding `records:v` at its top is refused (TypeError), so no value written raw reads as an envelope.
- No value stored before envelopes takes their shape: each owner's value is a scalar or a list, an object whose top members the owner makes (a format and its own fields), or caller data the owner keeps below its top.

## Depends on
- `store` (the JSON type)
