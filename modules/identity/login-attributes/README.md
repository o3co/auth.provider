# login-attributes

## Responsibilities
- Decides which of a login's attributes are kept: `users`' named set, within caps.
- Keeps the attributes under the source that stated them.
- Names the sources that logins state attributes under.

## Not here
- The attribute names and the forms each value takes (`users`).
- Mapping a source's values to the named set (the login that passes them).
- Keeping the attributes with a session (`session`).
- How each given value is judged and copied (`keeping`).

## Offers
- `SourcedAttributes`: the source, and the values by `users`' names.
- `loginSource.users`: the source for `users`' ledger.
- `loginSource.upstream(idp)`: the source for an upstream IdP.
- `attributeCaps`, the schema part a section takes for the caps an operator may set: `groups-limit` (1–200, default 64), `group-limit` and `picture-limit` (UTF-8 bytes, written with a unit: 1B–1KiB, default `256B`; 1B–8KiB, default `2KiB`).
- `keepingWith` (the caps read) → keeping: given attributes of any shape → the kept copy or none, the names dropped, and the count of names outside the set.
- Keeping logs nothing.
- `sourcedAttributesShape`: the form a kept copy is read back in, by name and type only.
- A copy read back has its caps judged by keeping it again.

## Deprecated
- `keptAttributes` (given attributes of any shape) → as `keepingWith` keeps them under the default caps; use `keepingWith(attributeCaps.parse({}))`. A later release removes it.

## Invariants
- Attributes are only the named set.
- A value `users` does not take (`acceptedAttributes`), empty or ill-formed, is dropped whole, never cut.
- Lowering a cap changes an open session's attributes when they are read back: a value past it is dropped then.
- A dropped attribute is reported by name, never by value.
- Names outside the set are reported only as a count.
- An `email` without `email_verified` is not verified.
- Each given value is read once.
- The kept copy is frozen.
- An upstream source never equals the `users` source, whatever the IdP's name.

## Depends on
- `users` (the attribute names and the forms each value takes); `kernel` (`setting`, a size's unit).

## Vocabulary
- attributes: what a login says of the user from `users`' named set (`userAttribute`, by those names).
- source: who stated the attributes, named by `loginSource`; it is never read here.
- upstream: an upstream IdP, by its name.
