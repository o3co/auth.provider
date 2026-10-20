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
- `keptAttributes` (given attributes of any shape) → the kept copy or none, the names dropped, and the count of names outside the set.
- `keptAttributes` logs nothing.
- `sourcedAttributesShape`: the form a kept copy is read back in, by name and type only.
- A copy read back has its caps judged by keeping it again.

## Invariants
- Attributes are only the named set.
- A value `users` does not take (`acceptedAttributes`), empty or ill-formed, is dropped whole, never cut.
- A value over its cap is dropped whole, never cut.
- The caps, in UTF-8 bytes: name 512, picture 2048, each group 256; and at most 64 groups.
- A verification without its email is dropped.
- A source empty, ill-formed, over 128 bytes or holding a control character drops them all.
- A dropped attribute is reported by name, never by value.
- Names outside the set are reported only as a count.
- An `email` without `email_verified` is not verified.
- Each given value is read once.
- The kept copy is frozen.
- An upstream source never equals the `users` source, whatever the IdP's name.

## Depends on
- `users` (the attribute names and the forms each value takes).

## Vocabulary
- attributes: what a login says of the user from `users`' named set (`userAttribute`, by those names).
- source: who stated the attributes, named by `loginSource`; it is never read here.
- upstream: an upstream IdP, by its name.
