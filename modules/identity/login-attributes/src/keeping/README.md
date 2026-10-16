# keeping

Internal module of `login-attributes`: keeping a login's attributes within caps.

## Responsibilities
- Judges each given attribute, and keeps a copy of those that hold.
- Tells which names it dropped, and how many names outside the set were given.

## Not here
- The source names and the form a kept copy is read back in (`login-attributes`' root).
- Whether `users` takes a value (`users`).

## Offers
- `keptAttributes`, as `login-attributes` offers it.

## Invariants
- A value `users` does not take (`acceptedAttributes`) is dropped whole.
- A value over its cap is dropped whole, never cut.
- The caps, in UTF-8 bytes: name 512, picture 2048, each group 256.
- More than 64 groups are dropped whole.
- An empty or ill-formed value is dropped whole.
- A verification without its email is dropped.
- A source that is empty, ill-formed, over 128 bytes or holding a control character drops every attribute.

## Depends on
- `users` (`acceptedAttributes` and the attribute names); `login-attributes`' contract types.
