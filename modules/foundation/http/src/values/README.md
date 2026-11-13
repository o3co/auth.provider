# values

Internal module of `http`: the values a request is received with, by name, read-only, from decoded input: a map, a JSON object's members.

## Responsibilities
- Gives received values by name as read-only maps, from a map of decoded values or from a JSON object's members.

## Not here
- Reading values from what a request sends: decoding a query or a form, and reading a body (the server's).
- What a value means, and whether it must be single (the route's); what a mistyped member means (the route's).

## Offers
- `Values`: a name's values, read-only; `single` gives a name's value when it holds exactly one, and `repeated` the names that hold more.
- `valuesOf` (a map of names to their values), `fieldsOf` (a JSON object → its string members as fields, the names of its others as mistyped), and `readOnly` (a map whose writes throw), on `http`'s contract.

## Invariants
- The values of a name keep the order given.
- The maps, their value lists and the mistyped names cannot be written to, and a write to a map throws.
- A JSON member that is not a string is no field, and its name is mistyped; none are mistyped when every member is a string.

## Depends on
- Nothing.
