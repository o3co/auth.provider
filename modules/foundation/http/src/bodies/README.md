# bodies

Internal module of `http`: the values a request is sent with, by name, from its body as its route takes it and from its query alike.

## Responsibilities
- Tells a body's kind from its type, and reads a form or a JSON object up to the size limit.
- Gives the received values by name as read-only maps.

## Not here
- Which bodies a route takes (the route's declaration).
- What a value means, and whether it must be single (the route's).
- What a mistyped member means (the route's).

## Offers
- A request's body as its route takes it: its form, its fields, the JSON object and its mistyped names, or the status that refuses it.
- Values by name, read-only, from a map, a query, a form, or a JSON object's fields: `single` gives a name's value when it holds exactly one, and `repeated` the names that hold more.

## Invariants
- A form and a JSON body share one size limit of 64 KiB: a larger form is read as empty, and a larger JSON body is `413`.
- A JSON body is one object in well-formed UTF-8, frozen, naming no member twice in one object; anything else is `400`.
- A route may take a form, JSON, none, or several.
- A request's fields are its body's values by name.
- A JSON member that is not a string is no field, and its name is mistyped.
- A body the route does not declare is `415`, and gives no fields.
- A route that declares no bodies reads a form when one is sent, and ignores any other body.
- No type and nothing sent is no body.
- A query's or a form's percent-escapes are read as UTF-8 and `+` as a space, a `%` without two hex digits kept as sent; escapes that are not well-formed UTF-8 give no values, and such a form, or one whose bytes are not UTF-8, is `400`.
- The values of a name keep the order sent.
- The maps, their value lists and the mistyped names cannot be written to, and a write to a map throws.

## Depends on
- `http` (its contract: the body kinds), and `kernel` (freezing).
