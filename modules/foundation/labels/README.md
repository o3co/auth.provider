# labels

## Responsibilities
- Owns the rule for a name a user gives something that a page shows back as it is, such as a second factor's label or a passkey's nickname.

## Not here
- What is named, and where the name is kept (the module that takes it). How a page escapes what it shows (the page's).

## Offers
- `isLabel` (text) → whether it is such a name.

## Invariants
- A label is 1 to 64 code points, well formed (no lone surrogate).
- It holds no control character (`\p{Cc}`), line or paragraph separator, directional mark (U+061C, U+200E, U+200F) or bidi control (U+202A to U+202E, U+2066 to U+2069): each breaks a line or reorders the text around it.
- Any other character is taken, spaces and joiners included.

## Depends on
- Nothing in the workspace.
