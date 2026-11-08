# mail-address

## Responsibilities
- Owns the rule for an address mail takes, and its one form to compare by.

## Not here
- Sending mail, and refusing an address it does not take (`mail`). Which address an account states (`users`).

## Offers
- `isAddress` (anything) → whether it is one address mail takes; a sender checks its own configured addresses by it too.
- `canonicalAddress` (text) → the address in one form to compare by, the domain in IDNA's ASCII form, lowercase, the local part as given; none for text that is no address.

## Invariants
- An address is at most 254 bytes in UTF-8, its local part at most 64, its domain's IDNA ASCII form at most 253 octets and 63 a label, and holds no space, control or format character, route operator (`%`, `!`) or encoded word. Letters beyond ASCII are allowed.
- Its domain reads one way: IDNA's ASCII form of it is letters, digits, hyphens and dots, each `xn--` label in it decodes to other letters and encodes back to itself, and the domain is that form or its Unicode form, case aside.

## Depends on
- Nothing in the workspace.
