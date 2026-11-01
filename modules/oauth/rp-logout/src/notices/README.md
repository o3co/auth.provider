# notices

Internal module of `rp-logout`: back-channel notices that a session closed.

## Responsibilities
- Keeps a notice for each client a closing session holds, and sends each a logout token until it is settled or too old, a failed try not tried again until a `sweep-interval` after it was last due, or made.

## Not here
- Which clients a session holds (written by the package on each redemption). When a session closes (`session`).

## Offers
- `noticesFrom` (the build context) → `closing` (a session → its notices, once all are written), `deliver` (notices → one try each) and `sweep` (one try at every kept notice whose wait is over).

## Depends on
- `clients`, `issuer`, `keys`, `outbound`, `session` (the session's type); the package's store interfaces, section and `registration`
