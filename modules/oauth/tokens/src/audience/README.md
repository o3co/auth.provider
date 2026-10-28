# audience

Internal module of `tokens`: the audiences an access token is for besides its grant's, as additions answer them, and how `aud` is split back into the two.

## Responsibilities
- Gives, for a grant, the audiences the additions answer, each once and none of the grant's own; a value that is not a non-empty string, or any to a grant with no audience, is the caller's mistake (TypeError).
- Splits a read `aud` by `aud_added` into the grant's audience and the added ones; none where `aud_added` would leave the grant none or counts a string `aud`.

## Depends on
- The package's contract (`AccessGrant`, `AudienceAddition`).
