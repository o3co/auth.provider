# session-tokens

## Responsibilities
- Ends a session's access tokens when the session closes; `tokens` knows nothing of sessions.
- Records, per session, references to the access tokens issued for it, and revokes them as a participant in closing it.
- Answers which session a token was issued for, through an index by token id.

## Not here
- The token format and its revocation: `tokens`. The session lifecycle: `session`. When to issue a token: the issuing side.
- Session expiry: participants are not called for a session that ends by expiry, and its tokens live out their own lifetimes. The promise is that closing a session ends its tokens.

## Offers
- `sessionOf(token id)` → bound, with the session handle, or unbound when no session recorded it.
- `grants`' token tie `session`: a token's session, `ended` (`session has ended`, `session is short of a requirement`) or held with its handle while `session` lets it in; joining a token issued from it checks that again and records nothing, as `issue` records it.
- Store interfaces, each with its needs (never evicted, survives a crash, does not come back on failover) and contract test (`./testing`):
  - the tokens issued in each session: add a reference for its lifetime → the references pushed out, which await in that same write until settled; the references kept, each with how long it still lives; how many it keeps to a session;
  - the token index: token id → session handle, saved once per id, for a lifetime;
  - the sessions pending a push-out: add, done, go through them; one whose handling fails stays, and is counted. It never pushes one out, and refuses when full.
- A stand-in (`./testing`): all its store interfaces in memory, for tests that compose the real module.
- Operator section: `sweep-interval` (written with its unit, `1s` to `1h` in whole seconds, default `30s`); `push-out-margin` (default 8, below the store's size, else boot is refused). How many tokens a session keeps is the store's size.
- Composition definition: the participant for closing, and the contribution to `grants`' session issuances, recording each token issued from a session; it answers after a confirmed write. It is the only way a token is recorded.

## Invariants
- A record of a token the index binds to another session fails as unavailable, so `token-endpoint` revokes that token.
- A token is indexed before its reference is kept, for the same lifetime, so every kept reference names its session in the index.
- An add within `push-out-margin` of the store's size lists its session first.
- What an add pushes out awaits in the set's own write; its tokens are revoked and settled, and the session leaves the list once nothing awaits.
- A pushed-out token that cannot be revoked fails the record and is left to the sweep, which every host runs every `sweep-interval` over the listed sessions.
- Closing a session revokes what awaits too.
- A host stopped past the add leaves the session listed.
- The window left: more adds at once than the margin push one out unlisted, and the host stops before listing it.
- On close, it answers done only after revoking every recorded token. If it cannot, it throws; the session stays closing, and a later close continues. Safe to repeat, and from several hosts at once.
- Closing a session, revoking a token or pushing its reference out leaves its index entry, so the token still answers its session; whether that session is open is checked by whoever asks, as the `session` tie does.
- `sessionOf` throws unavailable when the index cannot tell, never unbound.
- Boot is refused where access tokens cannot be revoked.

## Data
- References of the tokens issued in each session, and the token index, each kept for the token's remaining lifetime on `kernel`'s clock plus an allowance. If lost, tokens would survive a closed session, or answer no session. Pushed-out references still to revoke are kept until done.

## Depends on
- `kernel`, `session`, `session-participants`, `tokens`, `grants`

## Vocabulary
- reference: what names an issued token for revoking it later, without the token itself (`tokens`' own).
- push out: what the store does to the other references that end first when a session's set is full, never the one added; answered as `pushedOut`, never silent.
