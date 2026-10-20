# session-tokens

## Responsibilities
- Ends a session's access tokens when the session closes; `tokens` knows nothing of sessions.
- Records per session references to the access tokens issued for it, revoking them as a participant in its closing.
- Answers which session a token was issued for, by an index of token ids.

## Not here
- The token format and its revocation: `tokens`. The session lifecycle: `session`. When to issue a token: the issuing side.
- Session expiry: participants are not called for a session ending by expiry, whose tokens live out their lifetimes; closing a session is what ends its tokens.

## Offers
- `sessionOf(token id)` → bound, with the session handle, or unbound when no session recorded it.
- `grants`' tie `session`: a token's session, held while it lets the token in, else ended (`session has ended`, `session is short of a requirement`); a join only checks again.
- Store interfaces, each with its needs (never evicted, survives a crash, does not come back on failover) and contract test (`./testing`):
  - the tokens issued in each session: add a reference for its lifetime → the references pushed out, which await in that same write until settled; the references kept, with how long each lives; how many it keeps to a session;
  - the token index: token id → session handle, saved once per id, for a lifetime;
  - the sessions pending a push-out: add, done, go through them; one whose handling fails stays and is counted. It never pushes one out and refuses when full.
- A stand-in (`./testing`): all its store interfaces in memory, for tests composing the real module.
- Operator section: `sweep-interval` (written with its unit, `1s` to `1h` in whole seconds, default `30s`); `push-out-margin` (default 8, below the store's size, else boot is refused); the store's size is how many tokens a session keeps.
- Composition definition: the participant for closing, and `grants`' session issuance recording each token issued from a session, answering after a confirmed write; the only way a token is recorded.

## Invariants
- Recording a token the index binds to another session fails as unavailable, so `token-endpoint` revokes it.
- A token is indexed before its reference is kept, for the same lifetime, so every kept reference names its session in the index.
- An add within `push-out-margin` of the store's size lists its session first.
- What an add pushes out awaits in the set's own write; its tokens are revoked and settled, the session leaving the list once nothing awaits.
- A pushed-out token that cannot be revoked fails the record, left to the sweep every host runs each `sweep-interval` over the listed sessions.
- Closing a session revokes what awaits too.
- A host stopped past the add leaves the session listed.
- The window left: more adds at once than the margin push one out unlisted, and the host stops before listing it.
- On close, it answers done only after revoking every recorded token, else throws; the session stays closing, and a later close continues. Safe to repeat, and from several hosts at once.
- Closing a session, revoking a token or pushing its reference out leaves its index entry, so the token still answers its session; whoever asks, as the `session` tie does, checks it is open.
- `sessionOf` throws unavailable when the index cannot tell, never unbound.
- Boot is refused where access tokens cannot be revoked.

## Data
- References of the tokens issued in each session, and the token index, each kept for the token's remaining lifetime on `kernel`'s clock plus an allowance; lost, tokens would survive a closed session or answer no session. Pushed-out references to revoke are kept until done.

## Depends on
- `kernel`, `session`, `session-participants`, `tokens`, `grants`

## Vocabulary
- reference: what names an issued token for revoking it later, without the token itself (`tokens`' own).
- push out: the store dropping the references that end first when a session's set is full, never the one added; answered as `pushedOut`, never silent.
