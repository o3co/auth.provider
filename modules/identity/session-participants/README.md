# session-participants

## Responsibilities
- Keeps the work other modules do when a session closes: the participants they contribute, and the one order they are called in.
- A bridge to `session`: it comes wherever `session` is composed, and is the one contributor of `session`'s `closingParticipants`.

## Not here
- When a session closes, and which closes call the participants (`session` and its implementation). What is logged of a failure (the implementation). What each participant cleans up (its contributor).

## Offers
- Extension point `participants` (`session`'s object, re-exported): a participant's name, and `closing` (the session, its handle and context, never the cookie secret).
- Contribution to `session`'s `closingParticipants`.

## Invariants
- Participants are called one at a time in collect order; a failing one does not stop the rest, and each that failed is answered by its name and the error's kind alone.
- Each participant must be safe to call any number of times, from several hosts at once: a close left pending calls them all again.
- The answer, and each participant's factory, take `sessions` only late: `sessions` collects the answer as it is built.

## Depends on
- `kernel`, `session` (the session, the seam).

## Vocabulary
- participant: a contribution that cleans up when a session closes.
