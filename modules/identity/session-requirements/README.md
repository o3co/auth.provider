# session-requirements

## Responsibilities
- Keeps what a session must meet, beyond being live, to be entered at a level: the entry requirements other modules contribute, and the one order they are asked in.
- A bridge to `session`: it comes wherever `session` is composed, and is the one contributor of `session`'s `entryJudge`.

## Not here
- What makes a session live, the levels, and the `credentials` floor where no requirement judges that level (`session`). What each requirement asks (its contributor).

## Offers
- Extension point `entryRequirements`: a requirement's name, the levels it `judges`, and `admits` (context and level → admit, or short with an answer for the client, passed on unread).
- Contribution to `session`'s `entryJudge`.

## Invariants
- Requirements are asked one at a time in name order; the first that falls short is the answer, by its name and answer, and no later one is asked.
- Where none falls short, the session is admitted, with whether any requirement judges the level asked.
- The judge, and each requirement's factory, take `sessions` only late: `sessions` collects the judge as it is built.

## Depends on
- `kernel`, `session` (the context, the levels, the seam).

## Vocabulary
- entry requirement: a rule a module contributes that a session must meet to be entered at a level.
