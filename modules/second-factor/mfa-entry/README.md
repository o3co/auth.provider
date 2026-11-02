# mfa-entry

## Responsibilities
- Judges a session against second factors: the entry requirement `mfa` sets for using a session and for changing credentials, and whether a session proved a second factor recently.

## Not here
- The subject's factors, and whether one counts or the witness agrees: `mfa`, asked through `mfa-reading`'s `factorReading`.
- Proving a factor, raising a session or stepping up: `mfa-flows`. Sessions and their recent window: `session`.

## Offers
- `secondFactors.provenRecently(context)`: whether the session proved a second factor within `session`'s recent window; a recent sign-in never stands for one.
- Contribution to `session-requirements`' entry requirements, named `mfa` as answers and records outside name it, judging `use` and `credentials`. Contribution to `mfa`'s `enforcers`, without which `mfa` refuses to boot.

## Invariants
- Under `mfa.mode = required`, using a session needs `mfa` among its amr, else `mfa_required`; boot is refused unless a composed kind both counts and adds `mfa`, since no session could then be used.
- Changing credentials needs `mfa` added recently (as `session`'s `recent` tells), or a recent login while no counting factor is held; else `step_up_required`. A login at a time the upstream did not give is never recent, nor is the `mfa` it says it proved.
- Every credentials entry first asks `mfa` whether a counting factor is held: a factor store that cannot answer makes the entry unavailable, however recent its second factor. The witness is asked only where no counting factor is held, and there one that cannot answer, or that marks the subject, makes it unavailable too.
- Comes once `mfa` and `session` are both composed, through `combinations`; an app composed by hand must compose it, or sessions are not held to second factors at all.

## Depends on
- `kernel`, `session`, `session-requirements` (the entry requirements), `mfa` (composed with it, and its `enforcers`), `mfa-reading` (the reading of the factors), `mfa-extensions` (the kinds, and the `mfa` amr)
