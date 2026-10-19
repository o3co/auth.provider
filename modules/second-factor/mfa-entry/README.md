# mfa-entry

## Responsibilities
- Judges a session against second factors: the entry requirement `mfa` sets for using a session and for changing credentials, and whether a session proved a second factor recently.

## Not here
- The subject's factors, and whether one counts or the witness agrees: `mfa`, asked through its decisions.
- Proving a factor, raising a session or stepping up: `mfa-flows`. Sessions and their recent window: `session`.

## Offers
- `secondFactors.provenRecently(context)`: whether the session proved a second factor within `session`'s recent window; a recent sign-in never stands for one.
- Contribution to `session`'s entry requirements, named `mfa` as answers and records outside name it, judging `use` and `credentials`.

## Invariants
- Under `mfa.mode = required`, using a session needs `mfa` among its amr, else `mfa_required`; boot is refused unless a composed kind both counts and adds `mfa`, since no session could then be used.
- Changing credentials needs `mfa` added recently (as `session`'s `recent` tells), or a recent login while no counting factor is held; else `step_up_required`. A login at a time the upstream did not give is never recent, nor is the `mfa` it says it proved.
- Every credentials entry first asks `mfa` whether a counting factor is held, judged against the witness: a factor store or a witness that cannot answer, or a subject the witness marks while holding none, makes the entry unavailable, however recent its second factor.

## Depends on
- `kernel`, `session`, `mfa` (its decisions), `mfa-extensions` (the kinds, and the `mfa` amr)
