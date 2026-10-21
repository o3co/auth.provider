# login

Internal module of `federation`: the login a round trip ends in when it is not a link.

## Responsibilities
- Finds the local user an upstream login names, maps its amr and profile, and hands the login to `login-gates`.

## Not here
- The round trip, its exchange and freshness (`round-trip`). Handing over the upstream tokens (`upstream-handoff`). Opening the session (`login-gates`, through `session`).

## Offers
- `loginWith` (`login-gates`' logins, `users`, `audit`, `upstream-handoff`'s handoff, the landing, the held page, the held login's lifetime) → the round trip's login; `loginIn` builds it from the build context. `loginCaller`: its name as `login-gates`' caller.

## Invariants
- The local user is found by the IdP's name and the upstream subject only; none is `401 unknown_user`. The amr is `fed` plus the mapped upstream values, once each.
- The session gets the upstream profile's email (verified only where the type says so), name and picture under `login-attributes`' source name for the IdP, nothing else of it.
- Success is a 302 to the round trip's return target or the landing. A held login carries that same return in its `done`, and is a 303 to `held-page`, with no query, and the cookies; without one, a 403 with the gate's answer and cookies.
- `loginIn` refuses boot for a `held-page` off the public origin.

## Depends on
- `login-gates` (logins), `users` (the lookup), `login-attributes` (the source name), `upstream-handoff`, `audit`, `http`, `kernel`, `upstreams` (the upstream login); `round-trip` (what a continuation takes, the recorder, the redirect); `federation`'s section
