# login

Internal module of `federation`: the login a round trip ends in when no continuation is chosen.

## Responsibilities
- Finds the local user an upstream login names, maps its amr and profile, and hands the login to `login-gates`.

## Not here
- The round trip, its exchange and freshness (`round-trip`). Handing over the upstream tokens (`upstream-handoff`). Opening the session (`login-gates`, through `session`).

## Offers
- `loginWith` (`login-gates`' logins, `users`, `audit`, `upstream-handoff`'s handoff, the landing, the held page, the held login's lifetime) → the round trip's login; `loginIn` builds it from the build context. `loginCaller`: its name as `login-gates`' caller.

## Invariants
- The local user is found by the IdP's name and the upstream subject only; none is `401 unknown_user`. A login a gate refuses is answered alike, `401 unknown_user`, and recorded failed with the reason `refused`; one `session` answers revoked, with the reason `revoked`. The login states the round trip's start as `provenSince`. The amr is `fed` plus the mapped upstream values, once each.
- The session gets the upstream profile's email (verified only where the type says so), name and picture under `login-attributes`' source name for the IdP, nothing else of it.
- Success is a 303 to the round trip's return target or the landing, so the browser follows a posted answer by GET (RFC 9700 §4.12). A held login carries that same return in its `done`, and is a 303 to `held-page`, with no query, and the cookies; without one, a 403 with the gate's answer and cookies.
- `loginIn` refuses boot for a `held-page` off the public origin. `heldPageRefused` (the settings) → the production check's refusal of a `held-page` on a loopback host, which the package declares.

## Depends on
- `login-gates` (logins), `users` (the lookup), `login-attributes` (the source name), `upstream-handoff`, `audit`, `http`, `kernel`, `upstreams` (the upstream login); `round-trip` (what a continuation takes, the recorder, the redirect); `federation`'s section
