# freshness

Internal module of `conformance-federation`: the scenes of a federation login meeting a client's demand for a fresh login.

## Responsibilities
- Checks that a federation login meets a client's `prompt=login` only when the upstream says the user logged in after the demand, and a max age only when the upstream says when at all.
- Checks that an upstream whose clock is a little behind, within its allowance, still meets `prompt=login` in one trip while a login past the allowance does not, and that a login still of unknown time after the trip a max age asked for gets the client `login_required`.
- Checks that the login page is told the `prompt=login` and `max_age` a client asked, and that, handed on to the start, they reach the upstream and a code follows.
- Checks that a request back from a login the upstream says is older than the demand is refused with `login_required`, not sent to log in again.
- Checks that the ID token after a federation login says when the user logged in only as the upstream says it, and nothing where the upstream says nothing.
- Declares that the legacy build cannot be asked this way: it returns from a federation login only to a listed target, never to an authorization request (`federation-returns-to-authorization`); and that its ID token says the time of its own callback (`federation-auth-time-from-upstream`).

## Depends on
- The package's scene builder, browser and fake upstream; the code flow's authorization endpoint
