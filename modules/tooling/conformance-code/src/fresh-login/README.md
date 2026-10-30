# fresh-login

Internal module of `conformance-code`: the scenes of a password login meeting a client's demand for a fresh login.

## Responsibilities
- Checks that `prompt=login` and `max_age=0` send the browser to log in, are met by a login made after the demand, and refuse with `login_required` a return without one.
- Checks that a return which dropped its demand but kept its re-authentication is refused with `login_required`.
- Checks that `max_age` counts from when a second factor lets a password login in, however long it held it after the password.
- Declares that the legacy build counts a login in the same second as within `max_age=0` (`max-age-zero-asks-a-new-login`), keeps no record of the demand (`return-keeps-its-demand`), and counts `max_age` from the password, not from the second factor (`max-age-from-the-second-factor`).

## Depends on
- The package's scene builder and browser; `conformance` (the target); `conformance-oauth` (clients); `conformance-second-factor` (a target with a second factor, its browser and a held login let in by a recovery code)
