# reauth

Internal module of `authorize`: re-authentication records, asked for one request and taken once.

## Responsibilities
- Makes and takes re-authentication records, and decides whether a login is fresh enough for `prompt=login`, `max_age` and an essential `auth_time`.

## Not here
- When a record is asked for (`flow` for a login, `step-up` for the round trip). Where records are kept (the store interface, the package's).

## Offers
- `reauthsOver` (the build context) → `reauthsWith` (the store, the clock, randomness) → make (request, time, whether it is the step-up round trip → the record's name), take (name, request → the record / none), fresh (`prompt=login` asked, `max_age` in ms, whether a known authentication time is needed, the session's authentication time or that it is unknown, the taken record → yes / no).

## Invariants
- A fresh login that `prompt=login` or `max_age` demands counts only through a re-authentication record, never values in the URL: made for the whole request when the browser is sent to log in, taken once by that request, gone after 10 minutes. A session whose authentication time `session` answers as unknown meets neither, nor an essential `auth_time`, so a login is asked again.
- The request's hash covers its parameters (each one's first value) except the record's own name, independent of their order and of the order of prompt words.
- Taking rewrites the record as taken; it counts only when that rewrite found it untaken and made for the same request. A name that is not 43 base64url characters is not looked up.
- A new record's name is made from 32 random bytes. If the name is already held, unavailable.
- A login whose authentication time `session` answers as unknown is never fresh: it meets no record, no `max_age` and no need for a known time.
- A login meets a record when its authentication time falls in the record's second or later, compared in whole seconds.
- `max_age` is compared on `kernel`'s clock.
- Records are written in format 1 and checked on every read; one of another format or shape reads as none.

## Data
- Re-authentication record, per unguessable name, through its store interface: the time a login counts from, a hash of the request, whether it is the step-up round trip, and whether it was taken. Checked on every read; eviction only means logging in again.

## Depends on
- `kernel` (the build context, the clock, randomness, unavailable), `session` (the authentication context); the package's store interface
