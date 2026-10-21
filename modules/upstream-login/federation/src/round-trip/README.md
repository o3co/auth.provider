# round-trip

Internal module of `federation`: one round trip through an upstream IdP, a login's or a continuation's, from its start to its callback.

## Responsibilities
- Answers a start: checks what the browser asked, asks the continuation it chooses (the one named `link` when `link` is `1` or `true`, from `upstreams`' continuations; else the login; one not composed is `400 continuation_unavailable`, warned `federation.continuation_missing`), begins an `upstream-round-trip` round trip (or, from another site, goes on with the browser's live one), and sends the browser to the upstream.
- Answers a callback: takes the round trip once, has the upstream exchange its code, and hands the upstream login to the continuation the round trip names (else the login), with what it kept and where the browser lands, so neither ends in the other; one no longer composed is `continuation_unavailable` too.
- Decides whether an upstream login is fresh enough.
- Freshness is judged here on `kernel`'s clock, never by a type.
- Records each callback that took its round trip to `audit`.

## Not here
- The login itself: the local user, the amr, the profile and `login-gates` (`login`). Opening the IdPs at boot (`idps`). Handing over the upstream tokens (`upstream-handoff`). The route's declaration and its rate limit (the package's). What differs per IdP (the type). Keeping a round trip and taking it once (`upstream-round-trip`).

## Offers
- `roundTripIn` (the build context, the login; it collects the continuations itself) → the round trip's handler; `landingIn`: the landing, or the public origin's root; `federationIdps`: the opened IdPs' contract.
- `federated` (the opened IdPs, `upstream-round-trip`'s round trips, `login-gates`' return check, the login and the continuations by name, `kernel`'s clock and log, the landing, the round trip's lifetime) → a request under the federation path → its answer.
- `recorderOf` (`audit`, kind prefix): records a federation event in federation's words: `idp`, then `source`, `userAgent` and `reason` when known.
- `Continuation`: at the start, a refusal or what the round trip carries; after the take, exchange and freshness, the answer; a refusal in between, recorded its way.
- `Completing`, `Recorded`, `Flow`, `sent` and `secondOf`: what the continuations take, carry, record and answer with, and the whole second a time falls in. `Trip` (`trip.ts`): what a round trip carries for federation, read back from a take.
- `Idp`: what an opened IdP gives the round trip. `base` and `callbackPath` (IdP name → its callback's path). `proves`: what every federation login proves.

## Invariants
- Any other path is `not_found`. The start is GET only; the callback takes only its IdP's answer method; any other method is 405 with `allow`. A repeated parameter is refused next.
- The start refuses a return target `login-gates` does not allow, and a `max_age` that is not 1 to 9 digits. Only `prompt=login` is passed on.
- A round trip is named `federation.<idp>`, kept for `transaction-lifetime`, and cross-site only for an IdP that answers in a posted form.
- A callback that takes nothing is `invalid_state`. One whose round trip carries what `Trip` does not read is `invalid_state` too, its round trip spent.
- From the take on, every answer clears the round trip's cookie, unavailable included.
- An `error` or no code is `upstream_refused`, with no exchange. The exchange gets the take's verifier and nonce, the redirect URI and the callback's `iss`.
- A failed exchange is `exchange_failed`, logged with the IdP and its kind (`refused` or `failed`) only. An unavailable upstream is 503.
- With `prompt=login` or `max_age`, the upstream must say when the user logged in. That time, plus the type's clock allowance, is not before the start's whole second and is within the max age of now.
- Audit records come only after the take, with `idp` and the source when `request-source` determined it: the local subject on success or hold, the reason on failure. None records an unavailable answer.

## Data
- What a round trip carries for federation: the return target, `prompt` and max age, and the continuation it goes on to with what that kept. Read back by its own shape: another is none.

## Depends on
- `http` (the site for the landing, the request and answer, no-store, the JSON answer); `upstream-round-trip` (round trips); `request-source` (the source); `kernel` (the runtime, unavailable); `login-gates` (the return check); `audit`; `upstreams` (the upstream, its login, its refusal); `csrf` (origin evidence); `federation`'s section
