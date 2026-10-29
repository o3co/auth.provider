# federation

## Responsibilities
- Logs a browser in through an upstream IdP and hands the login to `login-gates`.
- Hands a round trip whose start chose a continuation to it (`upstreams`' continuations) in place of the login.

## Not here
- What an IdP type, an upstream and a receiver are (`upstreams`).
- The link records and their conflicts (`users`).
- Where a login may return to (`login-gates`).
- Opening the session (`session`, through `login-gates`).

## Offers
- A `login-gates` return path: each IdP's start.
- Composition definition: `GET /session/oauth/federation/<idp>` (start: `redirect_to`, `prompt` (only `login` is passed on), `max_age`, `link` (`1` or `true` chooses the continuation named `link`; any other value is a login)) and `…/<idp>/callback` (`code`, `state`, `iss`, `error`; by POST for an IdP that answers in a posted form, else GET; the other method is 405); starts and callbacks are limited per source
- Provides `upstreams`, as its default adapter.
- Declares to `users` (`upstreamNames`) each IdP's name with the issuer its upstream says.
- The operator section (its keys in the settings list).
- Test configuration builders and an IdP type for tests (`./testing`)
- Audit events for a callback that took its round trip, with `idp` and the source `request-source` determined: `federation.login.succeeded`, or `federation.login.held` when a gate held it, with the local subject; `federation.login.failed` with `reason` (`upstream_refused`, `exchange_failed`, `login_required`, `unknown_user`)
- No audit event comes before the take or records an unavailable answer, and none holds the upstream subject, tokens or text.
- Answer codes: `not_found` (404), `repeated_parameter`, `invalid_redirect`, `invalid_request`, `invalid_state`, `upstream_refused`, `continuation_unavailable` (400), `unknown_user`, `login_required` (401), a gate's answer (403), a continuation's own answers, `method_not_allowed` (405, with `allow`), `exchange_failed` (502), `temporarily_unavailable` (503)
- Success is a 303 to the return target or the landing.
- A held login carries that same return to its gates.
- A held login is a 303 to `held-page`, with no query, and the cookies; without one, a 403 with the gate's answer and cookies.

## Invariants
- A start begins an `upstream-round-trip` round trip named `federation.<idp>`, kept for `transaction-lifetime`, cross-site for an IdP that answers in a posted form, taken by its callback before the code is exchanged; one not from this deployment's own page (`csrf`'s origin evidence) goes on with the browser's live one instead: its first request whole, its return target and `prompt` too, no cookie set.
- So the first start wins: where no round trip lives, another site's start sets the return target, `prompt` and `max_age` a later one goes on with, never its state, nonce or verifier, nor one a continuation refuses.
- A start choosing a continuation not composed is `continuation_unavailable`, warned `federation.continuation_missing` with the IdP and the name, and starts nothing; so is a callback whose round trip names one no longer composed.
- A callback that takes nothing is `invalid_state`; one whose round trip carries what federation does not read is `invalid_state` too, its round trip spent.
- From the take on, every answer clears the round trip's cookie, unavailable included.
- The start refuses a return target `login-gates` does not allow (`invalid_redirect`).
- The start refuses a `max_age` that is not 1 to 9 digits (`invalid_request`).
- A repeated parameter is refused after the path and method.
- An `error` or no code is `upstream_refused`, with no exchange.
- A failed exchange is logged with the IdP and its kind only.
- An unavailable upstream is 503.
- The start is declared as the user's own navigation, and the callback as the IdP's redirect or posted form, each in place of a policy keeping other sites out; both change state.
- A login reports when the user logged in upstream, on our clock (one within the allowance before the start's second is the start, to the millisecond), or unknown; the session and ID token's `auth_time` keep it; later requests measure from it, no allowance.
- After `prompt=login` or a max age, a login counts only when the upstream says when the user logged in.
- Fresh enough: after `prompt=login`, the upstream's login time plus the IdP's `fresh-login-allowance` (its type's clock allowance by default) is not before the start's second (so an upstream that does not authenticate again passes a login up to that allowance before the start, or in the start's own second); with a max age, it is within the max age of now, to the millisecond.
- The fresh login allowance narrows only how far back a login time reaches: a time ahead of ours that the type's clock allowance passes, or any time the upstream says, is taken as the upstream says it.
- The local user is found only by the IdP's name and the upstream subject.
- An unknown identity is refused, and nothing is created.
- The login proves `fed` plus only the upstream amr values the operator maps (declared as provable).
- An upstream's text and tokens never reach the browser or the logs.
- Of what an upstream says of the user, only its profile's email, name and picture reach the session, as strings, under the IdP's source name (`loginSource.upstream`).
- Its email is verified only where the type says the upstream verified it in the type's own form; otherwise it is unverified.
- Groups and other claims never reach the session.
- A login's upstream tokens go to their receivers through `upstream-handoff`, which keeps a held login's for `transaction-lifetime`, its resume's deadline; if they cannot be kept, the callback is unavailable.
- An IdP's redirect URI is the public origin plus its callback path.
- Boot is refused for an unknown type, settings the type refuses, an upstream that does not match its settings (under the key and with the reason the type gives, where it gives them) or cannot be reached, told apart, no public origin, or a `held-page` off it (the page reads the held login with this deployment's cookies), one reason per issue, all at once.
- An IdP that answers in a posted form refuses boot where cookies cannot be secure, as its round trip's cookie is cross-site.

## Depends on
- `kernel`, `upstreams`, `upstream-round-trip`, `upstream-handoff`, `audit`, `csrf` (origin evidence), `http`, `request-source`, `url-setting`, `login-attributes`, `login-gates`, `users`, `rate-limit`
