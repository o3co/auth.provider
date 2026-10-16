# http-ops

## Responsibilities
- Answers the liveness and readiness routes, and times each request for `metrics`.

## Not here
- What each readiness probe checks (the module holding the connection); running them under a deadline (`kernel`).
- Serving the routes, and telling each request's end (`http`); publishing the counts (`metrics-prometheus`).

## Offers
- `GET /_healthcheck`: `200` `{"status":"ok"}`, checking no dependency; like `/readyz`, it uses no policy, takes no body (a body or a type is `415`, as anywhere) and answers `no-store`.
- `GET /readyz`: `200` `{"status":"ready"}` or `503` `{"status":"unready"}` as the kernel's readiness answers within `readiness-deadline-ms`, never naming what failed; requests share one run, and an unready answer is reused for 1 s from its start. The gauge `auth_dependency_up` gives each probe 1 or 0 from that run, by the name its module chose (no series without probes).
- The histogram `http_request_duration_seconds` counts each request once, answered or closed, by method (`other` outside the standard nine), the declared path of the route reached (`unmatched` when none) and the status written (`499` when the client closed first).
- Section `http-ops`: `readiness-deadline-ms`, its key in the settings list.
- Composition definition: comes by default with `http`.

## Invariants
- `/readyz` is ready only when every probe passed within the deadline; one failing, late or unanswered (the store's among them) makes it unready.
- No label holds a value a request brought (its path, query, headers or body) or a user's: methods outside the nine are `other`, routes are declared paths, statuses are numbers, and dependencies are the names their modules chose.

## Depends on
- `kernel`, `http`, and `metrics` by its contract only (never needed).
