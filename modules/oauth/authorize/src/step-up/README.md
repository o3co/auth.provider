# step-up

Internal module of `authorize`: the acr a request asks for, and raising a session's authentication to meet it.

## Responsibilities
- Judges `acr_values` and `claims`, decides the acr the code carries, and sends a session that falls short to the step-up page once.

## Not here
- Parsing `claims` (`claims-request`). The acr table and which amr meets an acr (`acr`). Raising the session (the step-up page and `session`). Keeping the round trip's record (`reauth`).

## Offers
- `stepUpOver` (the build context, `reauth`'s records) → `stepUpWith` (`acr`'s table, the package's `step-up-page`, `reauth`'s records) → asked (single values, parameters, `claims-request`'s reading → the known acr asked and whether a known authentication time is needed / a refusal), met (acr asked, the session's amr and authentication time, `prompt=none`, the taken record, the request → the met acr / a refusal / the step-up page).

## Invariants
- `acr`'s table picks the known acr in the order asked, and the first the session's amr meets. Without `acr_values` or an `acr` in `claims` nothing is asked.
- The `acr` that `claims-request` read from the `id_token` and `userinfo` members of `claims` (OpenID Connect Core §5.5.1.1) is judged; its shape is `claims-request`'s to refuse. Each value is one acr as written, known only where the table holds it whole (a value holding a blank names none). Each request is kept apart.
- An acr asked as essential, with values: the acr carried meets every essential request, one of the values all of them name, in the first's order; another request's voluntary values never stand in.
  - None known is `unmet_authentication_requirements`; none met is `interaction_required` under `prompt=none`, and `unmet_authentication_requirements` without a page or back from it unraised.
- Asked by `acr_values`, or in `claims` without `essential`, an acr is voluntary (Core §3.1.2.1); the claims parameter's values stand in for `acr_values`.
  - None known, or none met where the step-up page cannot or did not raise the session (none set, `prompt=none`, or back from it), goes on with the session's current acr (`acr`'s: the first in its table the session meets, Core §5.5.1.1), none where it meets none.
- An `auth_time` asked as essential under `id_token` needs a known authentication time; asked otherwise, it needs nothing.
- The page gets `acr_values` and a `redirect_to` back to the endpoint carrying a re-authentication record made for the trip; a taken record marked as the trip stops a second one.
- The trip's record takes the time of the record already taken, so a confirmed fresh login is kept across the trip (a raise does not change the authentication time).

## Depends on
- `acr` (known acr, met acr); `kernel` (the build context); `reauth`; `claims-request` (the acr `claims` asks)
