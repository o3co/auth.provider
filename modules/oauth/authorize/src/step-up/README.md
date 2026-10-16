# step-up

Internal module of `authorize`: the acr a request asks for, and raising a session's authentication to meet it.

## Responsibilities
- Judges `acr_values` and `claims`, decides the acr the code carries, and sends a session that falls short to the step-up page once.

## Not here
- The acr table and which amr meets an acr (`acr`). Raising the session (the step-up page and `session`). Keeping the round trip's record (`reauth`).

## Offers
- `stepUpOver` (the build context, `reauth`'s records) → `stepUpWith` (`acr`'s table, the package's `step-up-page`, `reauth`'s records) → asked (single values, parameters → the known acr asked and whether a known authentication time is needed / a refusal), met (acr asked, the session's amr and authentication time, `prompt=none`, the taken record, the request → the met acr / a refusal / the step-up page).

## Invariants
- `acr`'s table picks the known acr in the order asked, and the first the session's amr meets. Without `acr_values` nothing is asked.
- `claims` is parsed as JSON, and only its `id_token` and `userinfo` members are looked at for `acr`.
- An `auth_time` asked as essential under `id_token` needs a known authentication time; asked otherwise, it needs nothing.
- The page gets `acr_values` and a `redirect_to` back to the endpoint carrying a re-authentication record made for the trip; a taken record marked as the trip stops a second one.
- The trip's record takes the time of the record already taken, so a confirmed fresh login is kept across the trip (a raise does not change the authentication time).

## Depends on
- `acr` (known acr, met acr); `kernel` (the build context); `reauth`
