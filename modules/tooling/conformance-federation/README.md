# conformance-federation

## Responsibilities
- Owns the conformance scenes of the federation area: logging a browser in through an upstream OpenID Connect IdP, Google, Apple, or GitHub's OAuth, the audit events of those logins, and a start while the store fails.
- Owns the scenes of a federation login meeting a client's `prompt=login` or max age only as the upstream says when the user logged in.
- Owns the scenes of handing a login's upstream tokens to receiving clients (only once a login a gate holds opens), refreshing them, and logging out of an upstream.
- Owns the scenes of an OpenID Connect IdP reading its upstream's UserInfo: on https alone, through a front and a CONNECT proxy, its subject held to the id_token's.
- Owns the scenes of a federation login a gate holds: going on at the held page, or answered with the gate's answer where none is set.
- Owns the scenes of federation grants, from a client's intent through the user's connection to the upstream token, its refresh and its end.
- Sets up the federation area's part (the IdPs, the landing, the held page, the return targets, federation grants' page, connections and lodging limit, and a link's step-up page) on each of the legacy and new targets; on the new, the grants' page goes to `federation-grants-connect`, composed with the grants, and the step-up page to `federation-link`.
- The legacy build turns federation grants on only when enabled.
- The legacy set-up enables federation grants.
- The legacy set-up keeps federation grants in Redis.
- The legacy set-up checks no upstream account's holder.
- Scripts a fake upstream IdP on the test side, on the base's fake HTTP server: it publishes its description and keys (and its end of session, where the scene says), answers its token endpoint as a real one would, hands over the tokens a scene sets, and answers refreshes as the scene scripts them.
- The same fake upstream IdP stands for Google at Google's paths, naming Google's issuer and telling the user's subject.
- Scripts a fake Apple that answers in a posted form, takes a fixed client secret or one the team's key signs, and can move its id_tokens to a new key.
- Scripts a fake GitHub that answers a refused code with 200 and an error, refuses an API request without a User-Agent, and tells the user's numeric id.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key, user, client and code-flow parts (their own areas).

## Offers
- Area `federation` and the shape of its part
- Scene builder (builds the key, identity, OAuth, code-flow and federation parts from the form written in a scene)
- The needs `grantsLoginPage`, `linkStepUpPage` and `readsUserinfo`, which the legacy target cannot meet

## Invariants
- The legacy set-up, the needs the legacy system cannot provide, and the differences it answers otherwise, live only in `src/legacy.ts`.
- GitHub's, Google's and Apple's scenes check the authorization endpoint by path alone.
- The scenes touch only the HTTP interface.
- Whether a browser is logged in is asked with a silent authorization request.
- The new target reaches the fake upstream only because the scene names its host in outbound's `allow` and the upstream as a plain-http loopback destination, or, where it reads UserInfo, through the CONNECT proxy the scene names to an https front before it.
- On a pattern's app taking users from a ledger (`users-http`), a scene linking an identity from the deployment's own page is left out: the ledger, looking users up by upstream identity, holds the links.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`, `conformance-identity`, `conformance-oauth`, `conformance-code`, `conformance-second-factor` (a second factor that holds a login, in the scenes only)
