# scene

Internal module of `interop-oidf`: the app the OP plans meet.

## Offers
- `suiteScene`: the code flow with discovery, userinfo and refresh at the front's origin; an RS256 key of the run's own; first-party confidential clients whose redirect URI is the suite's callback under the plan's alias; one user with a name, an email and a picture. With `logout`, the clients register the suite's post-logout redirect and the plan's front- or back-channel logout URI where it names a channel, `logout.allowed` names the suite, and a proxy given is the app's `outbound.proxy`.

## Invariants
- The scene's own area raises the per-source limits of authorize, the token endpoint, introspection and revocation, and RP-initiated logout (`rp-logout`), each to 1000, and login: a whole plan comes from one source.
- The user's password hash is scrypt at the least work, as the identity area's is.
- The app declares one acr, named by a URI, that a password login meets: discovery offers it, so the suite asks for an acr the provider can meet. With none offered, the suite asks for `1 2`, which no provider knows.
