# registration

Internal module of `rp-logout`: the client metadata section a client registers for logouts.

## Responsibilities
- Judges the shape of a client's returns after a logout and its front-channel and back-channel URLs.

## Not here
- When they are used (`ending`, `notices`). The rule for a URI a client may be sent back to (`redirect-uris`).

## Offers
- `registration`, and `registrationIn` with its boot check: section `rp-logout` with `post-logout-redirect-uris` (default none), `frontchannel-logout-uri`, `frontchannel-logout-session-required` (default true), `backchannel-logout-uri`, `backchannel-logout-session-required` (default true).
- `returnsTo` (a client, as its record is now, and a URI → whether it registers that return exactly; none for no client).

## Invariants
- A return is one `redirect-uris` lets a client register. A front-channel or back-channel URL is http or https, without userinfo, a fragment, spaces or controls; a front-channel one has no `iss` or `sid` in its query, whatever its case, `-` or `_`, and its origin is one of the client's redirect URIs' (`redirect-uris`' `redirectsAt`): checked at boot for a registered client, and before framing for any other, whose frame is left out, logged.
- `registrationIn` (the build context) → the section with a boot check: a registered client's `backchannel-logout-uri` that `outbound`'s policy refuses refuses boot, naming the key, never the URL.

## Depends on
- `redirect-uris` (the rule for returns); `clients` (the section's type); `outbound-policy` (the boot check); `kernel` (the build context)
