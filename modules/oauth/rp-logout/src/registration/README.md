# registration

Internal module of `rp-logout`: the client metadata section a client registers for logouts.

## Responsibilities
- Judges the shape of a client's returns after a logout and its front-channel and back-channel URLs.

## Not here
- When they are used (`ending`, `notices`). The rule for a URI a client may be sent back to (`redirect-uris`).

## Offers
- `registration`: section `rp-logout` with `post-logout-redirect-uris` (default none), `frontchannel-logout-uri`, `frontchannel-logout-session-required` (default true), `backchannel-logout-uri`, `backchannel-logout-session-required` (default true).

## Depends on
- `redirect-uris` (the rule for returns); `clients` (the section's type)
