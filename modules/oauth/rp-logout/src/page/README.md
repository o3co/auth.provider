# page

Internal module of `rp-logout`: the front-channel page.

## Responsibilities
- Builds the page a logout ends on: it says the user is logged out, loads each client's front-channel URL in a hidden frame, then moves the browser on.

## Not here
- Which clients are framed and when the page is sent (`ending`).

## Offers
- `frontChannelPage` (frames, issuer, session, where to go next → the page and what it loads, for `http`'s `loads`, and how many frames were left out / none when no frame can load).
- `loggedOutPage` (where to go next, and whether to say the person was not signed in → the page with no frame and what it loads): moves on at once by the same one script, or stays with none.
- `returnUrl` (a client's return and `state` → the URL the browser goes to, `state` added to its query / none without a return).

## Invariants
- Each frame is sandboxed, allowing only scripts and its own origin, so the client's page can clear its own cookies and nothing more: no top navigation, forms, popups or downloads.
- Each frame's URL gets `iss`, and `sid` when its client asked for the session (OpenID Connect Front-Channel Logout 1.0 §2).
- A frame whose origin a Content-Security-Policy host source cannot name is left out, and counted for `ending` to log.
- It declares it loads only the frames' origins and its one script.
- Without a place to go next, the page has no script and stays.

## Depends on
- `http` (the type of what a page loads)
