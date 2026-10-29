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

## Depends on
- `http` (the type of what a page loads)
