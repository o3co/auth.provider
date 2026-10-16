# page

Internal module of `rp-logout`: the front-channel page.

## Responsibilities
- Builds the page that loads each client's front-channel URL in a hidden frame, then moves the browser on.

## Not here
- Which clients are framed and when the page is sent (`ending`).

## Offers
- `frontChannelPage` (frames, issuer, session, where to go next → the page and what it loads, for `http`'s `loads`, and how many frames were left out / none when no frame can load).

## Depends on
- `http` (the type of what a page loads)
