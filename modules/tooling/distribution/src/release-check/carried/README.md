# carried

Internal module of `release-check`: which package managers an app's image holds.

## Responsibilities
- Looks in an app's image for each package manager it holds, npm aside: corepack, pnpm or yarn on its PATH, or the corepack and the yarn Node's image bundles where it keeps them.

## Not here
- Building the image, and telling what it holds as a problem: `release-check`. The container it looks in: `containers`.

## Offers
- `carried` (a container, the image) → each path the image holds a package manager at; none where it holds none.

## Invariants
- The image is looked in past its entrypoint, with no network, so what it finds is the image's own and nothing it fetched.

## Depends on
- `containers`, to run the image.
