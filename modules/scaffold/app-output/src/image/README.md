# image

Internal module of `app-output`: the generated app's image, its Dockerfile and what its build context leaves out.

## Responsibilities
- Writes the Dockerfile: the stages that install and run the app, which Node, corepack and Alpine they take, and how the app is started and checked.
- Holds what the image's build context leaves out (`.dockerignore`).

## Not here
- Whether the app listens or answers its health check, its port, and where its files lie: the caller's, given to `dockerfile`.
- How packages outside the release are installed in the install stage: `outside`'s, given as its `image`.
- What git leaves out, and the guide's words on building and running the image: `app-output`'s own.

## Offers
- `dockerfile(http, beside, at)` → the Dockerfile's text; `dockerIgnored`, the build context's ignore list.

## Invariants
- The image's build context leaves out git, every env file, the local layer, keys and the host's install (`node_modules/`).
- The image follows one Node 24 minor, patch and digest unpinned, so a build takes its patches; a minor is fixed only until a newer one is out, so the operator moves `FROM` to the latest 24.x minor at each Node security release.
- The image pins corepack by version and installs the locked production dependencies in a stage of their own; the stage the app runs in starts again from Node's image and takes out the npm, npx, corepack and yarn Node's image bundles, so no package manager but apk is in it, and runs node under `tini` as a user other than root.
- The stage the app runs in takes Alpine's current packages; the guide builds it uncached.

## Depends on
- `fragments`, for the environment's names of `http.host` and `http.port`; `outside`, for the type of what it gives the install stage.
