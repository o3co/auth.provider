# helpers

Internal module of `distribution`'s `release-check`: the helpers scene, the resolver's helper processes in an app's image, run as a deployment constrains them.

## Responsibilities
- Boots the `simple-web` image limited, sees the resolver's two helpers run, and has the image's outbound, run once more in the container, resolve a name through them and reach the app by it; measures the processes the app takes and boots it refused under that limit; and ends the container by killing the app's process.

## Not here
- Booting and building the images (`release-check`'s `images`), and running each container (`containers`).

## Offers
- `helperScene` (what boots an image, the app, its image) → what the scene saw, or throws what failed.
- `lookupModules` and `lookupConfig` (the address to reach): the foundation's modules the image's outbound is run once more with, and their configuration beside the kernel's.

## Invariants
- The image's outbound is run once more with `tls-options` beside it, as an app composes it: outbound refuses to boot without the TLS floor it takes.
- The processes a container takes are read from its cgroup (`cgroup`): v2's count, or v1's under its pids controller, only where v2's file is not there; any other failure, Docker's included, is thrown.

## Depends on
- `containers`; the published foundation bundle's `kernel`, `outbound` and `tls-options`, inside the image. In tests, the workspace's `kernel`, `outbound` and `tls-options`: the outbound booted as the image boots it.
