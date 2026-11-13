# image-scan

Internal module of `distribution`: the known vulnerabilities in the image of an app the release makes, as an operator builds it on the day, a fixable critical or high one, or a Node behind a security release, failing the scan.

## Responsibilities
- Builds the image of `full-app`'s app as its guide says; runs Trivy on it for the critical and high vulnerabilities that have a fix, in its OS and Node packages; holds its Node to Node's security releases; and writes the verdict.

## Not here
- Making the app: `full-app`. Building the image: `release-check`'s `images`, its `deps` stage the install from the tarballs. Packing the tarballs: `release`, through `pack-published.sh`.
- Knowing what is vulnerable: Trivy and its database, the image pinned by digest in `scan.json`, and Node's release index. Reading Trivy's report: `release-scan`'s `readScan`.
- When it runs: the `image-scan` workflow, daily on main and on a manual run of a branch. It runs the scanner of the commit it scans.

## Offers
- `pnpm image:scan <tarballs> <dir>` (Docker running): writes into `dir` `README.md`, the verdict, and `image.trivy.json`, Trivy's report as it wrote it. Exits 0 only where the scan passed.
- `trivyArguments` → Trivy's `docker run`; `nodeChecked` (the image's Node, Node's release index) → current, behind with the newest security release and the minor to move to, or not checked; `verdictOf` (Trivy's run, the Node check) → whether it passed, and the verdict in Markdown.

## Invariants
- Passes only where Trivy ended clean, its report read OS and Node packages and holds no finding, and no security release of the image's Node major is newer than it. A scan that could not be made or read is told as not scanned, and a Node index that could not be fetched, read or that does not list the image's Node as not checked; each fails, never as clean.
- The image is built fresh (`--pull --no-cache-filter=runtime`), and removed however the scan ends.
- Trivy runs in its pinned image on the image saved to a file, mounted read-only, and the image's Node with no network, neither with a token or setting of the run passed in.
- Its workflow is held, by a test reading it, to run on the schedule and a manual run alone, on the commit it runs on, with `contents: read` alone and no secret or token, within a time, the verdict in the job's summary and Trivy's report kept however it ended.

## Depends on
- `full-app` (the app), `release-check` (`images`, `dockerMissing`), `release` (`packedOf`), `release-scan` (`readScan`, `reasonOf`, `cell`, `rank`), `release-sbom` (`endOf`); `docker-client`; Docker and pnpm, run; `nodejs.org`, fetched.
