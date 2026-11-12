# image-scan

Internal module of `distribution`: the known vulnerabilities in the image of an app the release makes, as an operator builds it on the day, a fixable critical or high one failing the scan.

## Responsibilities
- Makes, with the packed `create-auth-provider`, the full template with every feature that opts in; builds its image as its guide says; runs Trivy on it for the critical and high vulnerabilities that have a fix, in its OS and Node packages; and writes the verdict.

## Not here
- Building the image: `release-check`'s `images`, its `deps` stage the install from the tarballs. Packing the tarballs: `release`, through `pack-published.sh`.
- Knowing what is vulnerable: Trivy and its database, the image pinned by digest in `scan.json`. Reading Trivy's report: `release-scan`'s `readScan`.
- When it runs, and on which commit: CI's `image-scan` job, daily on main and on a manual run's `ref`.

## Offers
- `pnpm image:scan <tarballs> <dir>` (Docker running): writes into `dir` `README.md`, the verdict, and `image.trivy.json`, Trivy's report as it wrote it. Exits 0 only where the scan passed.
- `trivyArguments` → Trivy's `docker run`; `verdictOf` (Trivy's run as it ended) → whether it passed, and the verdict in Markdown.

## Invariants
- Passes only where Trivy ended clean and its report read packages and holds no finding. A finding fails it, and so does a scan that could not be made or read, told as not scanned with the reason; never as clean.
- The image is built with `--pull --no-cache-filter=runtime`, and removed however the scan ends.
- Trivy runs in its pinned image on the image saved to a file, mounted read-only, with no token or setting of the run passed in.
- CI's workflow is held, by a test reading it, to run the scan on the schedule and a manual run alone, on main or the run's `ref`, reading alone, within a time, the verdict in the job's summary however it ended, needed by no job.

## Depends on
- `release-check` (`images`, `overridesFile`, `dockerMissing`), `release` (`packedOf`), `release-scan` (`readScan`), `release-sbom` (`endOf`); `combinations` (the features that opt in); `docker-client`; pnpm and Docker, run.
