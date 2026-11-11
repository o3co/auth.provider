# release-scan

Internal module of `distribution`: a report of the known vulnerabilities in what the release ships, read from its lists.

## Responsibilities
- After the release's lists are made, runs Trivy on the reference image's list and the operator's app's, and writes what it found: per list, the count of each severity, and the critical and high findings that have a fix.

## Not here
- Making the lists: `release-sbom`. Knowing what is vulnerable: Trivy and its database, the image pinned by digest in `scan.json`.
- Deciding what a finding means for a release: no finding stops or delays one.

## Offers
- `pnpm release:scan <lists> <dir>` (Docker running): writes into `dir` `image.trivy.json` and `app.trivy.json`, Trivy's reports as it wrote them, and a `README.md` table. Exits 0 whatever Trivy found or failed at.
- `readScan` (Trivy's output, or why there is none) → the findings, or not scanned; `reportOf` → the table.

## Invariants
- A list Trivy could not scan, or whose output is not Trivy's report, is told in the table as not scanned with the reason, its last line; never as a list with no findings.
- Trivy runs in its pinned image with the lists mounted read-only and no token or setting of the run passed in, its database from the first of `scan.json`'s repositories that answers, kept for the second list in a volume of the run's own and removed after.
- A finding is counted once by its id, package and installed version.
- The release workflow is held, by a test reading it, to run it in a job of its own after the lists, taken by their id, that reads alone, holds no token to publish, runs within a time, cannot fail the run, and that no job needs.

## Depends on
- `release-sbom` (the lists it reads, and `endOf`, a docker command's end as its status); `docker-client` (the docker commands); Docker, run.
