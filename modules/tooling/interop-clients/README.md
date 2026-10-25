# interop-clients

## Responsibilities
- Runs the provider against independent client libraries, each through an adapter of its own, and checks what each library gave back: a run per library.
- Starts the provider the libraries meet, behind an https front whose origin is the issuer: the full template with every feature that opts in, and the services' (`a2a`) for the grants that need no user, such as jwt-bearer, which the full template's ledger of users cannot hold.
- Plays the browser in each flow: the driver logs in and follows the authorization URL a library built, only where it is the provider's authorization endpoint at the issuer, and hands the library the redirect.
- Holds the differences accepted between a library and the provider, each written narrowly and held to the checklist's exception rules.

## Not here
- What a library does on its own: its adapter calls the library's first-class interface and reports what the library said.
- Starting the app (`conformance`'s drivers) and the https front (`conformance-front`).
- Whether an item is met: the flow tests name the items they check, and `spec-checklist` reads their results.

## Offers
- The script `library <name>`: builds the library's adapter, then runs the flow tests with it (`INTEROP_LIBRARY`, `SPEC_EVIDENCE_RUN`).
- The script `evidence-runs`: each library's run as the JSON runs `spec-checklist` reads (`@mod/interop-clients#<library>`, kind `library`, the library its matrix value).
- `known-differences.json`: each accepted difference, by library, flow and the check's title, with its class and reason.

## Invariants
- An adapter is one program per library, its library pinned in its own manifest (`package.json` for Node, `pom.xml` for Maven, `go.mod` for Go, its toolchain too, `requirements.txt` for Python) and installed from the library's registry; a jar is pinned by its SHA-256 too (`jars.sha256`), as npm's are by the lockfile's integrity, Go's modules by `go.sum`, and Python's packages by `requirements.txt`'s hashes.
- An adapter trusts the front's certificate, as its instruction gives it, and nothing else, no public root either; no library is told to take plain http.
- The front tells the app the libraries send from `198.51.100.30`: on loopback the sender would be the app's trusted proxy, and its source undetermined.
- A check that fails is skipped as excused only where a known difference names its library, flow and title; a difference no check met fails the run.
- A flow test runs only for a library that runs the flow first-class; the others skip it.
- Where the app does not start, the front is closed and the run's files removed before the failure is told.

## Depends on
- `conformance`, `conformance-code`, `conformance-oauth`, `conformance-front`, `spec-checklist`, `openid-client`, `undici`; a JDK and Maven for the Nimbus adapter, Go for the Go adapter, Python for the Authlib adapter.

## Vocabulary
- adapter: a library's small program that runs one flow per start, told by its first input line.
- flow: a protocol exchange the provider offers and a library runs first-class, such as `login` or `refresh`.
