# libraries

Internal module of `interop-clients`: the client libraries the harness runs.

## Responsibilities
- Names each library, the flows it runs first-class, how its adapter is built and how it is started.

## Offers
- `libraries`, `libraryNamed` (a name not known is refused, naming those that are), and the flows by name.

## Invariants
- Each adapter takes the front's certificate from its instruction and trusts it alone, no public root either: openid-client's fetches through `undici` with that one CA, Nimbus's through a trust store holding it.
- Nimbus's adapter is a jar Maven builds, run by `JAVA_HOME`'s `java` or the one on the path.
- Authlib's adapter runs in a virtual environment kept with the package's caches (`node_modules/.cache`), made by the Python `.python-version` names (`INTEROP_PYTHON`, else `python3`), every package installed by the hash `requirements.txt` pins (`--require-hashes`); it sets Authlib's revocation and introspection authentication to the client's method, which Authlib otherwise makes Basic.
- Go's adapter is a binary `go build` makes from `adapters/go`, its modules and toolchain pinned by `go.mod` and every module's hash by `go.sum`; go-oidc checks no ID token's nonce, so the adapter does, as an app using it must.
- Spring's adapter is a jar Maven builds as Nimbus's is, its jars pinned alike; it runs headless only the grants its authorized-client providers make (jwt-bearer, token exchange), on a RestClient trusting the front's certificate alone, the token endpoint read from the provider's metadata, as Spring's own discovery takes no trust store; it signs the jwt-bearer assertion by Nimbus JOSE, as Spring takes one and makes none.
- Nimbus's build copies its runtime jars and checks them against `jars.sha256` before it compiles or shades anything from them; its plugins are pinned by version in its `pom.xml`.
- Each adapter refuses, right after discovery, an endpoint or key set the discovery names over anything but https, before any request is sent there; Nimbus's refuses any request not to https as well.
