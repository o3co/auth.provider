# libraries

Internal module of `interop-clients`: the client libraries the harness runs.

## Responsibilities
- Names each library, the flows it runs first-class, how its adapter is built and how it is started.

## Offers
- `libraries`, `libraryNamed` (a name not known is refused, naming those that are), and the flows by name.

## Invariants
- Each adapter takes the front's certificate from its instruction and trusts it alone, no public root either: openid-client's fetches through `undici` with that one CA, Nimbus's through a trust store holding it.
- Nimbus's adapter is a jar Maven builds, run by `JAVA_HOME`'s `java` or the one on the path.
- Nimbus's build copies its runtime jars and checks them against `jars.sha256` before it compiles or shades anything from them; its plugins are pinned by version in its `pom.xml`.
