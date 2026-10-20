# drivers

Internal module of `conformance`: the new system's driver, composed from a scene's parts or on a pattern's app.

## Responsibilities
- Generates the app a scene or a pattern asks for, and starts it with its audit sink, its Store and, where it sends mail, a fake relay.

## Offers
- The `new` target, registered on import: composed from the scene's parts, or on the pattern `CONFORMANCE_PATTERN` names.

## Invariants
- Does not rely on logs to tell that start-up is done.
- The driver picks the port and waits until it is reachable over HTTP.
- Composes `audit` with `audit-http` (through `outbound`) into every scene, sending each event to the `audit` sink, named in outbound's `allow` and as a plain-http loopback destination.
- A pattern's app boots on `trial`'s layer for the keys each scene leaves unset, but none in a section a set-up marks `whole`.
- A scene's `fallback` sections give way to the trial layer.
- A part's own configuration file (`layer`) boots as written, below the scene's sections and over the trial's layer. Lists replace each other across files: a list key in it hides the trial layer's list, and the scene's sections hide its own.
- Outbound's host lists join the trial's.
- The scene's registered clients join the trial's one clients list.
- A scene that sets the public origin sets the issuer there too.
- A pattern's app has its audit axis set to `audit-http`.
- A pattern's app has the modules its pattern's `conformanceAdd` names added.
- A pattern's app composing `mail-smtp` sends its mail to a fake relay at loopback, started and stopped with it, unless the scene sets that section.
- On a pattern's app, a scene whose modules the app lacks is skipped with that reason.
- On a pattern's app, a scene about a Store the app did not choose (it pauses the Store on a memory one, or refuses a volatile Store on Redis) is left out as an alternative, even with `full+opt-ins`.
- On a pattern's app, a scene about the absence of a module the app composes (a set-up's `without`) is left out with that reason, even with `full+opt-ins`.
- On a pattern's app, each scene left out or failed is a line in the file `CONFORMANCE_NOT_IN_PATTERN_FILE` names, when set, which `patterns` reads.

## Depends on
- The package's area contract and `launch`, the `audit` sink, the `patterns` names, and the fake relay; `create-app`, `trial`, `combinations`.
