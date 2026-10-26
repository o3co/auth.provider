# conformance

## Responsibilities
- Owns the conformance test base: the area contract, scene composition, the driver contract and selection, assembly of the new system, the pattern mode (every scene on one pattern's app), shared tools.
- Its internal modules for running a target: `drivers` runs the new system, on a scene's parts or a pattern's app; `audit` keeps the events a target sends; `patterns` runs every pattern's areas.
- Its internal modules for fault scenes: `relay` sits between an app and Redis to cause a fault at a known point and show that it happened; `store-wire` reads the Redis adapter's wire for the relay; `faults` runs a Redis topology and the faults of its nodes; `promotion` promotes a replica without losing what the primary took; `ask` sends a node commands; `clock` runs a process on a moved clock; `deployment` runs a scene's app as instances on a topology.

## Not here
- Scenes and scene vocabulary, and the set-ups for legacy and new (each area's conformance module). Starting the legacy system (`conformance-legacy`). The internals of the system under test.

## Offers
- Area (name and shape of its parts), scene composition, registration of set-ups for the new system (modules and sections, store kind; a set-up is told the modules composed, and the sections are those it gives knowing them)
- Driver contract: start with a scene, and on the new system the PEM files its process trusts besides the system's (`trustedCertificates`, for a party it reaches over https under a certificate of its own) → root URL or boot refusal, stop, storage failure (only when the scene asks for it), the mail sent where the driver runs a relay, `can` (the needs the target cannot provide) and `differs` (among the differences the owner decided, those the target answers differently).
  - A target's stop sends SIGTERM, then SIGKILL past its grace (40 seconds, beyond the kernel's stop deadline, unless the launch gives one), and fails where the target is still there after it.
- Driver registration and selection by `CONFORMANCE_TARGET` (the default is the new system)
- Pattern mode, with `CONFORMANCE_PATTERN` naming a pattern on the new system: `full` is the full template, `full+opt-ins` adds every feature that opts in
  - An area may adapt its part to the app's modules (`onNew`'s third argument): a set-up with a party the app reaches at loopback, started before it and stopped after it, or a reason to leave the scene out because the app chose an alternative, which even `full+opt-ins` leaves out
  - With `full+opt-ins`, a scene whose modules the app lacks fails
- The pattern runs (the script `patterns`, internal module `patterns`)
- Audit events (`auditEvents`, internal module `audit`): the need a scene states to read them, and a running target's trail
- Starting a process and waiting for it to respond, in a process group of its own where asked (then killed with what it started, and a stop, a kill, a refusal or a timeout answered only once the whole group has ended); a free port.
- Shared tools: a throwaway Redis (on the settings its caller gives, as `drivers` does; paused as a hung store is and, resumed, back once it answers again, within ten seconds), a second start that can cause a storage failure, a fake HTTP server for a scene's outside parties (keeps every request, its body as text and as bytes, and answers as the area's script says, in JSON, text or bytes; plain http at loopback)
  - A fake's script that fails fails the scene when the fake stops
- Test tools (`./testing`): a fake SMTP relay for a scene's mail (plain SMTP at loopback, on a free port each run; keeps every message, decoded, and finds the latest to an address)
- A fault run (`CONFORMANCE_FAULTS=1`, `./testing`): `faultRun` tells a scene it is in one, and `faultRunReporter` fails the run where a fault scene (`*.faults.case.ts`) did not run

## Invariants
- Holds neither feature vocabulary nor legacy-system names.
- Does not read scene parts; knows only area names.
- The scene-side store marks say only whether a failure can be caused and whether a store that can lose data is accepted.
- Does not depend on the contracts of the modules under test.
- Touches only the HTTP interface and boot refusals.
- A scene that contains a part of an area with no set-up fails before start.
- So does a scene about the absence of a module another one needs, on the new system.

## Depends on
- `create-app` (generates the new system's target), `trial` (the local layer it boots on), `combinations` (what modules need to run, the features that opt in). The system under test is touched only over HTTP

## Vocabulary
- Scene: a neutral description of the target's features and configuration that a test requires. A collection of named area parts.
- Area: the unit that owns scene vocabulary and set-ups. The base knows only its name.
- driver: an implementation that takes a scene and runs the target.
- not-in-pattern: a scene left out because the pattern's app lacks a module it asks for, composes one it is about the absence of, or chose an alternative, its Store among them; neither `cannot` nor `differs`.
