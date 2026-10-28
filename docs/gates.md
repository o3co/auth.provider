# Gates

A change passes four gates before it ships: the guard, a review, the checks at boot, and the conformance scenes. The guard reads how code is laid out, not what it means, so a module of sound shape can still be wrong. This page names, for each kind of misdesign tried, the gate that stops it and the test that shows it.

What each rule checks is in the `guard` and `guard-imports` cards (`modules/tooling/guard/README.md`, `modules/tooling/guard-imports/README.md`); a rule's ID here names it, never restates it. The tests are in `modules/tooling/guard/test/misdesigns.test.ts` and `modules/tooling/guard-imports/test/misdesigns.test.ts`, by title.

## Stopped by the guard

| Misdesign | Rule | Test |
|---|---|---|
| A feature keeps its data by taking the store itself, not through a store interface its wiring builds | G16 | "G16 stops a feature that keeps its data by taking the store itself, …" |
| A feature leans on an adapter | G10 | "G10 stops a feature that leans on an adapter, …" |
| A feature composes another module itself | G3 | "G3 stops a feature that composes another module itself, …" |
| A feature takes a contract its owner keeps for named takers alone | G31 | "G31 stops a feature taking a contract its owner keeps for named takers alone" |
| A feature reaches another server itself | G26 | "G26 stops a feature reaching another server itself, …" |
| A feature reads the host's clock | G13 | "G13 stops a feature reading the host's clock, …" |
| A feature draws its own randomness | G23 | "G23 stops a feature drawing its own randomness, …" |
| A wiring decides | G15 | "G15 stops a wiring that decides, as a feature would" |

## Passed by the guard

Each of these keeps every rule. Its test says so, and is turned over once the guard stops it.

| Misdesign | Review | At boot | Conformance | Test |
|---|---|---|---|---|
| A module keeps what is used once in its own process, so a second instance uses it again | Stops it | Planned: a module that declares nothing about several instances is taken as safe (promise 5 of the [security model](security-model.md#promises-across-modules)) | Planned: a scene running two instances at once, with such a module composed | "passes a feature that keeps what is used once in its own process, …" |
| A module grants where what it waits on cannot answer | Stops it | None | The scenes where the store fails, for the modules they compose (promise 3); a module no scene composes is a review's alone | "passes a feature that grants where what it waits on cannot answer: …" |
| A module writes a token into a log line | Stops it | None | None: no scene reads a running server's log lines (promise 8) | "passes a feature that writes a token into a log line: …" |
