# kernel

## Responsibilities
- Assembles modules in two stages: builds every provision and contribution, resolving contracts at once, then checks late references. Owns the generic rules of extension points, collecting contributions in module order.
- Loads configuration and gives each module only its own section, checked and frozen. With even one boot refusal, nothing is served.
- Runs the lifecycle (start, periodic tasks, stop within a drain deadline) and answers readiness (internal module `lifecycle`, whose card holds their invariants). Provides the clock, randomness and log.
- Additions to this module go through a human gate.

## Not here
- Feature vocabulary, other modules' names, per-feature kinds of extension point, the outside and storage, and what each configuration item means.

## Offers
- `defineModule`: name, section schema (zod, the library that reads sections), multi-instance declaration (a boolean, or a function asked only with a section that passed), `takes` (the `Handle`s its factories take from other modules: a list, or such a function), provisions and contributions. `contract` (optionally `takenBy`, the names of the modules that may take it) and `extensionPoint` (exactly one / at least one / any number / keyed) make the handles.
- `assemble`: answers `get`, `start` and `stop(deadlineMs?)` (without one, `stop-deadline`), or rejects with `BootRefused` (one module may raise several refusals), refused after its builds once their stop hooks ran (`lifecycle`'s rollback).
- `stop`: after the periodic tasks, runs the stop hooks in reverse order, each given a signal that aborts at the deadline; the hooks left are then called without waiting. A hook may also run without `start()`, on a refused assembly: it ends what its build started.
- Build context: the runtime, `section`, `get`, `collect`, `late` (a function giving a contract's interface once assembly succeeds), `readinessReport`, `onStart`, `onStop`, `every`, `refuse` and `refuseAll`.
- `readinessReport(deadlineMs)`: runs every probe (a contributed check of one resource, keyed by name at `probes`) at once, joining a check still running, and gives each probe's name and whether it passed. `ready` only if all pass within the caller's deadline; once stop begins, `unready` with all down. A check is aborted once no caller waits.
- `every(intervalMs, task)`: runs `task(signal)` from start at a whole interval of ms from 1 to 2^31−1, never two at once; a failed run is logged and the next follows; stop aborts a running one and waits for it.
- Refusals and outages (internal module `refusal`): `BootRefused`, `BuildRefused` (a library's refusal from inside a factory) and `Unavailable`, each told by a mark every copy of the kernel shares, its `is` never throwing.
- `deepFreeze` freezes a value from outside once, to the leaves. `sameSecret` compares two secrets (strings as UTF-8, or bytes) in constant time when their byte lengths match, and answers false otherwise.
- Runtime contracts (internal module `runtime`, whose card holds the log's invariants): clock, randomness, and a log with one method per level (trace to fatal). Sinks come from `logSinks` (any number).
- Section `kernel`: `deployment` (`single` or `multi`, no default), `logging.level` (a level or `silent`, default `info`) and `stop-deadline` (`1s` to `1h` in whole seconds, default `30s`; an orchestrator's grace period must be longer).
  - `kernelSection` is its schema, with a description of each key for operators; the kernel reads the section through it as a module's is read.
  - `kernelConfig` builds it, single unless told otherwise.
- A section, and a value it passes through read by `readConfigured` (the value, or each `ConfigurationIssue`), is read as the HOCON library's typed getters read it: a string converts to the number or boolean its schema asks for, and one that does not, or a value configuration cannot hold, refuses boot.
- Keys of time and size are read through `setting`: written with their unit, read as a number of it.
- `./testing`: a switch making an implementation's async calls unavailable (the next call, or named methods until restored), a module whose provision goes through one, a quiet runtime and a recording log, and `takesUnused` (each handle a module's takes name that no factory took in an assembly, which it stops before it answers, by module, for a test of each section).

## Invariants
- Before any factory runs, one preflight refuses, together with the sections', replicas' and duplicate providers' refusals, each gap a module's takes show: a contract no other module provides or its `takenBy` refuses, a point whose registered contributions break its rule (by identity, once). A refused boot has built nothing.
- A module with takes taking, by `get`, `late` or `collect`, a handle they do not name (its own contracts aside) refuses boot, even when it catches the throw.
- Contracts and points resolve by value identity, never by name. Cycles, gaps, two providers, an empty point needing one, duplicate keys and a bad `every` interval refuse boot.
- Refusals of one stage are reported together, by key path (a value configuration cannot hold too), never by value; a key the schema needs and the configuration does not set is `required, and not set`, unless the schema words it itself. Every key a keyed point holds twice is refused, and a point is checked once however many modules collect it. `multi` refuses a module unsafe on multiple instances.
- Before assembly succeeds, a late reference throws and `readinessReport` rejects. `readinessReport` and `stop` reject with a TypeError a deadline other than whole ms from 1 to 2^31−1. A late contract no module provides refuses boot.
- A module a contract's `takenBy` does not name that takes it by `get` or `late` refuses boot, even when it catches the throw. `Assembly.get`, the composition root's, is not bound, and it binds the modules of a trusted assembly, never hostile code in the same process.
- Sections are frozen to the leaves. Contributions are frozen one level, since library values they hold keep state.

## Depends on
- None (external libraries only)

## Vocabulary
- contract: a typed retrieval point, unique as a value.
- extension point: a point its owner creates to collect contributions. A contributor may use the owner's types and receives what the owner passes as arguments; it holds the owner's interface through a late reference.
- section: configuration of one module only, named after it.
