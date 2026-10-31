# app-entries

## Responsibilities
- Writes a generated app's entries, its start and the scripts its composed modules call for, and holds how each boots, refuses, checks 0.17's variables, writes and stops.

## Not here
- The project's files around them, its manifest, configuration, image and guide (`app-output`); what each module's script runs (that module, through its contract).

## Offers
- `mainSource` (the composed modules, what each is imported as, where the operator writes each key the configuration reads) → the app's entry, which `start` runs.
- `entriesOf` (the composed modules, what each is imported as, the command that runs a file) → each entry's script and file.
- `KeysWritten`: where the operator writes the keys the configuration reads: each one's variable, those of several lines, and the local layer.
- `kernel` and `configFiles`, the packages every app depends on (its entry reads its configuration files through `config-files`).

## Invariants
- The app reads the configuration files `APP_CONFIG` lists, comma-separated, layered in order; the generated configuration file when unset.
- The app exits 78 on a refused boot, told by the kernel's mark (`BootRefused.is`), writing each refusal on standard error, every line handed on before it exits.
- A refusal of a key the configuration reads from the environment says, after its reason, where to write it: its variable in `.env`, or the key in the local layer (the local layer alone for a value of several lines); a refusal of anything else is written as it is. The hint comes from a table written when the app was generated, from what writes `application.conf`: an app whose configuration files changed since may be told of a variable they no longer read.
- The app's entry checks, as it boots, the variables 0.17 read that the environment sets and no configuration file reads, by `config-files`' `legacyVariablesCheck` alone: its warning goes once to standard error as `warn config-files:` and boot goes on; its refusal refuses boot. `APP_LEGACY_VARIABLES` (`warn`, `refuse`, `ignore`) chooses, read there.
- SIGTERM or SIGINT stops the app, draining; one that comes while it starts stops it once started, and a second one waits for the first stop instead of stopping again.
- With `seal` composed, the project has a `reseal` script, running the modules' resealers.
- With `mfa-witnessing` composed, the project has a `witness-backfill` script. It settles each subject read from standard input, one a line, empty lines skipped, each other line used as sent, through `witnessBackfill`, and writes only how many were marked, held, none, unclaimed, inconsistent, unknown (an answer it does not know) and failed (unavailable), never a subject.
- A script reading subjects writes on standard error only fixed lines beside its counts: how many refusals refused its boot, where they can be counted (exit 78), that its boot failed or that the run stopped on an unexpected error (exit 1), and that 0.17's variables are set, naming none. Never a subject, a configured value or an error's words; the app's own start tells why.
- A script reading subjects holds the process's streams (`write` and `end`), the console, warnings and errors no one catches to those lines, reading the app and its modules only after. Code writing to a descriptor itself (`fs.writeSync(1, …)` or `(2, …)`) is code the process trusts, outside it.
- The `witness-backfill` script exits 0 where none failed and none was unknown, else 1, and 78 on a refused boot, told by the kernel's mark as the app's is.
- With `passkey-witnessing` composed, the project has a `passkey-backfill` script, read and exiting as `witness-backfill` does, through `passkeyBackfill`: it writes only how many were marked, held, none, pending, inconsistent, unknown and failed.
- With `mfa-reset` composed, the project has an `unclaimed-factors` script, reading subjects as the backfills do. It writes each subject given whose counting factor stands for nothing (`resetCandidates`), one a line on standard output, as the operator gave it, and the counts (named, clear, failed) on standard error. It exits 0 where none failed, else 1, and 78 on a refused boot.
- In a backfill or `unclaimed-factors`, a failure other than unavailable is counted and stops the run there: the subjects after it are not read.
- Each entry checks the variables 0.17 read as the app's entry does, by `legacyVariablesCheck`, its refusal refusing the entry's boot: `reseal` writes the warning as `warn config-files:`, a script reading subjects the fixed line above, naming none.
- What an entry writes is handed on before it exits: a slow pipe holds the script, never drops a line.
- The entries that read subjects read them one way: a line longer than a subject may be (255 bytes) is counted failed, and no more of it is held.

## Data
- Reads its templates; writes nothing, handing each file's text to its caller.

## Depends on
- Nothing in the workspace.
