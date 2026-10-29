# entries

Internal module of `app-output`: a generated app's entries besides `start`.

## Responsibilities
- Writes each entry an app's composed modules call for, as a script of the app's manifest and a file under `src/`: the same modules, built and never started, running what that module offers.

## Not here
- The app's own entry (`mainSource`) and the manifest and files around them: the package's.
- What each entry runs: the module it runs for, through its contract.

## Offers
- `entriesOf` (the composed modules, what each is imported as, the command that runs a file) → each entry's script and file.

## Invariants
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

## Depends on
- The package's `filled` and the packages every app depends on (`kernel`, `configFiles`).
