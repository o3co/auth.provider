# config-files

## Responsibilities
- Reads an app's configuration files: layers HOCON files into one tree for `kernel`'s `assemble`, which checks each module's section.
- Tells which variables 0.17 bound the environment sets and none of the files reads.

## Not here
- Reading and checking each module's section, and the `setting` forms of time and size (`kernel`). Which files an app reads, and in what order (the app's composition root).

## Offers
- `loadConfig` (`ConfigSource`: `files`, highest priority first, and `env`) → a plain tree; `${...}` reaches environment variables and the same file only.
- `unreadLegacyVariables` (`ConfigSource`) → the variables 0.17 bound that `env` sets and no file reads; `legacyVariablesWarning` (those names) → the boot's warning, or none.

## Invariants
- Each file is parsed and resolved on its own, then layered, earlier files first; a refusal names its file.
- A file that cannot be read, does not parse, or has a substitution that does not resolve refuses boot (`BootRefused`) at the file, or its `file:line:col`, and why by kind, never by its text.
- A file reads a variable when the HOCON library looks it up in `env` while parsing. The names come in order, with their count in the warning, never their values.

## Data
- The variable names 0.17's packages and app template bound, taken once from tag v0.17.0; the list does not grow.

## Depends on
- `kernel` (the boot refusal); the HOCON library
