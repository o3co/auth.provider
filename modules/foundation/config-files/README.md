# config-files

## Responsibilities
- Reads an app's configuration files: layers HOCON files into one tree for `kernel`'s `assemble`, which checks each module's section.

## Not here
- Reading and checking each module's section, and the `setting` forms of time and size (`kernel`). Which files an app reads, and in what order (the app's composition root).

## Offers
- `loadConfig` (`ConfigSource`: `files`, highest priority first, and `env`) → a plain tree; `${...}` reaches environment variables and the same file only.

## Invariants
- Each file is parsed and resolved on its own, then layered, earlier files first; a refusal names its file.
- A file that cannot be read, does not parse, or has a substitution that does not resolve refuses boot (`BootRefused`) at the file, or its `file:line:col`, and why by kind, never by its text.

## Depends on
- `kernel` (the boot refusal); the HOCON library
