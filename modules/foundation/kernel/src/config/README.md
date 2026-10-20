# config

Internal module of `kernel`: reading configuration, from files to each module's checked section.

## Responsibilities
- Layers HOCON files into one tree, and reads each module's section, and the kernel's own, through its schema.

## Not here
- The schemas of time and size keys (`setting`). Building the modules (the package's assembly). What a configuration item means (its module).

## Offers
- `loadConfig` and `ConfigSource`; `kernelSection`, `KernelSettings` and `kernelConfig`; `readSections` (modules, configuration, refusals) → the kernel's settings and each module's frozen section. `readConfigured` (schema, value) → the value read as a section is, or each `Issue`.

## Invariants
- Each file is resolved on its own, then layered; a file that does not read or resolve is refused at `file:line:col`, by kind, never by its text.
- A section is read as the HOCON library's typed getters read it; a refusal names the key path, never the value. A section for no module, a module without a section given one, and a duplicate module name are refused.

## Depends on
- `setting`; the package's freezing, module and refusal types; `runtime` (the log levels)
