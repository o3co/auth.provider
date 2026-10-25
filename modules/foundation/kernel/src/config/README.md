# config

Internal module of `kernel`: reading each module's section, and the kernel's own, from the configuration given.

## Responsibilities
- Reads each module's section, and the kernel's own, through its schema.

## Not here
- Reading configuration files (`config-files`). The schemas of time and size keys (`setting`). Building the modules (the package's assembly). What a configuration item means (its module).

## Offers
- Section `kernel`: `deployment` (`single` or `multi`, no default), `environment` (`production` or `development`, default `production`), `logging.level` (a level or `silent`, default `info`) and `stop-deadline` (`1s` to `1h` in whole seconds, default `30s`; an orchestrator's grace period must be longer).
  - `kernelSection` is its schema, with a description of each key for operators; the kernel reads the section through it as a module's is read.
  - `kernelConfig` builds it, single (and so production) unless told otherwise.
- `KernelSettings`; `readSections` (modules, configuration, refusals) → the kernel's settings and each module's frozen section. `readConfigured` (schema, value) → the value read as a section is, or each `Issue`.

## Invariants
- A section is read as the HOCON library's typed getters read it; a refusal names the key path, never the value. A section for no module, a module without a section given one, and a duplicate module name are refused.
- A module's schema that throws as it reads its section (any value, one whose reading throws too) refuses that section by the module's name (`its schema failed as it read the section`), keeping none of what it threw.

## Depends on
- `setting`; the package's freezing, module and refusal types; `runtime` (the log levels)
