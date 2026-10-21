# config

Internal module of `kernel`: reading each module's section, and the kernel's own, from the configuration given.

## Responsibilities
- Reads each module's section, and the kernel's own, through its schema.

## Not here
- Reading configuration files (`config-files`). The schemas of time and size keys (`setting`). Building the modules (the package's assembly). What a configuration item means (its module).

## Offers
- `kernelSection`, `KernelSettings` and `kernelConfig`; `readSections` (modules, configuration, refusals) → the kernel's settings and each module's frozen section. `readConfigured` (schema, value) → the value read as a section is, or each `Issue`.

## Invariants
- A section is read as the HOCON library's typed getters read it; a refusal names the key path, never the value. A section for no module, a module without a section given one, and a duplicate module name are refused.

## Depends on
- `setting`; the package's freezing, module and refusal types; `runtime` (the log levels)
