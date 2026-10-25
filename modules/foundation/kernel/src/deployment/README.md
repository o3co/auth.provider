# deployment

Internal module of `kernel`: the preflight of what the deployment's settings ask of the modules, before any factory runs.

## Responsibilities
- On multiple instances (`deployment = multi`), refuses each module that declares itself unsafe there (`replicaSafe`).
- In production (`environment = production`), refuses what each module declares a production deployment must not hold in its section (`refusedInProduction`).

## Not here
- What is unsafe on several instances, or in production: each module's own declaration. Reading the kernel's section (`config`). The takes' preflight (`takes`), refused with these at once.

## Offers
- `checkReplicas` and `checkProduction` (modules, their checked sections, the setting, the refusals so far): each adds its refusals.

## Invariants
- A declaration is read once, and a function asked as its module's method, only with a section that passed its schema (none for a module without one, the defaults filled in).
- A module that declares no `replicaSafe` is safe on multiple instances. `replicaSafe` answers a boolean. `refusedInProduction` is a function answering a list (read by index, never by its iterator) of records of two non-empty strings, `key` and `reason`.
- Reading the declaration, asking it, or reading its answer: a throw, or an answer of another shape, refuses its module by name with a fixed reason (`its multi-instance check failed`, `its production check failed`), keeping none of what it threw; the other modules are still asked, in order.
- A production refusal is at `<module>.<key>`, with the reason the module gave; the module gives no value.
- In development, no production check is asked.

## Depends on
- None; the package's module definitions, refusals and the kernel's settings type.
