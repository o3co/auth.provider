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
- A declaration that is a function is asked only with a section that passed its schema.
- One that throws, or whose answer throws as it is read, refuses its module by name with a fixed reason (`its multi-instance check failed`, `its production check failed`), keeping none of what it threw; the other modules are still asked.
- A production refusal is at `<module>.<key>`, with the reason the module gave; the module gives no value.
- In development, no production check is asked.

## Depends on
- None; the package's module definitions, refusals and the kernel's settings type.
