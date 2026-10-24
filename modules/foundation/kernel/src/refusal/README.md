# refusal

Internal module of `kernel`: what a refused boot and an outage are, as values every copy of the kernel tells apart.

## Responsibilities
- Gives a refused boot its refusals, and a dependency's outage its name, each marked so that two copies of the kernel a bundle may hold agree.

## Not here
- When a boot is refused, and how refusals are gathered and ordered (assembly's). What a module does with an outage (the module's).

## Offers
- `Refusal` (where, and why); `BootRefused` (its refusals), and `BootRefused.is`.
- `Unavailable` (a dependency gave no answer, as distinct from a negative answer; what gave none), and `isUnavailable`.
- `RefusalSignal`, what `refuse` and `refuseAll` throw inside a factory; it never leaves the kernel.

## Invariants
- Each is told by a mark (`Symbol.for`) every copy of the kernel shares, never by its class or name.

## Depends on
- None
