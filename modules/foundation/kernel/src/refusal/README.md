# refusal

Internal module of `kernel`: what a refused boot and an outage are, as values every copy of the kernel tells apart.

## Responsibilities
- Gives a refused boot its refusals, and a dependency's outage its name, each marked so that two copies of the kernel a bundle may hold agree.

## Not here
- When a boot is refused, and how refusals are gathered and ordered (assembly's). What a module does with an outage (the module's).

## Offers
- `Refusal` (where, and why); `BootRefused` (its refusals), and `BootRefused.is`.
- `Unavailable` (a dependency gave no answer, as distinct from a negative answer; what gave none), and `isUnavailable`.
- `BuildRefused` (where, and why), what a library called in a factory throws to refuse the boot, holding no build context; and `BuildRefused.is`, which never throws.
- `buildRefusalOf`, for assembly: the refusal a thrown value is, read once, or none.
- `readThrown` (read, otherwise): what a read makes of a thrown value, or `otherwise` where it throws; `thrownKind`, the type a warn line names (an error's name, the value's type, or `unknown`). The kernel reads a thrown value only through them.
- `RefusalSignal`, what `refuse` and `refuseAll` throw inside a factory; it never leaves the kernel.

## Invariants
- `BootRefused`, `BuildRefused` and `Unavailable` are told by a mark (`Symbol.for`) every copy of the kernel shares, never by their class or name; `RefusalSignal`, which never leaves the kernel, by its class.
- A `BuildRefused`'s where and reason reach the operator as written: a public diagnostic, never a secret, which the kernel cannot tell by its form. Each is one line (`where` 1 to 200 characters, `reason` 1 to 500) with no control or format character; a constructor given another throws a TypeError, and a marked value holding another is no `BuildRefused`.
- Assembly records a build's thrown `RefusalSignal` by its refusals and a `BuildRefused` by its where and reason. A build that failed because one it waited on failed adds nothing: that one's refusal is recorded already. Any other value, or one whose reading throws, is `failed during assembly`, its text never kept, and never passed over.

## Depends on
- None
