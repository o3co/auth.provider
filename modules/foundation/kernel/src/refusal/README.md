# refusal

Internal module of `kernel`: what a refused boot and an outage are, as values every copy of the kernel tells apart.

## Responsibilities
- Gives a refused boot its refusals, and a dependency's outage its name, each marked so that two copies of the kernel a bundle may hold agree.
- Contains a module's accidental failures as the kernel reads what it throws: a throw, an error holding a secret, a list of another shape. A module's code runs in the kernel's process and is trusted; one hostile on purpose is outside what the kernel guards.

## Not here
- When a boot is refused, and how refusals are gathered and ordered (assembly's). What a module does with an outage (the module's).

## Offers
- `Refusal` (where, and why); `BootRefused` (its refusals), and `BootRefused.is`, which never throws.
- `Unavailable` (a dependency gave no answer, as distinct from a negative answer; what gave none), and `isUnavailable`, which never throws.
- `BuildRefused` (where, and why), what a library called in a factory throws to refuse the boot, holding no build context; and `BuildRefused.is`, which never throws.
- `buildRefusalOf`, for assembly: the refusal a thrown value is, read once, or none.
- `readThrown` (read, otherwise): what a read makes of a thrown value, or `otherwise` where it throws; `thrownKind`, the type a warn line names (an error's name where the kernel knows it, else `Error`; the value's type; or `unknown`). `refusalsIn`, the refusals a value holds, read by index into the kernel's own list. The kernel reads a thrown value only through them.
- `RefusalSignal`, what `refuse` and `refuseAll` throw inside a factory; it never leaves the kernel.

## Invariants
- `BootRefused`, `BuildRefused` and `Unavailable` are told by a mark (`Symbol.for`) every copy of the kernel shares, never by their class or name, and a value whose mark cannot be read (a revoked proxy, a trap that throws) is none of them, never an error; `RefusalSignal`, which never leaves the kernel, by its class.
- A `BuildRefused`'s where and reason reach the operator as written: a public diagnostic, never a secret, which the kernel cannot tell by its form. Each is one line (`where` 1 to 200 characters, `reason` 1 to 500) with no control or format character; a constructor given another throws a TypeError, and a marked value holding another is no `BuildRefused`.
- A `BootRefused` and a `RefusalSignal` each hold a frozen list of their own, read by `refusalsIn` from what they are given: one at a time, by index, keeping a refusal only where its where and reason are strings (an empty one is still words); a hole, another shape, or a read that throws is left out, and a list changed after leaves them as read.
- Assembly reads a thrown signal's refusals by `refusalsIn` too, never through the signal's own methods; where it reads none, the build is `failed during assembly`, so a failed build is never passed over without a refusal.
- Assembly records a build's thrown `RefusalSignal` by its refusals and a `BuildRefused` by its where and reason. A build that failed because one it waited on failed adds nothing: that one's refusal is recorded already. Any other value, or one whose reading throws, is `failed during assembly`, its text never kept, and never passed over.

## Depends on
- None
