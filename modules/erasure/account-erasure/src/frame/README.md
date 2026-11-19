# frame

Internal module of `account-erasure`: the frame every command under the maintenance key runs in.

## Responsibilities
- Runs a command's body in one order: the journal's hold, the step, the body, the hold's release.

## Not here
- The step's own reads and refusals: the internal module `step`. What a command does: the internal module `commands`. `erasure-check`, which writes nothing and takes no key, runs outside it.

## Offers
- `inFrame(parts, way, body)`: the body's answer, or what kept the command from it: `busy` (another command holds the journal, its holder as the medium records it), or the step's answer where it is not `under-key`.

## Invariants
- The body runs only under the hold, after the step answers `under-key`.
- Where another command holds the journal, it answers `busy` and calls nothing more.
- Where the step answers anything but `under-key`, it answers that, and the body never runs.
- A body or step that throws, Unavailable among them, still releases the hold; only a crash leaves it, and then `busy` holds until the operator releases it (the journal adapter's card).

## Depends on
- `erasure-journal` (the hold); the internal modules `step` and `maintenance`.
