# frame

Internal module of `account-erasure`: the frame every command under the maintenance key runs in.

## Responsibilities
- Runs a command's body in one order: the journal's hold, the step, the body, the hold's release.

## Not here
- The step's own reads and refusals: the internal module `step`. What a command does: the internal module `commands`. `erasure-check`, which writes nothing and takes no key, runs outside it.

## Offers
- `inFrame(parts, way, body)`: the body's answer, or what kept the command from it: `busy` (the journal is held, its holder as the medium records it), or the step's answer where it is not `under-key`; either the body's or the step's as `hold-left` where the release then failed.

## Invariants
- The body runs only under the hold, after the step answers `under-key`.
- Where the journal is held, it answers `busy` and calls nothing more.
- Where the step answers anything but `under-key`, it answers that, and the body never runs.
- The hold's release is asked once, whether the step or the body answered or threw, Unavailable among them. Where the release throws Unavailable, an answer stands, given as `hold-left`, and a throw is thrown as it was; either way the hold can stay, as after a crash, and `busy` holds until the operator releases it (the journal adapter's card). Anything else a release throws is thrown in place of an answer; after a throw, that throw stands.

## Depends on
- `erasure-journal` (the hold); the internal modules `step` and `maintenance`.
