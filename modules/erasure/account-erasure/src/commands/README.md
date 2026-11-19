# commands

Internal module of `account-erasure`: the erasure commands, each as its app entry calls it.

## Responsibilities
- Answers each command's run as the lines it writes and the code it exits with, from the frame and the command's body.

## Not here
- The journal's hold, the step and their order: the internal module `frame`. Booting the entry, a refused boot (78) and a run that throws (1): `app-entries`.

## Offers
- `erasureCommands`, on `.`: `enter(args)`, `erasure-enter`'s run.

## Invariants
- The codes, fixed once for every command; 1 and 78 are app-entries' own:
  - 0: done.
  - 2: `accompanied`, nothing entered or run; 3: `unchecked`, nothing entered or run.
  - 4: `entered-not-shown-alone`, `enter` alone: the key is set.
  - 5: `busy`; 6: `not-in-maintenance`, for the commands that pass the step.
  - 7: `hold-left`: the command's answer stands, as its lines say; its hold's release failed, and the hold may be left.
  - 64: an argument the command does not take; `enter` takes none.
  - A later command's own answers take 10 and up.
- A line carries no subject, no configured value and no error's words. The journal's holder is shown as the medium records it only where it is one line of at most 200 characters with no control, format or line-separator character; otherwise "unreadable holder".
- Every command under the key runs in the frame; none reaches its body without it, and each command's test pins that.
- An unavailable call of the hold, the step or the body reaches the entry as thrown: app-entries' 1, look and run again. Where the release then fails too, the hold may be left, and the next command answers `busy` until it is released.
- `enter` runs in the frame, entering; the frame's and the step's answers become its lines and codes, and it writes nothing of its own.

## Depends on
- `erasure-journal` (the hold), `kernel`; the internal modules `frame`, `step` and `maintenance`.
