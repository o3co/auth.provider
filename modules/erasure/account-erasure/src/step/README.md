# step

Internal module of `account-erasure`: the one step a command under the maintenance key runs, "under the key and alone".

## Responsibilities
- Brings a command under the maintenance key, alone, or refuses it, before its body runs.

## Not here
- The journal's hold, and running the step before a command's body: the command frame (lands with the first command). What a command does: the command.

## Offers
- `underKeyAndAlone(maintenance, way, clock)`: `entering` for `erasure-enter` alone, `passing` for every other command under the key. It answers `under-key`, with the epoch, where the command may run.

## Invariants
- Only `entering` calls `enter()`. It reads `alone()`, and on `accompanied` or `unchecked` refuses without entering. It then enters and reads `alone()` again.
  - On `accompanied` or `unchecked` there, or where that read gives no answer (`unavailable`), it answers `entered-not-shown-alone`: the key stays set; it does not leave. The answer carries what it found and the way on:
    - for `accompanied`, stop that client and run `erasure-enter` again;
    - for `unchecked` or `unavailable`, run it again once every server answers.
  - Shown alone there, it writes the entry-time mark, `account-erasure.entered`, in the present epoch, then answers `under-key`. Nothing else writes it. Its time is the tool host's clock's, under design.md's decision that the deployment keeps host clocks synchronized.
- `passing` never enters. It reads `record()` and refuses `not-in-maintenance` where the key is not held, or is held with no epoch, which no entry leaves. It then reads `alone()` and refuses `accompanied` or `unchecked`. Its `under-key` carries the epoch read at `record()`.
- An unavailable `enter()` stops the step as unavailable and may have set the key. The way on is `erasure-enter` again: it enters under a new epoch and checks again, and nothing of the earlier epoch counts.
- An unavailable mark stops the step as unavailable with the key set; the entry time may or may not be written. The way on is `erasure-enter` again, which enters under a new epoch and writes its own.
- Any other call that is unavailable, the read after entering apart, stops the step as unavailable, and the step calls nothing after it.

## Depends on
- the internal module `maintenance`
