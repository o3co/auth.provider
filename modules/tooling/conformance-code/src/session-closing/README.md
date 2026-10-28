# session-closing

Internal module of `conformance-code`: the fault scenes of a closing session closed, every path for its tokens with it (`guarantee-1-a`).

## Responsibilities
- Checks, each scene after a control with no fault (a logout adds the close, writes the record closing, revokes the session's token, writes it closed and is done, in that order, and the token is refused), that a close is seen done in that order and its token refused after:
  - the closing's answer lost once, the resend taking the first answer (`Lr`); every answer lost, the logout answering unavailable and a sweep closing it (`Lx`);
  - the close stopped halfway, its participant's write held, then a caught-up replica promoted (`F`), its calls confirmed on a server other than the one that answered, closed only once healed (`Fs`), or Redis killed at once and started again (`C`);
  - its instance killed halfway, closed by another instance's sweep, no logout sent there (`K`); another instance's sweep closing it while the logout is held, the logout then answering closed (`H2`).

## Depends on
- `faults`; the package's scene builder (userinfo, a sweep every second); `conformance` (the relay's matches)
