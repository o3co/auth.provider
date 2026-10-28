# boundaries

Internal module of `conformance-code`: the fault scenes of bounds the security model leaves to the operator, recorded as they are; no promise is checked, so none names a guarantee or a fault of one.

## Responsibilities
- Records that a code's record lives its lifetime on Redis's clock, two hours ahead of the app's: Redis's `TIME` shows the offset, the record's `PTTL` the code's 10 minutes, and the code is redeemed once.
- Records that promoting a replica that fell behind, unchecked, loses a use another replica confirmed: the code is redeemed again (the operator keeps a lagging replica from promotion).
- Records that each instance decides a token's expiry on its own clock: a token taken where it was issued is refused where the clock runs two hours ahead (only where this host can move an instance's clock, never skipped in a fault run).
- Each annotates what it saw in its report.

## Depends on
- `faults`; `conformance` (the topology's nodes and clock, the relay, the fault run)
