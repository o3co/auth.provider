# device-code-once

Internal module of `conformance-device`: the fault scenes of a device code decided and redeemed once (`guarantee-5-f`).

## Responsibilities
- Checks, each scene after a control with no fault (the approval taken by one write that succeeds, and the device refused, `invalid_grant`, polling again with no such write), that a token is issued once for a device and a later poll is refused after:
  - its take's answer lost once, the resend taking the first answer (`Lr`); every answer lost, which answers unavailable and gives no token (`Lx`);
  - a caught-up replica promoted (`F`); Redis killed at once and started again (`C`);
  - its instance killed after the take and before answering, refused at another instance (`K`); one device polled at two instances at once, taken once when one take is let go after the other answered, and issuing at most once when both are let go together (`H2`).
- Checks that a device approved at one instance and denied at another at once is decided once: the decision let go first stands, the other is refused `already_decided`, and the poll follows the one that stood (`H2`).

## Invariants
- A taken device's poll answers `invalid_grant` with no description, as an unknown device's does, and an expired one answers `expired_token`; so a refusal as taken is told by the poll sending no take of its own while the device is still looked up at the verification interface: polled by its own client, a kept device answers `invalid_grant` only once taken.

## Depends on
- `faults`; `conformance` (the fault scene's deployment and the relay's matches)
