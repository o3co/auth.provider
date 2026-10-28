# lockout-holds

Internal module of `conformance-identity`: the fault scenes of password login's per-identifier count holding across a crash and a failover, each attempt counted once, the same on every instance (`guarantee-5-i`).

## Responsibilities
- Reads how many failures an identifier's run holds from the wait the next one starts: the scenes set the wait to start at the first failure, and it doubles with each after, so a run kept and a run lost or counted twice ask different waits.
- Checks, each scene after a control with no fault (each failure counted by one write, the attempt after them waiting and counting nothing), that:
  - a reservation whose answer is lost took effect once, unheard: the attempt is refused unavailable, and stays a failure, counted once and never resent (`Lr`);
  - a run counted before a caught-up replica is promoted, or before Redis is killed at once and started again, is held after (`F`, `C`);
  - an attempt whose instance was killed after its reservation ran and before answering is counted at another instance (`K`);
  - two attempts at one identifier at two instances, let go one after the other, are both counted, once each; let go together, each is counted at most once, one that loses its races is refused unavailable, and none goes on uncounted (`H2`): a lockout counts, it is not used once.
- After each fault, a new identifier's failure is counted.

## Depends on
- `faults`; `conformance` (the relay's faults and matches, the topology's promotion and crash, an instance's kill)
