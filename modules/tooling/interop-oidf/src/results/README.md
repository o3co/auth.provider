# results

Internal module of `interop-oidf`: what each suite test of a plan proved.

## Offers
- `outcomesOf`: each test passed, failed with why, excused by a class, or waiting for review; and the expected entries no test used.

## Invariants
- A failure or warning matches an entry of its test, variant and configuration file whose block, condition and kind are its own; the block is named as its start entry names it.
- A skip is excused only by a skip entry; a review is never passed; a test that never ran or did not finish fails.
