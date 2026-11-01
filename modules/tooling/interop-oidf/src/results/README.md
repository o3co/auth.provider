# results

Internal module of `interop-oidf`: what each suite test of a plan proved.

## Offers
- `testsOf`: each test of a plan the suite ran, read back from its API: its latest instance's result and log, none for one that never ran. The plan is the one its id names, bearing the name given; without an id, the one plan of that name, two of it refused.
- `outcomesOf`: each test passed, failed with why, excused by a class, or waiting for review; the expected entries no test used; and the tests declared not run that no test of the plan answers.

## Invariants
- A failure or warning matches an entry of its test, variant and configuration file whose block, condition and kind are its own; the block is named as its start entry names it.
- A skip is excused only by a skip entry; a review is never passed, and stands over the warnings an entry excuses.
- A test that never ran or did not finish fails, but one its driver declared not run, which a skip entry naming it excuses by the entry's class.
- A test declared not run that ran (it holds an instance or an info, whatever its state, judged before anything else), or that no entry excuses, fails.
- A declared test is its test and variant, the variant's keys in any order; a declaration no test of the plan answers is named.
