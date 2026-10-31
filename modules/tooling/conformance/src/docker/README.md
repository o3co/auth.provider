# docker

Internal module of `conformance`: the docker client, run within a time, for every container the base starts, stops and looks at.

## Responsibilities
- Runs each docker call within the deadline of its kind, so a stalled client or daemon fails the call rather than holding a scene.

## Offers
- `dockerSync` (kind, args, `input`, `stdio`) → what the client wrote, holding the process until it answers; `dockerAsync` (kind, args) → the same without holding it, so several run at once. Each takes a shorter `within`, for a test of the deadline itself.
- `dockerWithin`, each kind's deadline: `control` a minute (`ps`, `inspect`, `port`, `exec`, `kill`, `start`, `pause`, `rm`, `network`), `run` three (it may pull its image first), `build` ten.

## Invariants
- Past its deadline the client is killed (SIGKILL) and the call throws, naming its subcommand and the deadline (`docker image inspect gave no answer within 60 seconds`), the client's own error its cause.
- A call that fails in time fails as the client failed, its error passed on.
- Each deadline leaves the slowest call CI shows many times over, and ends a scene well inside its test's own time.

## Depends on
- node's `child_process`.
