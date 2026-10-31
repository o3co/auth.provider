# containers

Internal module of `release-check`: each container a check runs, owned for its whole life, its commands run by `docker-client`.

## Responsibilities
- Runs each container under one deadline, removing it at the end however its work ends.

## Not here
- What a container is for: building, installing, booting an app, and what a scene looks at in it (`release-check`'s images and scenes). Reading the cgroup (`helpers`).

## Offers
- `withContainer` (`run`, `purpose`, `within`, `teardownWithin`) → the work's answer, given a `Container`: its `name`, `run` (named and labelled; `-d` to start it), `on` (a command on it), `logs`, `state` (running and exit code, or none where gone), `until` (a look again and again), `removed`.
- `sweptRun` (run, `settle`) → the names it removed: every container labelled as of the run, then those seen after `settle` ms (3 seconds), every name tried though Docker refuses one, failing where one is still there, naming each with its refusal.

## Invariants
- Each container is named for its run, its purpose and a count, never reused, and labelled `release-check.run=<run>`.
- One deadline, from the start, covers the work, every command and every look: past it the work is cut, though it never ends, would succeed later or answers only by holding the clock past it, and fails; no look begins and no command is asked.
- A look narrows the deadline to its own while it runs, following its continuation: its commands are given no more, and one it asks past its time is refused; at its time a look still running is cut and its commands stopped, and an answer past it is not taken, and a command of it out of time is the look not holding, never a failure; any other failure of a look is.
- At the work's end, its commands are closed: one asked after it is refused, and one running is stopped, so nothing the work began reaches the container once its removal starts. A container hears its own end whatever asks, another container's work or look included, and its looks are its own; a look's waits end with it, leaving no timer.
- At the end, whatever the work did, it is removed by name, at best: so the work returns early (`rm -f -v`, its anonymous volumes with it, one gone already no failure) and inspected until Docker answers that it is not there, within a time of its own (30 seconds). Asking it closes the work's commands first, and asked again it does nothing more.
- A removal that fails, or a container still there, fails the work; where the work failed too, both failures are kept (`AggregateError`).
- Only Docker's own answer tells a container gone: a daemon unreachable, refusing or slow is a failure, never absence.
- The cleanup the check stands by is its run's sweep by label at its end, looking again after a while for a container whose making the daemon showed only after the container's own removal. Each container's own removal is best effort, to end early.
- Nothing is removed where the check's own process is killed before its sweep, or Docker cannot answer: what is left carries the label `release-check.run`. Remove it while no check runs: `docker rm -f $(docker ps -aq --filter label=release-check.run)`.

## Depends on
- `docker-client` (each docker command, within its time); node's `async_hooks` (`AsyncLocalStorage`, a look's scope)
