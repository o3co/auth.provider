# docker-client

## Responsibilities
- Runs the docker client within a time, ending it past its time, and sorts how each command fails, once, for every package that drives Docker: the release's images and the conformance base.

## Not here
- What a container is for, and owning one for its life (the release check's `containers`; the conformance base's drivers and topology).
- Anything a product reads: it is assembly, unpublished.

## Offers
- `docker` (args, ms, `merged`?, `signal`?, `input`?) → what it wrote, trimmed, not holding the process; or `DockerFailed`, its `kind` one of `absent` (no such container or object), `timeout` (the client ended past its time, or stopped by its signal), `unstarted` (no client), `failed` (any other, with what it `told` and `wrote`, both in its message, and its `code`).
- `dockerSync` (args, ms, `input`?, `stdio`?) → the same, holding the process until it answers, for a control command alone: `ps`, `inspect`, `port`, `exec`, `kill`, `start`, `stop`, `restart`, `pause`, `unpause`, `rm`, `info`, `version`, `logs`, and an image's, a network's, a volume's or a container's `inspect`, `ls` and `rm` (a network's `create`, `connect` and `disconnect` too).
- `dockerWithin`, each kind's time: `control` a minute, `run` three (it may pull its image first), `build` a quarter-hour (building, writing out or reading a whole image).

## Invariants
- A command's time, or its signal, ends `docker`'s wait at once: the client is started in a process group of its own, and the group is killed, what the client started with it (a build's buildx plugin), its output let go.
- `dockerSync` can end the client alone, so it takes no command that starts a process of its own: a `build`, a `run`, `compose` or any other throws a TypeError before anything runs, and is `docker`'s. An `exec`'s command runs inside its container, which ending the client leaves to the container's removal.
- A command past its time is a `timeout` naming its command and the time (`docker kill did not answer within 60 seconds`), what the client told before it kept.
- Only Docker's own answer tells a container or an object gone: a daemon unreachable, refusing or slow is a failure, never absence.

## Depends on
- node's `child_process` (`spawn` and `spawnSync`, the docker client).
