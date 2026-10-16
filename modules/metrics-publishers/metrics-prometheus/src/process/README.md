# process

Internal module of `metrics-prometheus`: the Node process's own counts, by `prom-client`.

## Responsibilities
- Counts the process defaults under the prefix `auth_provider_`, in one registry made once per process.
- Gives their text, and the names they take, so others are kept from clashing.

## Not here
- The counts of `metrics`, and how they become text (`text`).

## Depends on
- `prom-client` (pinned); nothing else in `metrics-prometheus`
