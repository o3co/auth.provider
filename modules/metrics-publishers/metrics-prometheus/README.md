# metrics-prometheus

## Responsibilities
- Publishes the counts of `metrics` and the Node process's own counts as Prometheus text, on a route of `http`.
- Writes what `metrics` samples in the text format through its internal module `text`, the only place that conversion lives.
- Counts the process defaults through its internal module `process`, with `prom-client` pinned.

## Not here
- What is counted belongs to the emitting modules, and the registry and label sets to `metrics`.
- Routing and the `503` and `500` answers belong to `http`; the gauge of whether dependencies are up, to `http-ops`.
- Limiting who may scrape belongs to the proxy, which the provider always sits behind.

## Interface
- Composition definition only: it contributes `GET <path>` to `http`'s routes, with no policy and no body, and `http` answers HEAD as GET.
- The answer is `200` with `text/plain; version=0.0.4; charset=utf-8`, `no-store` and `Pragma: no-cache`.
- The body is what `metrics` samples at the scrape, then the process defaults prefixed `auth_provider_`.
- Operator section `metrics-prometheus`: `path` (default `/metrics`), from `/`, not ending in `/*`, with no query, fragment, whitespace or control character.
- It comes by default with `http` and `metrics`, and a deployment that does not publish leaves it out.

## Invariants
- An instrument the text cannot hold refuses boot by name: a histogram label named `le`, or a name the process or another instrument takes, `_bucket`, `_sum` and `_count` included.
- Help escapes `\` and line feed, and label values also escape `"`, so no value breaks its line.
- The body holds only the series `metrics` gives and the process defaults, so no request's path or query reaches it.
- A wrong `path` refuses boot without showing the value, and so does a missing `metrics`.
- A gauge whose read fails or is late has no series, and the scrape still answers `200`.
- The process defaults are counted in one registry per process, from boot on.
- Each instance publishes only its own counts, so the module is safe on multiple instances.

## Depends on
- `kernel`, `metrics`, `http`, `zod`, `prom-client`
