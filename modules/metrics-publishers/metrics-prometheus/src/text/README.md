# text

Internal module of `metrics-prometheus`: what `metrics` reads, written in the Prometheus text format (version 0.0.4).

## Responsibilities
- Writes each reading's `HELP` and `TYPE` lines and its series. A counter or gauge gets one line per series; a histogram gets its cumulative `_bucket` lines with `le`, then `+Inf`, `_sum` and `_count`.
- Help escapes `\` and line feed; label values also escape `"`, so no value breaks its line.
- Tells which readings the format cannot hold: a histogram label named `le`, or a name, derived ones included, that the process or another instrument takes.

## Not here
- The process's own counts (`process`). Reading `metrics`, and the route.

## Depends on
- `metrics` (its types only); nothing else in `metrics-prometheus`
