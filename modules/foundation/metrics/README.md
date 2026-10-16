# metrics

## Responsibilities
- Owns the contract of counters, histograms and gauges: a name, help, every value each label can take, and a histogram's buckets.
- Keeps the counts of one assembly in the process and gives them to a reader.
- Reads each gauge only when sampled, within a bound.
- Keeps every series within the declared label values, so requests never add series.

## Not here
- What is counted, and what names and labels mean (the emitter's).
- How counts are published, how help and label values are escaped, and the process's own counts (the adapter's).
- Whether dependencies are up (the emitter's, through a gauge), and tracing.

## Interface
- `counter`, `histogram` and `gauge` make an instrument from its spec; a gauge also takes the read that gives its series.
- An emitter makes its instruments at each build and contributes them to `instruments`, keyed by name, without needing `metrics`.
- `instruments` is the extension point; metrics attaches its recorder to each instrument it collects.
- Recording before that, or with no `metrics` composed, does nothing.
- `metrics.read()` gives every instrument with its declared label names and series, and no series for a gauge.
- A histogram's counts are cumulative per bucket, then one for all.
- `metrics.sample()` gives what `read()` gives, with every gauge read now, each within 2 seconds.
- `./testing` gives the contract test of gauges, and a stand-in that decides by the same rules within a bound the test sets.
- Composition definition: comes by default with `http`, with no operator section and no store.

## Invariants
- Boot is refused, naming the instrument, unless names and label names match `[a-z][a-z0-9_]*` and help is a string.
- Boot is refused, naming the instrument, unless each label has distinct string values, at least one.
- Boot is refused, naming the instrument, unless a histogram's buckets are finite and strictly increasing, at least one.
- Two instruments of one name, one another assembly has, or one not made by `counter`, `histogram` or `gauge` refuse boot.
- The label values and buckets are copied when made, so the emitter cannot change them later.
- A record is dropped when a label is missing or undeclared, a value is outside its set, the number is not finite, or a counter step is negative.
- A dropped record never throws or changes the emitter's answer, and each instrument warns once, by name, when it first drops.
- A gauge's read that throws, fails, is late, or gives a series undeclared, not finite or given twice leaves that gauge with no series.
- Each such read warns with the name and why, never the error, and the sample still answers.
- A reading is frozen, so later records do not change it.
- A histogram's `count` equals its last count, and `sum` is the sum of the values.
- Data: the counts of each instance, in the process, with a series starting at its first record.
- Series are bounded by the product of the label sets, so the module is safe on multiple instances.

## Depends on
- `kernel`

## Vocabulary
- instrument: a counter, a histogram or a gauge, made by its emitter.
- series: the counts of one combination of label values.
