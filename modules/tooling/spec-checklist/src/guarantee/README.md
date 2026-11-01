# guarantee

Internal module of `spec-checklist`: the vocabulary and the source of the `guarantee` spec, the provider's own promises.

## Responsibilities
- Names the faults a guarantee's `faults:` line and a test's `{fault:<name>}` mark may name.
- Reads the security model's promises, so that none is lost unseen, and holds the guarantee file's sections to them.

## Not here
- Parsing the checklist's files and the tests' titles (the package's root). How a fault is brought about (`conformance`).

## Offers
- `faultNames`, `isFaultName`, `FaultName`: `Pu`, `Pd`, `R`, `L`, `S`, `Lr`, `Lx`, `F`, `Fs`, `C`, `K`, `H2`, `M`, `Ev`, `R0`, `Wt`, `Nr`, `Ta`; each one's meaning is written in the guarantee file's head.
- `promisesIn` (the security model's text → its promises, by number and bold title, and what could not be read), `guaranteeFindings` (the guarantee file against them), `promisesSource`.

## Invariants
- The section `## Promises across modules` is there once, CRLF read as LF; each top-level list entry is `N. **<title>**`, numbered 1, 2, …, the title to the line's last `**`, kept as written (punctuation and code spans). Any other top-level entry (another marker, an empty one, no bold, a title past its line, words after it), an indented numbered entry, an empty section: each is a finding. A promise's explanations are its indented bullets and lines, not read.
- Each section of the guarantee file is a promise's number with its title word for word, in order, once; every promise has an item; a ledger for the guarantee file is a finding.
- A guarantee item is MUST or MUST NOT, takes `noncompliant` alone of the marks, and one `faults:` line at most.
- A guarantee's test marks each fault it brings in its title, `{fault:<name>}`. A title reserves `{fault` and `{faults` not followed by a letter: each is a mark, to the next `}` or the title's end, well formed only as `{fault:<name>}` of a fault named once; any other is a finding, and so is a mark in a title that names no guarantee. A title's fault marks bind to every guarantee it names, whose `faults` lines must name them.
- The boundaries the fault scenes check (the clocks' drift as written, a lagging replica's promotion) are no fault a guarantee names.

## Depends on
- The package's checklist types.
