# legs

Internal module of `spec-checklist`, inside `evidence`: a run's legs, each a shard of its files or the whole of them.

## Responsibilities
- Gives a kind of job its legs, keys a report's or a mark's leg, chooses the reports that count by leg and attempt, and tells which expected runs every leg of reported.

## Not here
- Writing reports and marks, reading the runs, and an item's status (`evidence`).

## Offers
- `legsOf` (runs, a kind) → each leg of the kind's jobs, `{ matrix, shard }`, as many as the value's runs have shards (`1/1` for one); runs sharing a value that disagree on their shards are refused.
- `legOf` (an entry, a shard) → the key of its leg; no shard, or `1/1`, is the whole entry.
- `attemptsOf` (marks, runs, this run) → each leg's last attempt; `selectReports` (reports, this commit and run, those attempts) → the reports that count: this run's, each leg and job's last attempt, none older than its leg was marked attempted in.
- `reportedOf` (reports, the expected runs and their shards) → the reports counted, the runs reported, and those that did not report, a missing shard named with its run (`<entry> (shard i/n)`).

## Invariants
- A run reports when one report ran it whole, or each of its shards has a report; a report of a shard of another count than its run's is not counted.
- It reads a report's entry and shard alone, by shape: it imports nothing of `evidence`.

## Depends on
- None.
