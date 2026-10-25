# dialog

Internal module of `interop-clients`: one flow's exchange with an adapter.

## Responsibilities
- Starts an adapter, gives it the flow's instruction, answers what it asks mid-flow, and reads how the flow ended.

## Offers
- `converse`: the adapter's command, the instruction, the answerer and a time limit → the outcome (the adapter's result, or its error's type and message), every line both ways, and what it wrote on its error stream.

## Invariants
- Each line is one JSON object: the instruction goes in first; each line out is an `ask`, answered by one line in, or a `result` or an `error`, which ends the flow.
- A line that is no JSON object or none of those, an exit before the end, an answer that fails, or the time running out ends the flow as a `protocol` error.
- Lines after the end are no part of the flow.
