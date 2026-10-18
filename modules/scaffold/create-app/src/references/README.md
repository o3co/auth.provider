# references

## Responsibilities
- Generates the workspace's references from what each module declares: the configuration reference, each package's `reference.conf`, and the audit event reference.
- Holds each section's schema to the rules its defaults, time and size keys follow.

## Not here
- What a key means, its bounds and its default: the section's owner, in its schema.
- The fragments and the variable each key reads: `create-app`'s.

## Offers
- `pnpm --filter @mod/create-app run configuration`: writes the configuration reference, the audit event reference, and a `reference.conf` beside each package's manifest whose module has a section.
- The configuration reference: each section's keys from its schema (type, bounds, default, whether required, description) and its fragment (example, variable).
- `reference.conf`: the section's keys as HOCON, each with its description as a comment; a key with a default as `key = value` (a time or size bare, `5m`), one without as a comment saying whether it is required. The module applies its defaults itself; no app loads the file.
- The audit event reference: each module's events as its `./audit-events` declares them through `audit`.

## Invariants
- Each reference is held to the committed file; a file that differs fails, naming the command.
- A key with no description fails, outside the sections listed as described later.
- Every `.prefault` value reads through its key's own schema.
- In every section, a time or size key is read by `kernel`'s `setting.duration` or `setting.size` (a bare number refused) under a name with no unit (`-seconds`, `-ms`, `-bytes`), and a default is a `.prefault`, never a `.default()`.
- A section listed as described later leaves the list once it describes every key, and never comes back. A failure of the time, size and prefault rules names the key and the rule it breaks.
- A kind two modules declare must be declared alike in the audit event reference.

## Depends on
- `create-app`'s workspace's package list and fragments; the HOCON library, to read a written `reference.conf` back; `kernel`'s `setting`, the form its tests hold time and size keys to.
