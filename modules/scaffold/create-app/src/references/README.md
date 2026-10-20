# references

## Responsibilities
- Generates the workspace's references from what each module declares: the configuration reference, each package's `reference.conf`, the audit event reference, and the route reference.
- Holds each section's schema to the rules its defaults, time and size keys follow.

## Not here
- What a key means, its bounds and its default: the section's owner, in its schema.
- The fragments and the variable each key reads: `create-app`'s.

## Offers
- `pnpm --filter @mod/create-app run configuration`: writes the configuration reference, the audit event reference, the route reference, and a `reference.conf` beside each package's manifest whose module has a section.
- The configuration reference: each section's keys from its schema (type, bounds, default, whether required, description) and its fragment (example, variable).
- The configuration reference's client metadata sections: each section modules add to client records, by the package that adds it, as the full template with every opt-in composes it on the trial's settings.
- The configuration reference's IdP type settings: what one IdP under `federation`'s `idps` holds for each type, by the package that adds the type, composed alike.
- `reference.conf`: the section's keys as HOCON, each with its description as a comment; a key with a default as `key = value` (a time or size bare, `5m`), one without as a comment saying whether it is required. The module applies its defaults itself; no app loads the file.
- The audit event reference: each module's events as its `./audit-events` declares them through `audit`.
- The route reference: each route the full template with every opt-in serves, composed alike: its method, path, the package it is from, the bodies it takes, its policies in order, whether it changes state, what keeps other sites' requests out and what limits it by source (a marked policy or its reason), and whether it takes cross-origin requests. What a route answers stays in its package's card, as do the paths under a `*`.

## Invariants
- Each reference is held to the committed file; a file that differs fails, naming the command.
- A key with no description fails.
- A fragment's key read from env must be a fixed key of its section: one under a map whose names are the operator's (a record) fails, naming the fragment, as its variable would carry the example's name.
- Every `.prefault` value reads through its key's own schema.
- In every section, a time or size key is read by `kernel`'s `setting.duration` or `setting.size` (a bare number refused) under a name with no unit (`-seconds`, `-ms`, `-bytes`), and a default is a `.prefault`, never a `.default()`.
- A failure of the time, size and prefault rules names the key and the rule it breaks.
- A kind two modules declare must be declared alike in the audit event reference.
- Client metadata sections and IdP types' settings are held to the same rules as the sections: a description for every key, the time and size keys, and `.prefault`.
- The full template is assembled with the memory store in place of Redis, which is asked at assembly, and never started.

## Depends on
- `create-app`'s workspace's package list, fragments and generation; `trial`'s layer; `combinations` (the full template and its opt-ins); `kernel`, to assemble it; `clients`' metadata sections, `upstreams`' IdP types and `http`'s routes and marks, read from their contracts; the HOCON library, to read a written `reference.conf` back; `kernel`'s `setting`, the form its tests hold time and size keys to.
