# Checklist files

The forms of the files in this directory, which `spec-checklist` reads and holds to its card's rules. `decisions.md` and `notes.md` give their own forms in their heads.

- `checklist/<spec>.md`: the items, under `## <section> <title>`, each `- **<id>** <MUST|MUST NOT|SHOULD|SHOULD NOT>: <the requirement, in our words>`, with at most one of `out-of-scope: <reason>`, `deviates: <decision>` (a SHOULD's), `noncompliant: <issue>` (a MUST's), and `updates: <ids>` (an earlier spec's items it updates, none weaker), `role: <role>` and `note: <N-name>` (a note it shares with other items), each on its own line indented by two spaces.
- `checklist/<spec>.ledger.md`: the spec's source URL, version and the SHA-256 of its plain text, then a row per keyword occurrence, `- <section> #<n> <keyword>: <ids>` or `: excluded <other-role: the role|client-only|rs-only|definition|iana|example|deployment|not-a-bearer-route: route|restates <id>|other: reason>`; `other-role` names a role the server does not take, such as a native app.
