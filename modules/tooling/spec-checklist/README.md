# spec-checklist

## Responsibilities
- Holds the checklist of the specifications this provider implements: each requirement on the authorization server as an item, and, for each spec's version, a ledger tying every requirement keyword in its text to items or to the reason it is not one.
- Reads which tests name which items, and refuses an item ID written anywhere else.
- Writes the compliance report from the checklist and those tests.
- Decides whether an accepted difference in a run against another implementation may be taken (`exceptionProblems`).

## Not here
- The tests that check a requirement: the owning module's, or its area's conformance scenes.
- Running tests, and whether an item's tests passed in a run.
- The text of the specifications: kept outside the repository, read by `run ledger`.

## Offers
- `checklist/<spec>.md`: the items, under `## <section> <title>`, each `- **<id>** <MUST|MUST NOT|SHOULD|SHOULD NOT>: <the requirement, in our words>`, with at most one of `out-of-scope: <reason>`, `deviates: <decision>` (a SHOULD's), `noncompliant: <issue>` (a MUST's), and `updates: <ids>` (an earlier spec's items it updates, none weaker), each on its own line indented by two spaces.
- An item's ID is `<spec>-<section>-<letter>`, the spec `rfc<number>`, `oidc-core`, `oidc-discovery`, `oidc-rpinit` or `oidc-bcl`, the letters `a` to `z` then `aa` to `zz` within a section; it never changes once written.
- An item's strength is its keyword's as the spec writes it; a MUST NOT or SHOULD NOT item states, in the affirmative, what must not happen.
- `checklist/<spec>.ledger.md`: the spec's source URL, version and the SHA-256 of its plain text, then a row per keyword occurrence, `- <section> #<n> <keyword>: <ids>` or `: excluded <client-only|rs-only|definition|iana|example|deployment|not-a-bearer-route: route|restates <id>|other: reason>`.
- `checklist/decisions.md`: the decisions a `deviates:` or an exception names, `- **D-<n>** <date> (<who>): <what>`.
- A test names the items it checks in its title, as `[<id>]`; a `describe` names them for every test in it.
- `pnpm --filter @mod/spec-checklist run report` writes the report to `docs/compliance`; `run check` prints every finding; `run ledger <spec> <text file>` compares a ledger with the spec's plain text.
- `readChecklist` (the items, ledgers and decisions as written) and `exceptionProblems` (an exception and the items → why it may not be taken).

## Invariants
- An item's line, its marks and its heading follow the forms above; an ID is of its file's spec and of the section it is written under, once only.
- `deviates` is a SHOULD's alone and names a decision the decisions hold; `noncompliant` is a MUST's alone.
- A ledger row names items of its own spec whose strength is its keyword's (MUST, REQUIRED and SHALL as MUST; SHOULD and RECOMMENDED as SHOULD), or excludes it by one of the reasons above; every item is named by a row; a section's rows are numbered from 1 in order.
- An ID is taken only from the first argument of `it`, `test` or `describe` (through `.each`, `.runIf`, `.skipIf`, `.only` and the like, and the calls they return), a string with no substitution, in a file ending `.test.ts` or `.case.ts`, written in brackets. An ID written anywhere else in a workspace package's sources is a finding; so is one naming no item, or an out-of-scope item.
- The report is held to the committed `docs/compliance`; a report that differs fails, naming the command.
- `run ledger` reads plain text as RFCs print it: page heads and feet dropped, whitespace joined (a phrase split across lines or pages is one), a section from a numbered heading at a line's start (`Appendix A` as `A`), text before the first as `front`, the longer phrase first (`MUST NOT`, `NOT RECOMMENDED`).
- An exception for an item's mark names that item, marked so; an adaptation's or a third party's names no item, and carries its name or an https issue URL.

## Data
- The checklist files above, and the report it writes; nothing else is kept.

## Depends on
- `guard-imports` (the workspace's packages and files), `typescript` (reading test titles).

## Vocabulary
- item: one requirement the authorization server must meet, from one spec.
- ledger: a spec version's keyword occurrences, each tied to items or excluded with its reason.
- mapped: an item a test names; hole: an item in scope no test names.
