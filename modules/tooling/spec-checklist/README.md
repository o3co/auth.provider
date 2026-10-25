# spec-checklist

## Responsibilities
- Holds the checklist of the specifications this provider implements: each requirement on a role the server takes as an item, and, for each spec's version, a ledger tying every requirement keyword in its text to items or to the reason it is not one.
- Reads which tests name which items, and refuses an item ID written anywhere else.
- Writes the compliance report from the checklist and those tests.
- Decides whether an accepted difference in a run against another implementation may be taken (`exceptionProblems`).
- Its internal module `evidence` tells what a CI run's tests proved of each item, from the reports its vitest reporter writes.

## Not here
- The tests that check a requirement: the owning module's, or its area's conformance scenes.
- Running tests.
- The text of the specifications: kept outside the repository, read by `run ledger`.

## Offers
- `checklist/<spec>.md`: the items, under `## <section> <title>`, each `- **<id>** <MUST|MUST NOT|SHOULD|SHOULD NOT>: <the requirement, in our words>`, with at most one of `out-of-scope: <reason>`, `deviates: <decision>` (a SHOULD's), `noncompliant: <issue>` (a MUST's), and `updates: <ids>` (an earlier spec's items it updates, none weaker) and `role: <role>`, each on its own line indented by two spaces.
- An item's ID is `<spec>-<section>-<letter>`, the spec `rfc<number>`, `oidc-core`, `oidc-discovery`, `oidc-rpinit` or `oidc-bcl`, the letters `a` to `z` then `aa` to `zz` within a section; it never changes once written.
- An item's role is the role of the server's it binds: `as` (authorization server), `op` (OpenID Provider), `rs` (resource server at its own protected routes), `rp` (relying party to an upstream IdP) or `client` (client sending tokens or assertions out). It is its `role:` line's, else the file's head line `- role: <role>`, else an OpenID spec's `op` and an RFC's `as`.
- An item's strength is its keyword's as the spec writes it; a MUST NOT or SHOULD NOT item states, in the affirmative, what must not happen.
- `checklist/<spec>.ledger.md`: the spec's source URL, version and the SHA-256 of its plain text, then a row per keyword occurrence, `- <section> #<n> <keyword>: <ids>` or `: excluded <other-role: the role|client-only|rs-only|definition|iana|example|deployment|not-a-bearer-route: route|restates <id>|other: reason>`; `other-role` names a role the server does not take, such as a native app.
- `checklist/decisions.md`: the decisions a `deviates:` or an exception names, `- **D-<n>** <date> (<who>): <what>`.
- A test names the items it checks in its title, as `[<id>]`; a `describe` names them for every test in it.
- `pnpm --filter @mod/spec-checklist run report` writes the report to `docs/compliance`: a page per spec, each item with its role, and a README of fixed text; `run summary` prints the summary over every spec, by spec and by role, which is not kept; `run check` prints every finding; `run ledger <spec> <text file>` compares a ledger with the spec's plain text.
- `readChecklist` (the items, ledgers and decisions as written) and `exceptionProblems` (an exception and the items → why it may not be taken).
- `./testing`: `evidenceReporter`, a vitest reporter writing a run's results for `run compliance`; `run expected` and `run compliance` (the `evidence` card).

## Invariants
- An item's line, its marks and its heading follow the forms above; an ID is of its file's spec and of the section it is written under, once only. A mark belongs to the item just above it in its section, none after a heading or a refused item; an item has one `updates` line and one `role` line at most, and a file one head `role` line at most, a role one of the five.
- `deviates` is a SHOULD's alone and names a decision the decisions hold; `noncompliant` is a MUST's alone.
- A ledger row names items of its own spec whose strength is its keyword's (MUST, REQUIRED and SHALL as MUST; SHOULD and RECOMMENDED as SHOULD), or excludes it by one of the reasons above, a row that restates an item naming one whose strength is its keyword's; every item is named by a row; a section's rows are numbered from 1 in order.
- An ID is taken only from a test's title, written in brackets: the first argument, a plain string, of a call of `it`, `test` or `describe` that takes the title, directly, through `.only`, `.skip`, `.concurrent` and the like, or as the function `.each`, `.for`, `.runIf` and `.skipIf` return (`.each` and `.for` given their table as a tagged template too); their own arguments and tables are no title. Only files ending `.test.ts` or `.case.ts` hold titles.
- Strings are read decoded, the rest of a source as written. Anything written like an ID (a spec's name, a dash and more) anywhere else in a workspace package's sources, or malformed, is a finding; so is an ID naming no item, or an out-of-scope item.
- The report is held to the committed `docs/compliance`; a report that differs fails, naming the command.
- `run ledger` holds the checklist to its rules first, and matches each place once: a place the ledger writes twice never matches. It reads plain text as RFCs print it: page heads and feet dropped, whitespace joined (a phrase split across lines or pages is one), a section from a numbered heading at a line's start (`Appendix A` as `A`), text before the first as `front`, the longer phrase first (`MUST NOT`, `NOT RECOMMENDED`).
- An exception for an item's mark names that item, marked so, a deviation's a SHOULD with a decision the decisions hold; an adaptation's or a third party's names no item, and carries its name or an https issue URL.

## Data
- The checklist files above, and the report it writes; nothing else is kept.

## Depends on
- `guard-imports` (the workspace's packages and files), `typescript` (reading test titles).

## Vocabulary
- item: one requirement the authorization server must meet, from one spec.
- ledger: a spec version's keyword occurrences, each tied to items or excluded with its reason.
- mapped: an item a test names; hole: an item in scope no test names.
