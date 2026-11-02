# spec-checklist

## Responsibilities
- Holds the checklist of the specifications this provider implements: each requirement on a role the server takes as an item, and, for each spec's version, a ledger tying every requirement keyword in its text to items or to the reason it is not one.
- Reads which tests name which items, and refuses an item ID written anywhere else.
- Writes the checklist report from the checklist and those tests.
- Its internal module `exceptions` decides whether an accepted difference in a run against another implementation may be taken.
- Its internal module `evidence` tells what a CI run's tests proved of each item, from the reports its vitest reporter writes.

## Not here
- The tests that check a requirement: the owning module's, or its area's conformance scenes.
- Running tests.
- The text of the specifications: kept outside the repository, read by `run ledger`.

## Offers
- `checklist/<spec>.md` and `checklist/<spec>.ledger.md`: each spec's items and its ledger, in the forms `checklist/README.md` gives.
- An item's ID is `<spec>-<section>-<letter>`, the spec `rfc<number>`, `oidc-core`, `oidc-discovery`, `oidc-rpinit`, `oidc-bcl` or `guarantee`, the letters `a` to `z` then `aa` to `zz` within a section; it never changes once written.
- An item's role is the role of the server's it binds: `as` (authorization server), `op` (OpenID Provider), `rs` (resource server at its own protected routes), `rp` (relying party to an upstream IdP) or `client` (client sending tokens or assertions out). It is its `role:` line's, else the file's head line `- role: <role>`, else an OpenID spec's `op` and an RFC's `as`.
- An item's strength is its keyword's as the spec writes it; a MUST NOT or SHOULD NOT item states, in the affirmative, what must not happen.
- The `guarantee` spec: the provider's own promises, held to the security model, not a ledger (the `guarantee` card).
- `checklist/decisions.md` and `checklist/notes.md`: the decisions a `deviates:` or an exception names, and the notes a `note:` names, each once, in the form its file's head gives. The report writes the notes in its README, linked from each item's Note cell.
- A test names the items it checks in its title, as `[<id>]`; a `describe` names them for every test in it.
- `pnpm --filter @mod/spec-checklist run report` writes the report to `docs/compliance`: a page per spec, each item with its role, and a README of fixed text; `run summary` prints the summary over every spec, by spec and by role, which is not kept; `run check` prints every finding; `run ledger <spec> <text file>` compares a ledger with the spec's plain text.
- `SPEC_CHECKLIST_DIR` and `SPEC_CHECKLIST_REPORT_DIR` (`repo.ts`): where set, the directory the checklist is read from in place of `checklist/`, and the one `run report` writes to in place of `docs/compliance`.
- `readChecklist` (the items, ledgers, decisions and notes as written) and `exceptionProblems` (the `exceptions` card).
- `./testing`: `evidenceReporter`, a vitest reporter writing a run's results for `run compliance`; `run expected`, `run plan` and `run compliance` (the `evidence` card).

## Invariants
- An item's line, its marks and its heading follow the forms `checklist/README.md` gives; an ID is of its file's spec and of the section it is written under, once only. A mark belongs to the item just above it in its section, none after a heading or a refused item; an item has one `updates` line, one `role` line and one `note` line at most, a note one the notes hold, and a file one head `role` line at most, a role one of the five.
- `deviates` is a SHOULD's alone and names a decision the decisions hold; `noncompliant` is a MUST's alone.
- A ledger row names items of its own spec whose strength is its keyword's (MUST, REQUIRED and SHALL as MUST; SHOULD and RECOMMENDED as SHOULD), or excludes it by one of the reasons above, a row that restates an item naming one whose strength is its keyword's; every item is named by a row; a section's rows are numbered from 1 in order.
- A file holds tests where it is a `.test.ts` or `.case.ts` file, or lies under a `test` directory.
- A test that names an item is known by where it is written: its suites' titles, outermost first, and its own, a suite's title that is no plain string left unknown.
- An ID is taken only from a test's title, written in brackets: the first argument, a plain string, of a call of `it`, `test` or `describe` that takes the title, directly, through `.only`, `.skip`, `.concurrent` and the like, or as the function `.each`, `.for`, `.runIf` and `.skipIf` return (`.each` and `.for` given their table as a tagged template too); their own arguments and tables are no title.
- Strings are read decoded, the rest of a source as written. Anything written like an ID (a spec's name, a dash and more) anywhere else in a workspace package's sources, or malformed, is a finding; so is an ID naming no item, or an out-of-scope item.
- The report is held to the committed `docs/compliance`; a report that differs fails, naming the command. `run report` and `run compliance` write nothing while a finding stands.
- `run ledger` holds the checklist to its rules first, and matches each place once: a place the ledger writes twice never matches. It reads plain text as RFCs print it: page heads and feet dropped, whitespace joined (a phrase split across lines or pages is one), a section from a numbered heading at a line's start (`Appendix A` as `A`), text before the first as `front`, the longer phrase first (`MUST NOT`, `NOT RECOMMENDED`).

## Data
- The checklist files above, and the report it writes; nothing else is kept.

## Depends on
- `guard-imports` (the workspace's packages and files), `typescript` (reading test titles).

## Vocabulary
- item: one requirement the authorization server must meet, from one spec.
- ledger: a spec version's keyword occurrences, each tied to items or excluded with its reason.
- mapped: an item a test names; hole: an item in scope no test names, or a guarantee's fault no test marks.
