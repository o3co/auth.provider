# Findings and fixes

How a finding, from a review or an audit, is kept until it is fixed, and what each fix records. This page holds the form and the steps alone: the ledger and the records of unfixed findings are private.

## Nothing public before the fix is released

A finding not yet fixed shows nowhere public: not its text, nor the pull request that fixes it, the modules or contracts it changes, or its tests, any of which can tell where the hole is (`SECURITY.md`).

- The fix is made in the security advisory's temporary private fork, as a private pull request, its change record kept private too.
- GitHub runs no Actions in a temporary private fork, so the checks that hold the guarantees are run again on the fix's branch on a private machine, and their evidence (the commands, the environment, the commit, the results) kept in its change record: the whole test suite, the conformance areas and patterns, the checklists' compliance, the guard and the release check.
- The fix is made public with the release that carries it, and the advisory with that release.
- Once released, the change record is reviewed, then published with the advisory or in a pull request after the release. CI's run on the published commits is added to it; where it differs from the private run, a fix follows at once.

A pull request's description holds a change record in public only for a finding already fixed, or for a change that fixes no finding.

## The ledger

One line a finding, kept in a private security advisory's draft and in a private list:

| Column | What it holds |
|---|---|
| ID | `F-<year>-<n>` |
| Source | the review or audit, who, and when |
| Severity | the CVSS 4.0 score and vector |
| Where | the modules and the contracts |
| Owners | who fixes it, and the module's owner |
| Status | `open`, `fixing`, `fixed`, `accepted-risk` or `not-a-vuln` |
| Fixed in | the version |
| Change record | where its record is |
| What remains | the risk left after the fix |
| Accepted | the day the fix was reviewed and accepted |
| Retested | an independent retest (by the auditor, or by a reviewer who did not make the fix), its result and day |
| Advisory | the advisory's ID |

- A finding marked `not-a-vuln` names which of `SECURITY.md`'s "Not a vulnerability" cases it is.
- A finding marked `accepted-risk` names the owner's decision and its day, and the declaration in `docs/security-model.md` or `SECURITY.md` that states the risk: no risk is accepted in silence.

## A change record

One for each fix. The machine's rows come from `pnpm --filter @mod/guard run change-record <base> <head>`, which compares the two commits and keeps nothing; the rest are written by hand.

| Row | What it holds | Written by |
|---|---|---|
| Compared | the base and head commits and their trees | the command |
| Modules touched | the packages and internal modules added, removed, moved and changed | the command |
| Contract changes | each export added, removed, renamed, moved or changed in structure, a member's type or a member put in another's place included; and whether the owner confirmed each | the command, then by hand |
| Dependency edges | the edges between packages added and removed | the command |
| Budget measures | each of the guard's measures that moved, with its limit | the command |
| The checks run again | the conformance areas, the checklists' item statuses before and after, the guard, each with its run | by hand |
| Design review | whether the design axioms called for one, and its review | by hand |
