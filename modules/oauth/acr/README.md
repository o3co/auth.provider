# acr

## Responsibilities
- Holds the acr table: the operator's, and the entries modules offer by themselves.
- Answers, for the acr a request asks for, which ones the table knows and which one a session's amr meet.
- Checks at boot that a declared way of logging in can meet every acr in the table.
- Names the offered acr among `issuer`'s metadata items.

## Not here
- The authorization endpoint's decisions, and where to send the browser when unmet: `authorize`.
- What each amr value means: the giving side's.
- Which amr a login can produce: `login-gates`.

## Offers
- `acr`: the known acr among the request's `acr_values`, in the order asked; the first of them a session's amr meet.
- Extension point: table entries, an acr and the amr sets that meet it, keyed by acr; `isAmrSets` is the rule they follow.
- Contribution to `issuer`'s metadata: `acr_values_supported`, the operator's table in its written order, then the entries; left out when empty.
- Operator section: `values`, each acr and the amr sets that meet it, each set and each list non-empty; default empty.
- Test configuration builders (`./testing`).

## Invariants
- An acr is met when a session holds every amr of any one of its sets.
- The first acr asked that is met wins; acr have no order of strength.
- An acr is known only by its exact name as an own entry of the table.
- The operator's table wins over an entry offered for the same acr.
- An offered entry's sets follow the operator's rule, non-empty sets in a non-empty list; boot is refused for any other.
- Boot is refused when an acr in the table has no set a declared way of logging in can meet.

## Data
- The table, read once at boot; nothing is stored.

## Depends on
- `kernel`, `login-gates`, `issuer`

## Vocabulary
- table: for each acr, the amr sets that meet it.
