# client-allowance

## Responsibilities
- Decides what a client may be issued and may see: its grants, scopes and audiences.
- Owns the client metadata section that holds them.

## Not here
- How a refusal is answered (`unauthorized_client`, `invalid_scope`, `invalid_target`): each caller's.
- The audience a request asks for within what is allowed: `token-endpoint`'s target rule.
- Where a client's record comes from: `clients` and its sources.

## Offers
- `clientAllowance`, decisions over a client's section:
  - `allowsGrant`: a grant is allowed only when its allowed grants list it; `grantsOf` answers that list, as a boot check that compares it with the grants composed reads it.
  - `allowsScope`: one scope is allowed only when its allowed scopes list it.
  - `allowedIssuance`: the scope and audience for a requested scope. No scope asked gives the defaults; an explicit empty default gives no scope, and no default at all is refused while scopes are allowed. A scope outside the allowed ones is refused. The audience is the first allowed one, else the issuer.
  - `covers`: an earlier issuance (`Issued`) has every scope allowed, and exactly one audience the client may be issued.
  - `allowsAudience`: any allowed audience, or the issuer when none is allowed.
  - `maySee`: the audience includes an allowed audience or the client's own id.
  - `parseScope`: RFC 6749 scope tokens joined by single spaces; an empty value names none, as when left out.
  - `allowedIssuanceWithin` and `allowsAudienceWithin`: the same within ceilings (`Ceiling`, a `scopes` and an `audiences` list, each optional). Each list a ceiling holds narrows the client's, its defaults and the issuer's audience among them, and an empty one allows nothing; a default narrowed to none is refused, and no audience left is `invalid_target`.
  - `allowancesWithin`: the section entry for a client asking within a ceiling. Each list keeps what both hold, and a list not asked is the ceiling's. Refused when the asked audiences leave none of a ceiling that names some, since none means the issuer.
- `AllowanceLists`: the grants, scopes and audiences lists a ceiling and a request name.
- Client metadata section `client-allowance`: `grants`, `scopes`, `audiences` (default empty, allowing nothing), `default-scopes` (unwritten means "not set", which differs from an explicit empty value). Readers do not interpret the values themselves; they use `clientAllowance`.
- For tests (`./testing`): `allowancesFor`, a test client's sections holding the given allowances.

## Invariants
- A client without the section is allowed nothing; an unknown field in it refuses the client's record.
- `offline_access` in `scopes` or `default-scopes` refuses the client's record at that entry: offline access is not offered, so it would allow nothing.
- Decisions are pure: no failure, no state.
- `allowancesWithin` never widens the ceiling.

## Data
- None, so it is safe on many instances.

## Depends on
- `kernel`, `clients`

## Vocabulary
- allowance: what a client may be issued: grants, scopes and audiences.
- ceiling: the most a client from a source may be allowed.
