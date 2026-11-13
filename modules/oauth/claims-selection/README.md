# claims-selection

## Responsibilities
- Decides which claim names a `claims` request parameter may release (OpenID Connect Core §5.5), by the client's allowance and the subject's consent, and keeps that selection and its value constraints for the code, the refresh family and each access token they give.

## Not here
- Reading the `claims` parameter and which claims a name stands for (`authorize`, `oidc`). Judging consent (whoever contributes it). Releasing claims and checking values against constraints (`oidc`).

## Offers
- Contract `claimsSelections`:
  - `scopeOf`: a claim's scope, as the contributed table of claim scopes tells it; none without one.
  - `select`: the names whose scope the client is allowed (`client-allowance`) and the subject agreed to; every constraint kept, since constraints only hold back.
  - `keepForCode`, by the redemption's name, for the code's subject, for the code's lifetime and a minute more.
  - `forCode`: the selection pinned to a redemption; none for a code without one.
  - `forToken`: the userinfo target kept for an access token; none for a token without one.
  - `follow`: the pinned userinfo target kept for the family founded from a redemption, for the pin's subject.
  - `forRefreshed`: a refreshed token kept its family's target, its names cut to what is allowed and agreed to now.
- `selectionLimits`, `withinLimits` (whether a selection keeps within them) and the types `Selection`, `Target`, `Named`, `Constraint` and `Scalar`.
- Extension points, two of either refusing boot: the judge of consent, `consented(client, subject, scope)`; the table of claim scopes, `scopeOf(claim)`, from the module releasing claims.
- Contribution to `code-grant`'s redemption hooks: the pin, for the code's subject, and a redeemed code's token kept the pinned userinfo target, for the pin's subject.
- Contribution to `grants`' token ties: a token with constraints ties a token exchanged from it, which keeps those constraints and none of its names.
- Store interface, wired by the assembly: records by name, each kept once for its lifetime, through exactly one of `create`, for its subject, and `save`; `erase` and `migrate` together or neither, optional until 0.22; another set refuses the boot. `./testing` holds its contract test for every implementation (`selectionRecordsContract`, through faults), and claims-selection composed over records in memory (`claimsSelectionInMemory`), which a test may wrap.

## Invariants
- A selection holds only scalar values: strings up to 256 characters, booleans and finite numbers; exactly one of `value` and a non-empty `values` of up to 16; 4 KiB whole. These are fixed, as a selection is stored and read back under the same bounds. Another is a `TypeError`.
- Without a judge of consent, no name is agreed to.
- An empty pin means the code had no selection kept, never that claims requests are not taken; every redemption is pinned.
- A pin copies the code's selection, or marks it none, and holds it five minutes; the redemption's other reads use only the pin. A pin gone fails the read, never answering none.
- A code still alive at its pin finds its selection, which outlives the code by a minute; a code past its life is refused by `code-grant` before anything reads its pin.
- A family's target is written once and never cut: each refresh cuts the names from it again, so a name allowed and agreed to again comes back, as a scope does.
- A record is read in format 2, which keeps its subject and which 0.19.x fails closed on, or in 0.19's format 1, keeping none: for a code, a pin and a token until 0.22, for a family's target until the first release past refresh's family-lifetime ceiling after the last 0.19 instance stopped. One of another format or shape fails the read as unavailable, as a read the place cannot answer does; never answered as none.
- Writes and reads that fail throw to the caller. A write past its subject's erasure fails as unavailable, except a join, which answers false; a record's own subject wins, and a caller's that differs fails as unavailable. A redemption's writes take the pin's subject: a pin without one is a defect, unavailable. A write without its subject to a store filing by subject is the caller's bug, a `TypeError`.

## Data
- Records: a code's selection for the code's lifetime and a minute, so a code still alive finds it; a pin for five minutes, a fixed margin over the one exchange it covers; a family's target until the family's end; a token's target until the token's end and two minutes, for clock drift between hosts.
- Needs: no eviction, a crash survived, no rollback on failover; a lost record would let a constrained claim go out unconstrained.

## Depends on
- `kernel`, `clients`, `client-allowance`, `code-grant`, `grants`, `erasure-extensions`

## Vocabulary
- Selection: what a request releases beyond its scope (names) and what it holds back (constraints), by target.
- Target: the ID token or userinfo.
- Pin: a redemption's copy of its code's selection, read through that one exchange.
