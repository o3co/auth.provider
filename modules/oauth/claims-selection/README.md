# claims-selection

## Responsibilities
- Decides which claim names a `claims` request parameter may release (OpenID Connect Core §5.5), by the client's allowance and the subject's consent, and keeps that selection and its value constraints for the code, the refresh family and each access token they give.

## Not here
- Reading the `claims` parameter and which claims a name stands for (`authorize`, `oidc`). Judging consent (whoever contributes it). Releasing claims and checking values against constraints (`oidc`).

## Offers
- Contract `claimsSelections`:
  - `select`: the names whose scope the client is allowed (`client-allowance`) and the subject agreed to; every constraint kept, since constraints only hold back.
  - `keepForCode`, by the redemption's name, for the code's lifetime and a minute more.
  - `forCode`: the selection pinned to a redemption; none for a code without one.
  - `forToken`: the userinfo target kept for an access token; none for a token without one.
  - `follow`: the pinned userinfo target kept for the family founded from a redemption.
  - `forRefreshed`: a refreshed token kept its family's target, its names cut to what is allowed and agreed to now.
- `selectionLimits` and the types `Selection`, `Target`, `Named`, `Constraint` and `Scalar`.
- Extension point: the judge of consent, `consented(client, subject, scope)`; two refuse boot.
- Contribution to `code-grant`'s redemption hooks: the pin, and a redeemed code's token kept the pinned userinfo target.
- Contribution to `grants`' token ties: a token with constraints ties a token exchanged from it, which keeps those constraints and none of its names.
- Store interface, wired by the assembly: records by name, each kept once for its lifetime.

## Invariants
- A selection holds only scalar values: strings up to 256 characters, booleans and finite numbers; `value` or a non-empty `values` of up to 16, never both; 4 KiB whole. Another is a `TypeError`.
- Without a judge of consent, no name is agreed to.
- A pin copies the code's selection, or marks it none, and holds it five minutes; the redemption's other reads use only the pin. A pin gone fails the read, never answering none.
- A code still alive at its pin finds its selection, which outlives the code by a minute; a code past its life is refused by `code-grant` before anything reads its pin.
- A family's target is written once and never cut: each refresh cuts the names from it again, so a name allowed and agreed to again comes back, as a scope does.
- A record of another format or shape fails the read, never answered as none.
- Writes and reads that fail throw to the caller.

## Data
- Records: a code's selection for the code's lifetime and a minute; a pin for five minutes; a family's target until the family's end; a token's target until the token's end and two minutes, for clock drift between hosts.
- Needs: no eviction, a crash survived, no rollback on failover; a lost record would let a constrained claim go out unconstrained.

## Depends on
- `kernel`, `clients`, `client-allowance`, `code-grant`, `grants`

## Vocabulary
- Selection: what a request releases beyond its scope (names) and what it holds back (constraints), by target.
- Target: the ID token or userinfo.
- Pin: a redemption's copy of its code's selection, read through that one exchange.
