/**
 * A verified id_token's `auth_time` as an instant: `undefined` when the claim
 * is absent; its whole seconds since the epoch, a fraction floored — OIDC
 * allows one, and flooring never answers an instant later than the claim;
 * `"invalid"` for a value that is not a finite number, is negative, or lies
 * more than `aheadToleranceMs` (default `DEFAULT_CLOCK_SKEW_MS`) ahead of
 * `nowMs`, which would read as fresher than any ask. An adapter whose library
 * tolerates more clock skew passes its own tolerance. An adapter fails the
 * login on `"invalid"`. Throws a `RangeError` only for a clock that is not a
 * finite number or a tolerance that is not a finite duration ≥ 0.
 */
export declare function readUpstreamAuthTime(claim: unknown, nowMs?: number, aheadToleranceMs?: number): Date | undefined | "invalid";
//# sourceMappingURL=upstream-auth-time.d.mts.map