import type { RefreshTokenFamily } from "./types.mjs";
/**
 * The longest an access token carrying a family's `family_id` can live, in
 * milliseconds: `oauth.accessToken.maxExpiresIn`, read through
 * `resolveAccessTokenLifetime`, which refuses a configuration that has no
 * lifetime rather than letting a horizon be computed from nothing.
 */
export declare function resolveFamilyAccessTokenHorizonMs(config: unknown): number;
/**
 * The expiry to commit for a family being revoked at `nowMs`: the later of
 * its own expiry and `nowMs + accessTokenHorizonMs`, plus
 * `REVOCATION_RETENTION_ALLOWANCE_MS` — rounded up to a whole millisecond,
 * since the Redis adapter writes it as `PX` and reads a stored family's
 * `expiresAtMs` back only as an integer.
 */
export declare function revokedFamilyExpiresAtMs(family: Pick<RefreshTokenFamily, "expiresAtMs">, nowMs: number, accessTokenHorizonMs: number): number;
/**
 * The `accessTokenHorizonMs` a wrapper was handed, or a construction error
 * naming it: a horizon that is not a positive lifetime would keep a revoked
 * record no longer than before.
 */
export declare function assertAccessTokenHorizonMs(value: unknown, factory: string): number;
//# sourceMappingURL=retention.d.mts.map