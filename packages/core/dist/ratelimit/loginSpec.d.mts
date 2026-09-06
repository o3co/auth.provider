import type { RateLimitSpec } from "./types.mjs";
/**
 * Seed a rate-limiter adapter's `limits` with the login spec drawn from
 * `config.rateLimit.login`.
 *
 * `/session/login` runs on the shared `RateLimiter`, keyed `login:ip:<ip>`
 * (#270). Adapters resolve a spec by key prefix from their own `limits` map,
 * but the documented login window and limit live in a different config slice —
 * `rateLimit.login`, in milliseconds. Left unseeded, a `login:` key falls
 * through to the adapter's `defaultLimit` of 60/60s: **weaker** than the
 * documented 20 / 15 min, silently, on the one endpoint whose whole job is
 * resisting password guessing.
 *
 * Seeding keeps `rateLimit.login` the single source of truth. Restating the
 * value under each adapter's `limits` instead would be two numbers that must
 * agree, which is the drift bug rather than a fix for it.
 *
 * An operator-declared `limits.login` wins: that is an explicit statement about
 * this adapter, and overwriting it would discard what they wrote. The tradeoff
 * is that an operator reading `limits` alone sees no `login` entry while login
 * *is* limited — `reference.conf` documents this beside both `limits` blocks
 * and beside `rateLimit.login`.
 *
 * @param limits  The adapter's own configured limits.
 * @param config  The full application config (only `rateLimit.login` is read).
 */
export declare const resolveLoginLimitSpec: (limits: Readonly<Record<string, RateLimitSpec>>, config: unknown) => Record<string, RateLimitSpec>;
//# sourceMappingURL=loginSpec.d.mts.map