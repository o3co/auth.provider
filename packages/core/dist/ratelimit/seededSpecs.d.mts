import type { RateLimitSpec } from "./types.mjs";
/**
 * Every per-endpoint spec that lives in its own config slice, seeded into an
 * adapter's `limits` in one call.
 *
 * Both bundled adapter modules (memory here, redis in
 * `@o3co/auth-provider-redis`) call this rather than each seed individually,
 * so a spec seeded into one adapter cannot be forgotten in the other — which
 * is how `device_verification` went unseeded in both while `login` was
 * seeded in each. An operator-declared entry for any prefix still wins; see
 * the individual resolvers.
 */
export declare const resolveSeededLimitSpecs: (limits: Readonly<Record<string, RateLimitSpec>>, config: unknown) => Record<string, RateLimitSpec>;
//# sourceMappingURL=seededSpecs.d.mts.map