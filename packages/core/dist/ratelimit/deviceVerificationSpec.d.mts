import type { RateLimitSpec } from "./types.mjs";
/**
 * The key prefix `POST /oauth/device/verification` limits under
 * (`device_verification:user:<subject>`). Defined here, in core, so the seed
 * below and the endpoint that keys on it share one name;
 * `@o3co/auth-provider-device-grant` re-exports it rather than restating it.
 */
export declare const DEVICE_VERIFICATION_RATE_LIMIT_PREFIX = "device_verification";
/**
 * Seed a rate-limiter adapter's `limits` with the device-verification spec
 * drawn from `config.oauth.deviceAuthorization.rateLimit`.
 *
 * RFC 8628 §5.1 sizes the user code's entropy *against* a rate limit — its
 * worked example reaches 2^-32 only where "the rate-limiting interval and
 * validity period would need to only allow 5 attempts" — and the device-grant
 * module refuses to boot without a limiter on exactly that argument. But the
 * adapters resolve a spec by key prefix from their own `limits` map, and
 * nothing seeded `device_verification`, so the key fell through to the
 * adapter's `defaultLimit` of 60/60s: twelve times the budget the boot
 * refusal reasons from, silently, on the one endpoint whose whole job is
 * resisting code guessing. The package README meanwhile documented a key that
 * nothing read.
 *
 * Same shape as `resolveLoginLimitSpec` (#270): one config key that is the
 * source of truth, seeded into each adapter unless the operator declared the
 * prefix explicitly — an explicit `limits.device_verification` is a statement
 * about this adapter and wins.
 *
 * The values are screened structurally even though the device-grant schema
 * validates them: a hand-built config never passed that schema, and a limit
 * invented from `0` or `"5"` is worse than the adapter's own default.
 *
 * @param limits  The adapter's own configured limits.
 * @param config  The full application config (only
 *                `oauth.deviceAuthorization.rateLimit` is read).
 */
export declare const resolveDeviceVerificationLimitSpec: (limits: Readonly<Record<string, RateLimitSpec>>, config: unknown) => Record<string, RateLimitSpec>;
//# sourceMappingURL=deviceVerificationSpec.d.mts.map