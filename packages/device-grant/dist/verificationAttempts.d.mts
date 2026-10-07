/**
 * `POST /oauth/device/verification`'s own attempt limit: the tag its attempts
 * are counted under (`device_verification:user:<subject>`), and
 * `device-grant.rateLimit` read as the spec the attempt guard counts them
 * against — the limit RFC 8628 §5.1 sizes the user code against. The limit is
 * the device-grant module's alone: no rate limiter's budget, failMode or
 * outage changes it.
 */
import { type AttemptSpec } from "@o3co/auth-provider-core";
/** The tag the verification endpoint counts attempts under, and the rate-limit prefix the module claims. No `:`. */
export declare const DEVICE_VERIFICATION_ATTEMPT_TAG = "device_verification";
/**
 * `device-grant.rateLimit` (`{ limit, windowSeconds }`) as an attempt spec.
 * Fields read as the schema coerces them; a missing or unusable value, a
 * window over a day included, is a `RangeError` naming the key.
 */
export declare function readVerificationAttemptSpec(section: unknown): AttemptSpec;
//# sourceMappingURL=verificationAttempts.d.mts.map