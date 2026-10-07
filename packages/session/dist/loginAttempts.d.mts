/**
 * `POST /session/login`'s own attempt limit: the tag its attempts are counted
 * under (`login:ip:<ip>`), and `session.rateLimit.login` read as the spec the
 * attempt guard counts them against. The limit is the session module's alone:
 * no rate limiter's budget, failMode or outage changes it.
 */
import { type AttemptSpec } from "@o3co/auth-provider-core";
/** The tag `/session/login` counts attempts under, and the rate-limit prefix the module claims. No `:`. */
export declare const LOGIN_ATTEMPT_TAG = "login";
/** The longest `session.rateLimit.login.windowMs`: the longest window a counter takes. */
export declare const MAX_LOGIN_WINDOW_MS: number;
/**
 * `session.rateLimit.login` (`{ windowMs, limit }`) as an attempt spec, the
 * window rounded up to whole seconds, so a window is never shorter than
 * configured. Fields read as the schema coerces them; a missing or unusable
 * value is a `RangeError` naming the key.
 */
export declare function readLoginAttemptSpec(section: unknown): AttemptSpec;
//# sourceMappingURL=loginAttempts.d.mts.map