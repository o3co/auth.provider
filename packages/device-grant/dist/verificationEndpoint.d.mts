/**
 * `POST /oauth/device/verification` — where the human answers (#298).
 *
 * RFC 8628 leaves this endpoint's shape entirely to the implementation; §3.3
 * says only that the user "visits the verification URI and enters the user
 * code". What that means concretely is a decision, and this is it:
 *
 * ### The library provides the API, the deployment provides the page
 *
 * There is no HTML here, and `verification_uri` is configuration rather than a
 * route this package mounts. That is the boundary `/authorize` already draws —
 * it redirects to a deployment-configured `loginUrl` rather than rendering a
 * login form — and drawing it differently for this one flow would mean the
 * library ships a page for one ceremony and not the other.
 *
 * ### One endpoint, three actions
 *
 * `lookup`, `approve` and `deny` are one route rather than three, because all
 * three take a `user_code` and **all three are the same brute-force oracle**.
 * §5.1 requires rate-limiting the code; a `lookup` route that answered "which
 * client is this?" without counting against the same budget would be a free
 * oracle sitting beside a limited one. One route means one limiter call, and
 * no way to add a fourth entry point that forgets it.
 *
 * ### Rate limiting is half of the security argument, not a nicety
 *
 * §5.1's own worked example: an 8-character base-20 code has "roughly 34.5
 * bits of entropy", and reaching a 2^-32 attack probability needs the
 * "rate-limiting interval and validity period ... to only allow 5 attempts".
 * The entropy and the limit are two halves of one mitigation. This endpoint
 * therefore **refuses to run without a rate limiter** rather than degrading to
 * an unlimited one — see `createDeviceVerificationHandler`.
 *
 * The limiter is keyed on the **authenticated subject**, not the code. Keying
 * on the code would count an attacker's misses against whichever code they
 * happened to hit, which is nobody's budget; keying on the subject means an
 * attacker needs an account and burns their own budget guessing.
 *
 * ### The decision is an audit event
 *
 * An approval is a consent: a named subject grants a named client a scope,
 * and a device somewhere turns that into a token. That belongs in the same
 * sink as `authorize.granted`, not in an optional `logger.info` nobody tails
 * — so `approve` emits `device.approved`, `deny` emits `device.denied`, and a
 * subject who exhausts the budget emits `device.rate_limited`, which is the
 * signal that an account is being used to guess codes. No event carries the
 * user code or the device code: one is the value being brute-forced and the
 * other is a bearer credential.
 *
 * ### Cross-site requests are the module's problem, and it handles them
 *
 * This handler never sees a body parser or an origin check; the router
 * `deviceGrantModule` mounts is JSON-only and runs the session package's
 * CSRF guard ahead of it (RFC 8628 §5.4 — see `module.mts`). A composition
 * that mounts this handler by hand must do the same.
 */
import type { RateLimiter } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import { type DeviceGrantDependencies } from "./types.mjs";
export interface DeviceVerificationHandlerOptions extends DeviceGrantDependencies {
    /**
     * Required. See the file header: the code's entropy budget is calculated
     * against a limit, so running without one is running with 34.5 bits and no
     * ceiling.
     */
    readonly rateLimiter: RateLimiter;
}
export declare const createDeviceVerificationHandler: (options: DeviceVerificationHandlerOptions) => RequestHandler;
//# sourceMappingURL=verificationEndpoint.d.mts.map