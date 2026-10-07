/**
 * The browser flow's one reading of each value it takes from a request: a
 * parameter, the express session id, the cookie's claim, whether it is a
 * prefetch or a step-up trip's return, and the callback's parameters for the
 * adapter. Reads only. A single parameter that is not a non-empty string is
 * absent; the callback's parameters keep every string value, empty ones
 * included, except `code` and `state`.
 */
import { type SessionClaim } from "@o3co/auth-provider-core";
import type { Request } from "express";
export declare const single: (value: unknown) => string | undefined;
/** The express session's own id: one half of the browser binding, the durable `sid` the other. */
export declare const sessionIdOf: (req: Request) => string | undefined;
/**
 * The cookie's claim, core's one reading of it (`cookieClaim`). `req.session`
 * is the session middleware's field, which this package does not type.
 */
export declare const claimOf: (req: Request) => SessionClaim;
/**
 * Whether this connect is a step-up trip's return: the marker, exactly as
 * connect sets it. Anything else is no marker, which only offers the trip.
 */
export declare const isSteppedUpReturn: (req: Request) => boolean;
/** A browser prefetching a link has not asked for it: nothing is parked on its behalf. */
export declare const isPrefetch: (req: Request) => boolean;
/**
 * The rest of the callback's parameters, string values only, without `code`
 * and `state` — which the flow binds itself — exactly as `exchangeCode` takes
 * them, so an adapter forwards `iss` (RFC 9207) the one way it knows.
 */
export declare function callbackParamsOf(req: Request): Readonly<Record<string, string>>;
//# sourceMappingURL=browserRequest.d.mts.map