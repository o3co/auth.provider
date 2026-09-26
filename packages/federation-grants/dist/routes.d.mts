/**
 * The router both routes live in, and the order its middleware runs in
 * (#593, D9).
 *
 *   1. cache directives and correlation, ahead of anything that can answer;
 *   2. the throttle, keyed on the IP, BEFORE client authentication, so that
 *      repeated unauthenticated hits are bounded before they reach a
 *      repository lookup;
 *   3. content type and body parsing;
 *   4. client authentication;
 *   5. the handlers;
 *   6. everything this package does not serve, as a 404;
 *   7. a sanitizing error handler, for what the parsers reject.
 *
 * Authentication before domain validation, deliberately: an unauthenticated
 * caller must not be able to learn anything about a grant, including by
 * measuring how long a refusal took.
 *
 * Exported so a composition root that mounts the handlers itself gets the same
 * chain rather than a hand-assembled approximation of it — the ordering above
 * is the security property, not a convenience.
 */
import { type ClientRepository, type RateLimiter, type RateLimitFailMode, type ReplaySeenSet } from "@o3co/auth-provider-core";
import { type ErrorRequestHandler, type RequestHandler, type Router } from "express";
import { type FederationGrantAcquisitionRouteOptions } from "./lodgeRoute.mjs";
import { type FederationGrantTokenHandlerOptions } from "./tokenRoute.mjs";
/** The shared prefix both routes are throttled under: `federation_grants:ip:<ip>`. */
export declare const FEDERATION_GRANTS_RATE_LIMIT_PREFIX = "federation_grants";
/**
 * `Cache-Control` / `Pragma` on every exit, live or refused, ahead of anything
 * that can answer. A 404 with no directives is the shape an intermediary
 * caches heuristically, and a cached "this deployment has no federation
 * grants" would outlive the operator turning them on.
 */
export declare const noStore: RequestHandler;
/**
 * The last handler under the mount path: every method and sub-path this
 * package does not serve.
 *
 * The body carries no description, unlike the neighbouring packages'
 * refusals. That is what a disabled deployment needs:
 * `{"error":"not_found"}` is byte-identical to what a deployment without the
 * package installed answers, so an unauthenticated caller cannot learn that
 * offline delegation is one configuration key away. On an enabled deployment
 * it is the answer for a method that does not exist — and there is no `GET`
 * status alias to point anyone at.
 */
export declare const notFound: RequestHandler;
/** What a deployment that has not enabled the feature mounts. */
export declare function createDisabledFederationGrantRouter(): Router;
/**
 * What the body parsers reject, in this package's own vocabulary.
 *
 * Nothing of the parser's error reaches the caller: `body-parser` puts the
 * offending input into its message for a JSON syntax error, so the `type` it
 * classifies with is all that is read.
 */
export declare const parserErrors: ErrorRequestHandler;
export interface FederationGrantRouterOptions extends FederationGrantTokenHandlerOptions {
    /**
     * Slice 6: what creating a grant needs. Absent, the two lodging routes are
     * not mounted and answer as any unknown path does; the module always passes
     * it, having refused at boot a deployment that could not supply it.
     */
    readonly acquisition?: FederationGrantAcquisitionRouteOptions;
    readonly clientRepository: ClientRepository;
    /** `oauth.jwt.issuer`: the Basic realm, and the audience an assertion may name. */
    readonly issuer: string;
    readonly rateLimiter: RateLimiter;
    readonly failMode: RateLimitFailMode;
    /** #484: where a `private_key_jwt` assertion's single-use `jti` is recorded. */
    readonly replaySeenSet?: ReplaySeenSet;
}
export declare function createFederationGrantRouter(options: FederationGrantRouterOptions): Router;
//# sourceMappingURL=routes.d.mts.map