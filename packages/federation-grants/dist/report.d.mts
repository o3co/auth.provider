/**
 * What an operator is told when something failed — and what they are not
 * (#593, D18).
 *
 * Core reports every cause it turns into a typed answer, because a 503 says
 * that something broke without saying what. The error it hands over may be an
 * upstream's, and an upstream's error carries whatever the upstream echoed
 * back: a request body, a refresh token it did not like, a header. The same
 * is true of the errors the shared client-authentication and rate-limit
 * middleware log when a repository throws.
 *
 * So both of these are built from an **allowlist**, not by redacting the
 * error. A redaction list is a list of the leaks somebody has already thought
 * of, and this is exactly the code path where the thing nobody thought of
 * arrives from another system.
 */
import type { AuditSink, Logger } from "@o3co/auth-provider-core";
/**
 * The `report` seam of `RetrieveFederationGrantTokenDeps`.
 *
 * Four fields and a classification, and nothing that came out of the error
 * itself. What makes it useful is the correlation: the same `x-request-id` the
 * caller was answered under, including for a refresh that failed after the
 * answer was sent.
 */
/**
 * What a failure report carries — core's `FederationGrantRetrievalFailure`
 * with `during` widened to a plain string.
 *
 * Widened here rather than in core so the route can report its own unexpected
 * failures through the same function: a handler that threw did not fail
 * *during* any of core's phases, and inventing a core phase for it would put a
 * lie in an operator's logs. A function taking this is still assignable to
 * core's narrower `report` seam.
 */
export interface SanitizedFailure {
    readonly during: string;
    readonly error: unknown;
    readonly grantId: string;
    readonly correlationId: string;
}
export declare function createSanitizedReporter(logger: Logger): (failure: SanitizedFailure) => void;
/**
 * The audit sink handed to the shared rate-limit guard.
 *
 * Its `rate_limit.unavailable` event carries `details.error` — the same
 * stringified limiter exception the log line carries — so the sink needs the
 * same allowlist the logger does. The event itself is kept: an operator's
 * dashboard counts limiter outages, and the count is the useful part.
 */
export declare function createSanitizedAuditSink(sink: AuditSink): AuditSink;
/**
 * A {@link Logger} facade handed to the shared middleware this package mounts.
 *
 * `createClientAuthMiddleware` and the rate-limit guard log a repository
 * failure with the raw error among the structured fields. That is right for a
 * deployment that has decided what its logger redacts; it is not something
 * this route can decide for it, and this is the one route whose repository
 * errors can arrive from an upstream IdP. So the middleware is given this
 * instead of the deployment's own logger: object-first calls keep their
 * scalars and lose everything else, string-first calls pass through.
 */
export declare function createSanitizedLogger(logger: Logger): Logger;
//# sourceMappingURL=report.d.mts.map