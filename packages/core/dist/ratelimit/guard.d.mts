import type { RequestHandler } from "express";
import type { AuditSink } from "../audit/types.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { RateLimiter, RateLimitSpec } from "./types.mjs";
/**
 * How the guard behaves when the limiter backend itself errors — mirrors
 * `config.rateLimit.failMode` (OR-5). See {@link createRateLimitGuard}.
 */
export type RateLimitFailMode = "open" | "closed";
export interface RateLimitGuardOptions {
    /** The shared limiter component the guarded route runs on. */
    readonly limiter: RateLimiter;
    /**
     * Endpoint tag: the key prefix (`<tag>:ip:<ip>`) by which an adapter
     * resolves this route's spec, and the `tag` field on the guard's log and
     * audit emissions. E.g. `"token"`, `"authorize"`, `"introspect"`, `"login"`.
     */
    readonly tag: string;
    /**
     * OR-5: fail-mode policy for a limiter-backend outage, read from
     * `config.rateLimit.failMode` — one policy for the product, not one per
     * router. `"open"` lets the request through; `"closed"` returns 503.
     */
    readonly failMode: RateLimitFailMode;
    /** Operator-visible outage channel. Defaults to `consoleLogger`. */
    readonly logger?: Logger;
    /**
     * Structured-pipeline outage channel: when present the guard emits a
     * `rate_limit.unavailable` audit event alongside the `logger.error` call
     * (fire-and-forget via `emitAuditEvent`).
     */
    readonly auditSink?: AuditSink;
    /**
     * Configured spec backing the `RateLimit-Limit` / `RateLimit-Reset` headers
     * when the decision does not carry `limit` / `resetAt`. Callers with a
     * documented per-endpoint spec (e.g. `rateLimit.login`) pass it here;
     * without it the guard only advertises what the adapter actually reported,
     * because a header value the caller invented is a limit no request is
     * measured against.
     */
    readonly headerFallback?: RateLimitSpec;
}
/**
 * Middleware factory for the product's security throttles (#325).
 *
 * One implementation of the rate-limit check + outage policy shared by the
 * OAuth endpoints (`/token`, `/authorize`, `/introspect`) and
 * `/session/login`, which previously carried two hand-synchronized copies
 * (#314) that had already drifted: only the oauth copy emitted the
 * `rate_limit.unavailable` audit event, and only the session copy emitted
 * `RateLimit-*` headers. Both surfaces now do both.
 *
 * The guard checks `limiter.check("<tag>:ip:<ip>", ctx)` and:
 *
 * - **allow** → emits `RateLimit-*` headers and calls `next()`;
 * - **deny** → emits `RateLimit-*` headers, `Retry-After` when the decision
 *   carries a reset time, and a 429 with the RFC 6749 §5.2 envelope
 *   (`{error: "rate_limited"}` — AS-2 unified error shape);
 * - **limiter outage** → applies `failMode` (OR-5). The previous
 *   implementation was silent fail-open with a fire-and-forget audit event.
 *   The audit sink is typically Redis-backed too, so during a Redis outage
 *   the audit emission also silently drops — operators saw nothing while
 *   rate limiting was down for hours. The `failMode` policy makes the
 *   behavior configurable, and the `logger.error` call ensures operators see
 *   the outage regardless of audit-sink status. Belt-and-suspenders: the
 *   `rate_limit.unavailable` audit event is kept for ops dashboards that
 *   consume it — the logger call is the operator-visible path, the audit
 *   event is the structured pipeline path.
 */
export declare const createRateLimitGuard: ({ limiter, tag, failMode, logger, auditSink, headerFallback, }: RateLimitGuardOptions) => RequestHandler;
//# sourceMappingURL=guard.d.mts.map