/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { Request, RequestHandler, Response } from "express";
import { emitAuditEvent } from "../audit/factory.mjs";
import type { AuditSink } from "../audit/types.mjs";
import { errorEnvelope } from "../errors/envelope.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
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
export const createRateLimitGuard = ({
	limiter,
	tag,
	failMode,
	logger = consoleLogger,
	auditSink,
	headerFallback,
}: RateLimitGuardOptions): RequestHandler => {
	return async (req: Request, res: Response, next): Promise<void> => {
		const ip = req.ip ?? "unknown";
		let decision: Awaited<ReturnType<RateLimiter["check"]>>;
		try {
			// CP-10: pass the same normalized ip into the check context as the
			// key derivation uses, so limiters that re-use ctx.ip for logging
			// or secondary keying observe the same value.
			decision = await limiter.check(`${tag}:ip:${ip}`, {
				ip,
				userAgent: req.get("user-agent"),
			});
		} catch (cause) {
			const errorMessage = cause instanceof Error ? cause.message : String(cause);
			logger.error(
				{ error: errorMessage, mode: failMode, tag, ip },
				failMode === "open" ? "rate_limiter_failed_open" : "rate_limiter_failed_closed",
			);
			emitAuditEvent(auditSink, {
				timestamp: new Date(),
				type: "rate_limit.unavailable",
				ip,
				userAgent: req.get("user-agent"),
				details: {
					tag,
					error: errorMessage,
				},
			});
			if (failMode === "closed") {
				res
					.status(503)
					.json(errorEnvelope("service_unavailable", "Rate limiter temporarily unavailable"));
				return;
			}
			next();
			return;
		}

		// The advertised limit is the one the adapter reports having *applied*,
		// not the one configured by the caller. They differ whenever an operator
		// declares a per-adapter spec (e.g. `limits.login`) — which deliberately
		// overrides the value seeded from `rateLimit.login` — and a header
		// advertising a limit no request is measured against is worse than no
		// header. `decision.limit` is optional, so a custom adapter that does
		// not report one falls back to `headerFallback`; a caller with no
		// configured spec omits the fallback and the header with it.
		const limitHeader = decision.limit ?? headerFallback?.limit;
		if (limitHeader !== undefined) {
			res.setHeader("RateLimit-Limit", String(limitHeader));
		}
		if (decision.remaining !== undefined) {
			res.setHeader("RateLimit-Remaining", String(Math.max(0, decision.remaining)));
		}
		const decisionResetSeconds =
			decision.resetAt === undefined
				? undefined
				: Math.max(0, Math.ceil((decision.resetAt.getTime() - Date.now()) / 1000));
		const resetHeader = decisionResetSeconds ?? headerFallback?.windowSeconds;
		if (resetHeader !== undefined) {
			res.setHeader("RateLimit-Reset", String(resetHeader));
		}

		if (!decision.allowed) {
			if (decisionResetSeconds !== undefined) {
				res.setHeader("Retry-After", String(decisionResetSeconds));
			}
			// AS-2: rate-limit body migrated from `{error, reason}` to RFC 6749 §5.2
			// `{error, error_description}` so all auth-product error responses share
			// a single shape. `decision.reason` is the operator-visible cause string.
			// `||` (not `??`) so that `decision.reason: ""` from a custom rate
			// limiter also falls back — the envelope helper would otherwise drop
			// the empty string and produce a 429 response with no `error_description`.
			res.status(429).json(errorEnvelope("rate_limited", decision.reason || "Rate limit exceeded"));
			return;
		}
		next();
	};
};
