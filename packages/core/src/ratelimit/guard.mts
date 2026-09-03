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
import { type ErrorEnvelope, errorEnvelope } from "../errors/envelope.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { RateLimitContext, RateLimitDecision, RateLimiter, RateLimitSpec } from "./types.mjs";

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
 * The one method the outage report is written through. A full {@link Logger}
 * satisfies it; so does a caller's narrower duck-typed logger.
 */
export interface RateLimitOutageLogger {
	error(obj: Record<string, unknown>, msg: string): void;
}

/**
 * What {@link checkWithFailMode} needs from {@link RateLimitGuardOptions}: the
 * limiter, the endpoint tag, the OR-5 outage policy and its two channels.
 */
export type RateLimitPolicyOptions = Pick<
	RateLimitGuardOptions,
	"limiter" | "tag" | "failMode" | "auditSink"
> & {
	/** Operator-visible outage channel. Defaults to `consoleLogger`. */
	readonly logger?: RateLimitOutageLogger;
};

/**
 * What {@link checkWithFailMode} hands back: the limiter's decision, or the
 * fact that it had none together with the policy the caller is to apply.
 */
export type RateLimitCheckOutcome =
	| { readonly status: "decided"; readonly decision: RateLimitDecision }
	| { readonly status: "unavailable"; readonly failMode: RateLimitFailMode };

/**
 * The guard's check with its outage policy attached, for a route that cannot
 * be guarded by a middleware (#457).
 *
 * `POST /oauth/device/verification` keys its budget on the authenticated
 * subject rather than the IP, and its 429 is its own audit event carrying the
 * request's `action` — neither fits the `<tag>:ip:<ip>` middleware. Until
 * #457 it therefore called `limiter.check` bare, and a limiter-backend outage
 * there was an unhandled throw: a 500 through the terminal handler,
 * `rateLimit.failMode` ignored, no `rate_limit.unavailable` event. This is
 * the half of {@link createRateLimitGuard} such a route shares: the check,
 * and on a throw the paired `logger.error` + audit emission described there.
 * The caller renders the outcome — 503 with
 * {@link rateLimiterUnavailableEnvelope} under `"closed"`, proceed under
 * `"open"` — so that the policy and its reporting exist once, and the guard
 * is this function plus HTTP framing.
 *
 * The outage report's `ip` / `userAgent` are read from `ctx`, so a caller
 * that wants them on the audit event passes them in the check context, as
 * the guard does.
 */
export const checkWithFailMode = async (
	{ limiter, tag, failMode, logger = consoleLogger, auditSink }: RateLimitPolicyOptions,
	key: string,
	ctx: RateLimitContext,
): Promise<RateLimitCheckOutcome> => {
	try {
		return { status: "decided", decision: await limiter.check(key, ctx) };
	} catch (cause) {
		const errorMessage = cause instanceof Error ? cause.message : String(cause);
		const ip = ctx.ip ?? "unknown";
		logger.error(
			{ error: errorMessage, mode: failMode, tag, ip },
			failMode === "open" ? "rate_limiter_failed_open" : "rate_limiter_failed_closed",
		);
		emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "rate_limit.unavailable",
			ip,
			userAgent: ctx.userAgent,
			details: {
				tag,
				error: errorMessage,
			},
		});
		return { status: "unavailable", failMode };
	}
};

/**
 * The 503 body the guard answers under `failMode = "closed"`, so a caller of
 * {@link checkWithFailMode} that renders the outage itself answers the same
 * envelope and a client sees one outage shape across every throttled route.
 */
export const rateLimiterUnavailableEnvelope = (): ErrorEnvelope =>
	errorEnvelope("service_unavailable", "Rate limiter temporarily unavailable");

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
 *
 * The check and the outage policy are {@link checkWithFailMode} (#457); this
 * factory adds the `<tag>:ip:<ip>` key, the headers and the responses.
 */
export const createRateLimitGuard = ({
	limiter,
	tag,
	failMode,
	logger = consoleLogger,
	auditSink,
	headerFallback,
}: RateLimitGuardOptions): RequestHandler => {
	const policy: RateLimitPolicyOptions = { limiter, tag, failMode, logger, auditSink };
	return async (req: Request, res: Response, next): Promise<void> => {
		const ip = req.ip ?? "unknown";
		// CP-10: pass the same normalized ip into the check context as the
		// key derivation uses, so limiters that re-use ctx.ip for logging
		// or secondary keying observe the same value.
		const outcome = await checkWithFailMode(policy, `${tag}:ip:${ip}`, {
			ip,
			userAgent: req.get("user-agent"),
		});
		if (outcome.status === "unavailable") {
			if (outcome.failMode === "closed") {
				res.status(503).json(rateLimiterUnavailableEnvelope());
				return;
			}
			next();
			return;
		}
		const { decision } = outcome;

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
