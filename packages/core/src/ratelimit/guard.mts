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
import { auditedError } from "../audit/auditedError.mjs";
import { emitAuditEvent } from "../audit/factory.mjs";
import type { AuditSink } from "../audit/types.mjs";
import { shownConfigValue } from "../config/configuredValue.mjs";
import { auditErrorText, type ErrorEnvelope, errorEnvelope } from "../errors/envelope.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import type {
	RateLimitContext,
	RateLimitDecision,
	RateLimiter,
	RateLimitFailMode,
	RateLimitSpec,
} from "./types.mjs";

export interface RateLimitGuardOptions {
	/** The shared limiter component the guarded route runs on. */
	readonly limiter: RateLimiter;
	/**
	 * Endpoint tag: the key prefix (`<tag>:ip:<ip>`) by which an adapter
	 * resolves this route's spec, and the `tag` field on the guard's log and
	 * audit emissions. E.g. `"token"`, `"authorize"`, `"introspect"`, `"mfa"`.
	 */
	readonly tag: string;
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
	 * documented per-endpoint spec pass it here; without it the guard only
	 * advertises what the adapter actually reported, because a header value
	 * the caller invented is a limit no request is measured against.
	 */
	readonly headerFallback?: RateLimitSpec;
	/**
	 * A fixed `error_description` for this route's 429, in place of the
	 * limiter's `decision.reason`, for routes whose error bodies are a
	 * vocabulary a client switches on: the federation-grant routes answer
	 * `rate_limited` with the reason `provider` whoever throttled. Leave it
	 * unset wherever `error_description` is for a human: `decision.reason` is
	 * the operator-visible cause.
	 */
	readonly deniedDescription?: string;
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
 * limiter, whose `failMode` is the outage policy, the endpoint tag and the
 * outage's two channels.
 */
export type RateLimitPolicyOptions = Pick<
	RateLimitGuardOptions,
	"limiter" | "tag" | "auditSink"
> & {
	/** Operator-visible outage channel. Defaults to `consoleLogger`. */
	readonly logger?: RateLimitOutageLogger;
};

declare const policyBrand: unique symbol;

/**
 * A check's outage policy, built once by {@link createRateLimitPolicy}: the
 * limiter's `failMode` as it was read then, with the tag and the channels.
 * Branded, and checked at runtime: no other value is one.
 */
export interface RateLimitPolicy {
	readonly [policyBrand]: true;
	readonly limiter: RateLimiter;
	readonly tag: string;
	readonly failMode: RateLimitFailMode;
	readonly logger: RateLimitOutageLogger;
	readonly auditSink?: AuditSink;
}

/** The policies {@link createRateLimitPolicy} built: the only ones a check accepts. */
const builtPolicies = new WeakSet<object>();

/**
 * The policy {@link checkWithFailMode} applies: the limiter's `failMode` read
 * and validated once, here (`readRateLimitFailMode`, naming `who`).
 */
export function createRateLimitPolicy(
	options: RateLimitPolicyOptions,
	who = "createRateLimitPolicy",
): RateLimitPolicy {
	const policy = Object.freeze({
		limiter: options.limiter,
		tag: options.tag,
		failMode: readRateLimitFailMode(options.limiter, who),
		logger: options.logger ?? consoleLogger,
		...(options.auditSink === undefined ? {} : { auditSink: options.auditSink }),
	}) as RateLimitPolicy;
	builtPolicies.add(policy);
	return policy;
}

/**
 * What {@link checkWithFailMode} hands back: the limiter's decision, or the
 * fact that it had none together with the limiter's policy the caller is to
 * apply.
 */
export type RateLimitCheckOutcome =
	| { readonly status: "decided"; readonly decision: RateLimitDecision }
	| { readonly status: "unavailable"; readonly failMode: RateLimitFailMode };

/**
 * The guard's check with its outage policy attached, for a route that cannot
 * use the middleware (`POST /oauth/device/verification` keys its budget on the
 * authenticated subject and audits its own 429). On a throw it writes the
 * paired `logger.error` + audit event described at {@link createRateLimitGuard};
 * the caller renders the outcome (503 with
 * {@link rateLimiterUnavailableEnvelope} under `"closed"`, proceed under
 * `"open"`), so the policy and its reporting exist once.
 *
 * The policy is the limiter's own `failMode` (only its backend can be down),
 * as {@link createRateLimitPolicy} read it; a policy it did not build is
 * refused.
 *
 * The outage report's `ip` / `userAgent` are read from `ctx`.
 */
export const checkWithFailMode = async (
	policy: RateLimitPolicy,
	key: string,
	ctx: RateLimitContext,
): Promise<RateLimitCheckOutcome> => {
	if (!builtPolicies.has(policy)) {
		throw new TypeError(
			"checkWithFailMode: the policy must be one createRateLimitPolicy built, which reads the limiter's own failMode",
		);
	}
	const { limiter, tag, failMode, logger, auditSink } = policy;
	try {
		return { status: "decided", decision: await limiter.check(key, ctx) };
	} catch (cause) {
		// A limiter's error is a store's (a Redis reply echoes the command it
		// refused), so the log line carries loggableError's projection, and a
		// thrown non-Error says what kind it was, not what it held. The audit
		// event, a record other systems read, keeps only the name and code
		// (`auditedError`) as `details.cause`.
		const projected = loggableError(cause);
		const reported = projected.detail ?? projected.name;
		const ip = ctx.ip ?? "unknown";
		// Behind `trust proxy`, `ip` is what the caller wrote in
		// X-Forwarded-For: on the line, sanitised and capped, as claimed. The
		// audit event is handed it raw — `emitAuditEvent` keeps it only if it
		// is an address, so a sink never gets `"unknown"` or a spoofed name.
		logger.error(
			{ error: reported, mode: failMode, tag, ip: auditErrorText(ip) },
			failMode === "open" ? "rate_limiter_failed_open" : "rate_limiter_failed_closed",
		);
		emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "rate_limit.unavailable",
			ip,
			userAgent: ctx.userAgent,
			details: {
				tag,
				cause: auditedError(cause),
			},
		});
		return { status: "unavailable", failMode };
	}
};

/**
 * The limiter's outage policy, read once: `"closed"` when it declares none.
 * A declared value other than `"open"` or `"closed"` is a `RangeError` naming
 * `who`.
 */
export function readRateLimitFailMode(limiter: RateLimiter, who: string): RateLimitFailMode {
	const declared: unknown = limiter.failMode;
	if (declared === undefined) return "closed";
	if (declared === "open" || declared === "closed") return declared;
	throw new RangeError(
		`${who}: a rate limiter's failMode must be "open" or "closed" when it declares one (got ${shownConfigValue(declared)})`,
	);
}

/**
 * The 503 body the guard answers under `failMode = "closed"`, so a caller of
 * {@link checkWithFailMode} that renders the outage itself answers the same
 * envelope and a client sees one outage shape across every throttled route.
 */
export const rateLimiterUnavailableEnvelope = (): ErrorEnvelope =>
	errorEnvelope("service_unavailable", "Rate limiter temporarily unavailable");

/**
 * Middleware factory for the routes the deployment's rate limiter throttles,
 * shared by every module that keys the limiter (the OAuth endpoints among
 * them). It checks `limiter.check("<tag>:ip:<ip>", ctx)` and:
 *
 * - **allow** → `RateLimit-*` headers, then `next()`;
 * - **deny** → `RateLimit-*` headers, `Retry-After` when the decision carries
 *   a reset time, and a 429 with the RFC 6749 §5.2 envelope
 *   (`{error: "rate_limited"}`);
 * - **limiter outage** → applies the limiter's own `failMode` (closed when it
 *   declares none) and reports on two channels:
 *   `logger.error` for operators, which works even when the audit sink shares
 *   the failed backend (typically Redis), and the `rate_limit.unavailable`
 *   audit event for dashboards.
 *
 * The check and outage policy are {@link checkWithFailMode}; this factory
 * adds the key, the headers and the responses.
 */
export const createRateLimitGuard = ({
	limiter,
	tag,
	logger = consoleLogger,
	auditSink,
	headerFallback,
	deniedDescription,
}: RateLimitGuardOptions): RequestHandler => {
	const policy = createRateLimitPolicy(
		{ limiter, tag, logger, ...(auditSink === undefined ? {} : { auditSink }) },
		"createRateLimitGuard",
	);
	return async (req: Request, res: Response, next): Promise<void> => {
		const ip = req.ip ?? "unknown";
		// The same ip as the key, so a limiter that reuses ctx.ip for logging
		// or secondary keying sees the same value.
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

		// Advertise the limit the adapter applied, not the caller's (see
		// `RateLimitDecision.limit`): a header naming a limit no request is
		// measured against is worse than none. `headerFallback` covers adapters
		// that report none; without either, the header is omitted.
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
			// RFC 6749 §5.2 `{error, error_description}`, the shape every error
			// response shares. A reason that is empty or not a string (a custom
			// adapter can put anything there) falls back to the default, which the
			// envelope would otherwise drop, leaving the 429 without one.
			const reason =
				typeof decision.reason === "string" && decision.reason !== ""
					? decision.reason
					: "Rate limit exceeded";
			res.status(429).json(errorEnvelope("rate_limited", deniedDescription ?? reason));
			return;
		}
		next();
	};
};
