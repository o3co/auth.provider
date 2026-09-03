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
 * ### A limiter outage is the product's outage policy, not a 500 (#457)
 *
 * The check cannot sit behind `createRateLimitGuard` as a middleware: the
 * budget is keyed on the subject rather than the IP, and the 429's audit
 * event needs the `action` — so what this endpoint shares with the guarded
 * routes is the guard's check-plus-outage-policy as a function,
 * `checkWithFailMode`. When the limiter backend itself fails,
 * `rateLimit.failMode` decides here exactly as it does on `/oauth/token`:
 * `"closed"` answers the guard's `503 service_unavailable`, `"open"` serves
 * the request, and either way `rate_limiter_failed_*` is logged and
 * `rate_limit.unavailable` is emitted. Before #457 the call was bare, so an
 * outage was an unhandled throw — `500 server_error` through the terminal
 * handler, `failMode` ignored, and no audit event for the alert operators
 * page on — on the one endpoint whose limit is half of its security argument.
 * A `limited` decision is not an outage: it stays a 429 under either mode,
 * and stays the `device.rate_limited` signal (#443).
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

import type {
	RateLimitContext,
	RateLimiter,
	RateLimitFailMode,
	RateLimitOutageLogger,
} from "@o3co/auth-provider-core";
import {
	checkWithFailMode,
	emitAuditEvent,
	normaliseUserCode,
	rateLimiterUnavailableEnvelope,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { DEVICE_VERIFICATION_RATE_LIMIT_PREFIX, type DeviceGrantDependencies } from "./types.mjs";

type Action = "lookup" | "approve" | "deny";

const ACTIONS: readonly Action[] = ["lookup", "approve", "deny"];

const respond = (res: Response, status: number, body: Record<string, unknown>): void => {
	res.status(status).set("Cache-Control", "no-store").json(body);
};

/**
 * The authenticated end user, from the session the deployment's verification
 * page runs inside.
 *
 * Returns `null` when there is nobody logged in. That is a 401, not a
 * redirect: this is a JSON API called by a page, and the page owns what to do
 * about a missing session.
 */
const subjectOf = (req: Request): string | null => {
	const session = (req as { session?: { isAuthenticated?: boolean; user?: { id?: unknown } } })
		.session;
	if (session?.isAuthenticated !== true) return null;
	const id = session.user?.id;
	return typeof id === "string" && id !== "" ? id : null;
};

/**
 * The check context: the subject the budget is keyed on, plus the request
 * details the outage report carries (`rate_limit.unavailable` names the `ip`
 * and `userAgent`, as the guard's does).
 */
const contextOf = (req: Request, subject: string): RateLimitContext => {
	const userAgent = req.get("user-agent");
	return {
		userId: subject,
		...(req.ip === undefined ? {} : { ip: req.ip }),
		...(userAgent === undefined ? {} : { userAgent }),
	};
};

/**
 * The dependency's logger is a duck type with `warn` required and the rest
 * optional; the outage line is written through `error`. A logger without one
 * is left out so the shared check falls back to core's console logger rather
 * than losing the line.
 */
const hasErrorChannel = (
	logger: DeviceGrantDependencies["logger"],
): logger is NonNullable<DeviceGrantDependencies["logger"]> & RateLimitOutageLogger =>
	typeof logger?.error === "function";

export interface DeviceVerificationHandlerOptions extends DeviceGrantDependencies {
	/**
	 * Required. See the file header: the code's entropy budget is calculated
	 * against a limit, so running without one is running with 34.5 bits and no
	 * ceiling.
	 */
	readonly rateLimiter: RateLimiter;
	/**
	 * Required, like the limiter, and not defaulted for the same reason the
	 * module refuses to: what this endpoint does when the limiter backend is
	 * down is `rateLimit.failMode`, one policy for the product (#457).
	 */
	readonly failMode: RateLimitFailMode;
}

export const createDeviceVerificationHandler = (
	options: DeviceVerificationHandlerOptions,
): RequestHandler => {
	const now = options.now ?? Date.now;
	// The guard's check with its outage policy attached — see the file header.
	const policy = {
		limiter: options.rateLimiter,
		tag: DEVICE_VERIFICATION_RATE_LIMIT_PREFIX,
		failMode: options.failMode,
		logger: hasErrorChannel(options.logger) ? options.logger : undefined,
		auditSink: options.auditSink,
	};

	return async (req: Request, res: Response): Promise<void> => {
		const subject = subjectOf(req);
		if (subject === null) {
			respond(res, 401, {
				error: "login_required",
				error_description: "an authenticated end-user session is required to approve a device",
			});
			return;
		}

		const body = (req.body ?? {}) as Record<string, unknown>;
		const action = body.action;
		if (typeof action !== "string" || !ACTIONS.includes(action as Action)) {
			respond(res, 400, {
				error: "invalid_request",
				error_description: `action must be one of: ${ACTIONS.join(", ")}`,
			});
			return;
		}

		// Counted before the code is even parsed. A malformed code is still an
		// attempt, and excluding it would hand an attacker an unmetered way to
		// probe which shapes the endpoint accepts.
		const budget = await checkWithFailMode(
			policy,
			`${DEVICE_VERIFICATION_RATE_LIMIT_PREFIX}:user:${subject}`,
			contextOf(req, subject),
		);
		if (budget.status === "unavailable") {
			// The limiter had no answer, so `rateLimit.failMode` is the answer
			// (#457). The outage is already logged and audited by the shared
			// check; `open` serves the request exactly as the guard would.
			if (budget.failMode === "closed") {
				respond(res, 503, { ...rateLimiterUnavailableEnvelope() });
				return;
			}
		} else if (!budget.decision.allowed) {
			// A limiter that answered "no" is not an outage: this is the #443
			// signal that an account is guessing codes, under either fail mode.
			const { decision } = budget;
			options.logger?.warn(
				{ subject, action, remaining: decision.remaining },
				"device_verification_rate_limited",
			);
			emitAuditEvent(options.auditSink, {
				timestamp: new Date(),
				type: "device.rate_limited",
				subject,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { action, remaining: decision.remaining },
			});
			respond(res, 429, {
				error: "slow_down",
				error_description: "too many device code attempts",
			});
			return;
		}

		const rawUserCode = body.user_code;
		const userCode = typeof rawUserCode === "string" ? normaliseUserCode(rawUserCode) : null;
		if (userCode === null) {
			// Deliberately the same answer as "no such code": telling a caller
			// that a code is well-formed but unknown, distinctly from
			// malformed, narrows the search space for free.
			respond(res, 404, {
				error: "invalid_user_code",
				error_description: "that code is not valid — check it and try again",
			});
			return;
		}

		const nowMs = now();

		if (action === "lookup") {
			const authorization = await options.store.findPendingByUserCode(userCode, nowMs);
			if (authorization === null) {
				respond(res, 404, {
					error: "invalid_user_code",
					error_description: "that code is not valid — check it and try again",
				});
				return;
			}
			// §5.4: "it is RECOMMENDED to inform the user that they are
			// authorizing a device ... and to confirm that the device is in
			// their possession". The page needs the client's identity and the
			// scope to say that; it gets nothing else.
			respond(res, 200, {
				client_id: authorization.clientId,
				scope: (authorization.requestedScope ?? []).join(" "),
				expires_at: new Date(authorization.expiresAtMs).toISOString(),
			});
			return;
		}

		const outcome =
			action === "approve"
				? // `grantedScope` is deliberately omitted: the port grants
					// `requestedScope`, which was settled and filtered against the
					// client's allowlist when the device asked. Re-reading it here
					// to pass it back would open a window between the lookup that
					// showed the user a scope and the write that grants one.
					await options.store.approve({ userCode, subject, nowMs })
				: await options.store.deny(userCode, nowMs);

		switch (outcome.status) {
			case "ok": {
				const { authorization } = outcome;
				const scope = (authorization.grantedScope ?? authorization.requestedScope ?? []).join(" ");
				options.logger?.info?.(
					{ subject, clientId: authorization.clientId, action },
					"device_authorization_decided",
				);
				// Two literal emission sites rather than a computed type: the
				// inventory drift guard in core reads the `type:` literal at
				// each call, and a ternary would hide one name from it.
				if (action === "approve") {
					emitAuditEvent(options.auditSink, {
						timestamp: new Date(),
						type: "device.approved",
						subject,
						clientId: authorization.clientId,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { scope },
					});
				} else {
					emitAuditEvent(options.auditSink, {
						timestamp: new Date(),
						type: "device.denied",
						subject,
						clientId: authorization.clientId,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { scope },
					});
				}
				respond(res, 200, {
					status: action === "approve" ? "approved" : "denied",
					client_id: authorization.clientId,
				});
				return;
			}
			case "expired":
				respond(res, 410, {
					error: "expired_token",
					error_description: "that code has expired — start again on the device",
				});
				return;
			case "already_decided":
				// A second decision must not overwrite the first: a user who
				// denied a phishing prompt must not be able to be talked into
				// "just trying again".
				respond(res, 409, {
					error: "already_decided",
					error_description: `this code was already ${outcome.current}`,
				});
				return;
			default:
				respond(res, 404, {
					error: "invalid_user_code",
					error_description: "that code is not valid — check it and try again",
				});
		}
	};
};
