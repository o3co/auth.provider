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
 */

import type { RateLimiter } from "@o3co/auth-provider-core";
import { normaliseUserCode } from "@o3co/auth-provider-core";
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

export interface DeviceVerificationHandlerOptions extends DeviceGrantDependencies {
	/**
	 * Required. See the file header: the code's entropy budget is calculated
	 * against a limit, so running without one is running with 34.5 bits and no
	 * ceiling.
	 */
	readonly rateLimiter: RateLimiter;
}

export const createDeviceVerificationHandler = (
	options: DeviceVerificationHandlerOptions,
): RequestHandler => {
	const now = options.now ?? Date.now;

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
		const decision = await options.rateLimiter.check(
			`${DEVICE_VERIFICATION_RATE_LIMIT_PREFIX}:user:${subject}`,
			{ userId: subject, ...(req.ip === undefined ? {} : { ip: req.ip }) },
		);
		if (!decision.allowed) {
			options.logger?.warn(
				{ subject, action, remaining: decision.remaining },
				"device_verification_rate_limited",
			);
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
			case "ok":
				options.logger?.info?.(
					{ subject, clientId: outcome.authorization.clientId, action },
					"device_authorization_decided",
				);
				respond(res, 200, {
					status: action === "approve" ? "approved" : "denied",
					client_id: outcome.authorization.clientId,
				});
				return;
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
