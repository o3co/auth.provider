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
 * `POST /oauth/device/verification` — where the user answers an RFC 8628
 * device request (§3.3). This package serves the JSON API; the page at
 * `verification_uri` belongs to the deployment.
 *
 * - `lookup`, `approve` and `deny` share one route: each takes a `user_code`
 *   and is the same brute-force oracle, so one route means one limiter call.
 * - The limiter is required: RFC 8628 §5.1's ~34.5-bit code is safe only with
 *   about 5 attempts. The budget is keyed on the authenticated subject, so an
 *   attacker burns their own account's budget; that is why this runs
 *   `checkWithFailMode` itself instead of the IP-keyed guard middleware.
 * - Order: JSON media type (415), the body's `action` (400), session
 *   admission, what an approval records (401, below; `approve` only), the
 *   email gate (`approve` only), the budget, the code's shape (a malformed
 *   code is 404), then the store's answers, on a clock read after the budget:
 *   a code that expires while the limiter answers is expired. Refusals before
 *   the budget spend no attempt and read no code.
 * - Admission (`admitSession`; see the session-admission ADR) reads the live
 *   `UserSession` behind the cookie's `sid`, not the cookie's claim: the
 *   device token carries no `sid` or `family_id`, so no later logout reaches
 *   it, and the approval is the last point that can check the session.
 * - An approval records the admitted session's `vouchedAmr` and `authTime`,
 *   which the device token carries. One the store would refuse to record
 *   (core's `recordableDeviceApproval`: an `authTime` further ahead of the
 *   approval's clock than the skew, or before the epoch) is refused
 *   `401 login_required` before the email gate, the budget and the store are
 *   asked, so no attempt is spent on it; and again on the clock the store is
 *   handed, so a store error stays an outage.
 * - Outages fail closed as 503 (a limiter outage follows the limiter's own
 *   `failMode`), never as `login_required`.
 * - A record the store answers is read through core's
 *   `readDeviceAuthorization` before any of it is used, and the decision's
 *   answer around it through `readDecisionOutcome`. One either refuses is
 *   answered as an outage (503), logged at error; on a decision, it is
 *   audited as an unknown outcome, as a lost reply is.
 * - Decisions and budget exhaustion are audit events; none carries the user
 *   code (the brute-force target) or the device code (a bearer credential).
 * - JSON only, checked here whatever parsed the body: a form POST is a CORS
 *   "simple" request sent cross-site with the cookie and no preflight
 *   (RFC 8628 §5.4 remote phishing). Body parsing and the CSRF guard are the
 *   mounting router's (`module.mts`); a hand-built mount must add both.
 */

import type {
	Admission,
	AdmissionDeps,
	ApproveDeviceAuthorizationInput,
	CookieCarrier,
	Logger,
	RateLimitContext,
	RateLimiter,
	RateLimitOutageLogger,
	SessionRequirementResolver,
	SubjectRevocation,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	admitSession,
	checkResolver,
	checkWithFailMode,
	consoleLogger,
	cookieClaim,
	createRateLimitPolicy,
	describeAdmissionOutage,
	emitAuditEvent,
	isEmailVerified,
	normaliseUserCode,
	rateLimiterUnavailableEnvelope,
	readDeviceAuthorization,
	recordableDeviceApproval,
	vouchedAmr,
	wellFormedAmr,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import type { DeviceGrantAdmissionAction } from "./admissionActions.mjs";
import { readDecisionOutcome, type StoreAnswerRefusal } from "./storeAnswer.mjs";
import {
	DEVICE_CODE_STORE_UNAVAILABLE,
	type DeviceAuthorizationRefusal,
	reportDeviceCodeStoreOutage,
	reportUnreadableDeviceAuthorization,
} from "./storeOutage.mjs";
import { DEVICE_VERIFICATION_RATE_LIMIT_PREFIX, type DeviceGrantDependencies } from "./types.mjs";

type Action = "lookup" | "approve" | "deny";

const ACTIONS: readonly Action[] = ["lookup", "approve", "deny"];

const isAction = (value: unknown): value is Action =>
	typeof value === "string" && (ACTIONS as readonly string[]).includes(value);

/** Each body action as admission is asked about it: the action the device grant registers for it. */
const ADMITTED_AS: Readonly<Record<Action, DeviceGrantAdmissionAction>> = {
	lookup: "device.lookup",
	approve: "device.approve",
	deny: "device.deny",
};

/** Device verification selects no `acr`: nothing asks for one here. */
const NO_ACR_TABLE: AdmissionDeps["acrTable"] = Object.freeze({});

const respond = (res: Response, status: number, body: Record<string, unknown>): void => {
	res.status(status).set("Cache-Control", "no-store").json(body);
};

/**
 * The user object the cookie session carries: what the email gate reads, as
 * `/authorize` reads it. Nobody's subject is taken from it — the subject is
 * the admitted record's.
 */
const cookieUserOf = (req: Request): unknown =>
	(req as { session?: { user?: unknown } | null }).session?.user;

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

/**
 * The dependency's logger as the `Logger` admission writes through: its
 * `warn`, and its `error` — core's console logger's when it has none, as the
 * rate-limit check falls back — or core's console logger outright when none
 * is wired. Admission writes object-first lines at `warn` and `error`
 * alone; the other levels go where `error` or nowhere goes.
 */
const admissionLogger = (logger: DeviceGrantDependencies["logger"]): Logger => {
	if (logger === undefined) return consoleLogger;
	const errors = hasErrorChannel(logger) ? logger : consoleLogger;
	const line =
		(write: (obj: Record<string, unknown>, msg: string) => void) =>
		(first: Record<string, unknown> | string, msg?: unknown): void => {
			if (typeof first === "string") write({}, first);
			else write(first, typeof msg === "string" ? msg : "");
		};
	const ignored = (): void => undefined;
	const adapted: Logger = {
		trace: ignored,
		debug: ignored,
		info: ignored,
		warn: line((obj, msg) => logger.warn(obj, msg)),
		error: line((obj, msg) => errors.error(obj, msg)),
		fatal: line((obj, msg) => errors.error(obj, msg)),
		child: () => adapted,
	};
	return adapted;
};

/** The `401 login_required` descriptions. */
const NO_SESSION = "an authenticated end-user session is required to approve a device";
const NO_SID = "session identifier (sid) is required";
const ENDED = "the session is no longer active; sign in again";
const SIGN_IN_AGAIN = "sign in again to continue";

const loginRequired = (description: string) =>
	({ status: 401, body: { error: "login_required", error_description: description } }) as const;

/**
 * The answer to an admission that did not admit a live session. A new login
 * is the only remedy the page can offer, so every unusable session is
 * `401 login_required`; `step_up` is `403 step_up_required` with its page; an
 * outage is 503, never `login_required`. An `admitted` without a record never
 * reaches a handler built with a store, and is refused with the rest.
 */
const refusalOf = (
	admission: Admission,
): { readonly status: number; readonly body: Record<string, unknown> } => {
	switch (admission.outcome) {
		case "unavailable":
			return {
				status: 503,
				body: {
					error: "temporarily_unavailable",
					error_description: describeAdmissionOutage(admission.store),
				},
			};
		case "step_up":
			return {
				status: 403,
				body: {
					error: "step_up_required",
					error_description: "the session must step up before it can do this",
					requirement: admission.requirement,
					// Where the step-up starts, as registered — resolved on the issuer
					// then, as every consumer answers it. No return parameter: the
					// deployment's verification page knows where it comes back to.
					page: admission.page.href,
				},
			};
		case "unauthenticated":
			return loginRequired(NO_SESSION);
		case "not_live":
			if (admission.reason === "no_subject") return loginRequired(NO_SESSION);
			if (admission.reason === "no_sid") return loginRequired(NO_SID);
			return loginRequired(ENDED);
		case "revoked":
			return loginRequired(ENDED);
		case "reauthenticate":
		case "unmet":
		case "admitted":
			return loginRequired(SIGN_IN_AGAIN);
	}
};

export interface DeviceVerificationHandlerOptions extends DeviceGrantDependencies {
	/**
	 * Required: RFC 8628 §5.1 sizes the user code's entropy against a limit,
	 * so without one it is 34.5 bits and no ceiling. Its own `failMode` is the
	 * policy for its backend's outage.
	 */
	readonly rateLimiter: RateLimiter;
	/**
	 * Required: where admission reads the `UserSession` behind the cookie's
	 * `sid`. Without it an approval would rest on the cookie's word alone.
	 */
	readonly userSessionStore: UserSessionStore;
	/**
	 * Required: the `sessionRequirementResolver` the boot planner built
	 * (`resolverForTests` in a test). Admission refuses any other object.
	 */
	readonly requirements: SessionRequirementResolver;
	/**
	 * `oauth.requireEmailVerified`, resolved. Required rather than defaulted, so
	 * a hand-built composition states whether the gate holds.
	 */
	readonly requireEmailVerified: boolean;
	/**
	 * Where admission reads the subject's sessions boundary. Optional: a
	 * composition that declared subject-level revocation absent has none.
	 */
	readonly subjectRevocation?: SubjectRevocation;
}

export const createDeviceVerificationHandler = (
	options: DeviceVerificationHandlerOptions,
): RequestHandler => {
	// The type requires it; a caller the type cannot reach is refused here,
	// where the composition is assembled, rather than answered 503 on every
	// request as if the store were down.
	if (typeof options.userSessionStore?.get !== "function") {
		throw new TypeError(
			"createDeviceVerificationHandler: userSessionStore is required — every action reads " +
				"the live UserSession behind the cookie's sid before it is answered",
		);
	}
	// Likewise the resolver — missing, or one the planner did not build:
	// refused here, not answered 500 on every request.
	const requirements = checkResolver(
		options.requirements,
		"createDeviceVerificationHandler",
		Object.values(ADMITTED_AS),
	);
	const now = options.now ?? Date.now;
	// Admission's dependencies: this handler's own slots and clock.
	const admissionDeps: AdmissionDeps = {
		userSessionStore: options.userSessionStore,
		subjectRevocation: options.subjectRevocation,
		requirements,
		acrTable: NO_ACR_TABLE,
		logger: admissionLogger(options.logger),
		auditSink: options.auditSink,
		now: () => new Date(now()),
	};
	// The guard's check with its outage policy attached — see the file header.
	const policy = createRateLimitPolicy(
		{
			limiter: options.rateLimiter,
			tag: DEVICE_VERIFICATION_RATE_LIMIT_PREFIX,
			...(hasErrorChannel(options.logger) ? { logger: options.logger } : {}),
			...(options.auditSink === undefined ? {} : { auditSink: options.auditSink }),
		},
		"createDeviceVerificationHandler",
	);

	return async (req: Request, res: Response): Promise<void> => {
		// JSON only — see the file header. Checked on the request's media
		// type rather than inferred from whether `req.body` has fields, so
		// the rule holds whatever parsed the body before this handler ran.
		if (!req.is("application/json")) {
			respond(res, 415, {
				error: "invalid_request",
				error_description: "the request body must be application/json",
			});
			return;
		}

		// The body first — see the file header.
		const body = (req.body ?? {}) as Record<string, unknown>;
		const action = body.action;
		if (!isAction(action)) {
			respond(res, 400, {
				error: "invalid_request",
				error_description: `action must be one of: ${ACTIONS.join(", ")}`,
			});
			return;
		}

		// Then the session behind the cookie, before anything else is asked.
		// `req.session` is the session middleware's field, which this package
		// does not type: it reads the cookie's claim through core's reading.
		const admission = await admitSession(admissionDeps, {
			claim: cookieClaim(req as CookieCarrier),
			action: ADMITTED_AS[action],
		});
		const session = admission.outcome === "admitted" ? admission.session : null;
		if (session === null) {
			const refusal = refusalOf(admission);
			respond(res, refusal.status, refusal.body);
			return;
		}
		const subject = session.sub;

		// What an approval records, held to the store's own rule: refused, and
		// answered, when the store would not record it at `atMs`.
		const amr = wellFormedAmr(vouchedAmr(session));
		const authTime = session.authTime;
		const refusedToRecord = (atMs: number): boolean => {
			const recorded = { atMs, amr, authTime };
			try {
				recordableDeviceApproval(recorded, recorded.atMs);
				return false;
			} catch {
				(options.logger ?? consoleLogger).warn(
					{ sid: session.sid, aheadMs: authTime.getTime() - atMs },
					"auth_time_ahead_of_clock",
				);
				const refusal = loginRequired(SIGN_IN_AGAIN);
				respond(res, refusal.status, refusal.body);
				return true;
			}
		};
		// Before the email gate, the budget and the code — see the file header.
		if (action === "approve" && refusedToRecord(now())) return;

		// Before the budget and the code — see the file header.
		if (
			action === "approve" &&
			options.requireEmailVerified &&
			!isEmailVerified(cookieUserOf(req))
		) {
			respond(res, 403, {
				error: "access_denied",
				error_description: "email address is not verified",
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
			// The limiter had no answer, so its own `failMode` decides. The
			// shared check already logged and audited the outage; `open`
			// serves the request exactly as the guard would.
			if (budget.failMode === "closed") {
				respond(res, 503, { ...rateLimiterUnavailableEnvelope() });
				return;
			}
		} else if (!budget.decision.allowed) {
			// A limiter that answered "no" is not an outage: this is the signal
			// that an account is guessing codes, under either fail mode.
			const { decision } = budget;
			(options.logger ?? consoleLogger).warn(
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
				error_description: "that code is not valid; check it and try again",
			});
			return;
		}

		// The store judges the code's expiry by this instant, so it is taken after
		// the budget, which may wait on its backend.
		const nowMs = now();

		/**
		 * The store could not answer: an outage, not a verdict on the code.
		 * The line names the action and not the subject, as the route's
		 * `device_route_unexpected_error` does not.
		 */
		const storeUnavailable = (err: unknown): void => {
			reportDeviceCodeStoreOutage(options.logger, "device_verification_store_unavailable", err, {
				action,
			});
			respond(res, 503, {
				error: DEVICE_CODE_STORE_UNAVAILABLE.error,
				error_description: DEVICE_CODE_STORE_UNAVAILABLE.description,
			});
		};

		/** The store answered a record, or a wrapper around it, nothing can be read of: answered as an outage. */
		const recordUnreadable = (refusal: DeviceAuthorizationRefusal | StoreAnswerRefusal): void => {
			reportUnreadableDeviceAuthorization(
				options.logger,
				"device_verification_record_unreadable",
				refusal,
				{ action },
			);
			respond(res, 503, {
				error: DEVICE_CODE_STORE_UNAVAILABLE.error,
				error_description: DEVICE_CODE_STORE_UNAVAILABLE.description,
			});
		};

		/**
		 * The store may have recorded the decision, and the device's poll may
		 * then get tokens no `device.approved` accounts for, so the unknown
		 * outcome is audited, attributed to the subject. It names no client: the
		 * record could not be read.
		 */
		const auditUnknownOutcome = (): void => {
			emitAuditEvent(options.auditSink, {
				timestamp: new Date(),
				type: "device.decision_outcome_unknown",
				subject,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { action },
			});
		};

		if (action === "lookup") {
			let pending: Awaited<ReturnType<typeof options.store.findPendingByUserCode>>;
			try {
				pending = await options.store.findPendingByUserCode(userCode, nowMs);
			} catch (err) {
				storeUnavailable(err);
				return;
			}
			if (pending === null) {
				respond(res, 404, {
					error: "invalid_user_code",
					error_description: "that code is not valid; check it and try again",
				});
				return;
			}
			const reading = readDeviceAuthorization(pending);
			if (!reading.ok) {
				recordUnreadable(reading);
				return;
			}
			const { authorization } = reading;
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

		// `grantedScope` is deliberately omitted: the port grants
		// `requestedScope`, which was settled and filtered against the
		// client's allowlist when the device asked. Re-reading it here to pass
		// it back would open a window between the lookup that showed the user
		// a scope and the write that grants one.
		// Held to the store's rule again, on the instant the store is handed, so
		// a store error stays an outage.
		if (action === "approve" && refusedToRecord(nowMs)) return;
		const approval: ApproveDeviceAuthorizationInput | undefined =
			action === "approve" ? { userCode, subject, nowMs, amr, authTime } : undefined;

		let answered: unknown;
		try {
			answered =
				approval !== undefined
					? await options.store.approve(approval)
					: await options.store.deny(userCode, nowMs);
		} catch (err) {
			// The reply was lost, the decision perhaps recorded before it.
			auditUnknownOutcome();
			storeUnavailable(err);
			return;
		}
		// An answer that cannot be read says nothing of whether the decision landed.
		const read = readDecisionOutcome(answered);
		if (!read.ok) {
			auditUnknownOutcome();
			recordUnreadable(read);
			return;
		}
		const outcome = read.answer;

		switch (outcome.status) {
			case "ok": {
				const reading = readDeviceAuthorization(outcome.authorization);
				if (!reading.ok) {
					auditUnknownOutcome();
					recordUnreadable(reading);
					return;
				}
				const { authorization } = reading;
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
					error_description: "that code has expired; start again on the device",
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
					error_description: "that code is not valid; check it and try again",
				});
		}
	};
};
