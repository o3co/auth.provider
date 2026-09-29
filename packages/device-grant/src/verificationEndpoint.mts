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
 * A device-code **store** outage is the other outage here, and gets the
 * product's answer for one (`storeOutage.mts`): `503 temporarily_unavailable`,
 * logged at error as `device_verification_store_unavailable` — not a `500`
 * through the terminal handler, and not an answer about the code. A 503 on an
 * approval or a denial does not say nothing was decided: the store's script
 * may have run before its reply was lost, and a retry then answers
 * `409 already_decided`. Such an outcome is audited as
 * `device.decision_outcome_unknown`, with the subject, as the decision itself
 * would have been.
 *
 * ### The body first, then the session behind the cookie
 *
 * Which action the body asks for decides what admission is asked about, so
 * the body's `action` is read before anything else: an action this endpoint
 * does not implement is `400 invalid_request` before a signed-out cookie's
 * `401` and before a store outage's `503` (the session-admission ADR's D8).
 *
 * Then the session is admitted — core's `admitSession`, the one reading
 * every consumer of an authenticated browser session shares — on the
 * cookie's claim (`cookieClaim`) and the action's own name, one per body
 * action: `device.lookup`, `device.approve`, `device.deny`, all graded
 * `use` (`ADMISSION_ACTIONS`, the ADR's D4). `isAuthenticated` is what the
 * cookie claims; the `UserSession` its `sid` names is the fact. A logout, a
 * `revokeAllForSubject` or a record deleted out of band ends the record and
 * leaves the cookie as it was — and the approval is the one point that can
 * see it: the device token it leads to carries no `sid` and no `family_id`,
 * so no logout reaches that token afterwards, and a subject watermark
 * stamped before the approval is older than the token's `iat`. (A watermark
 * stamped after the token is minted does reach it, at `verifyJwt`; the
 * window between the approval and the poll is closed at the poll, by the
 * grant — see `grant.mts`.) So admission reads the record: a `sid` the store
 * holds, recording the cookie's own subject, not past its `expiresAt` on
 * this handler's clock, and — with `subjectRevocation` wired — authenticated
 * after the subject's sessions boundary (`revokeAllForSubject` stamps it
 * before it deletes the sessions, so a cascade that failed for one, or a
 * session the subject index never learnt of, leaves a record the boundary
 * has ended). Then it asks the registered session requirements. The module
 * refuses to boot an enabled grant without a store, and this handler
 * refuses to be built without one, or without the resolver the planner
 * built (core's `checkResolver`), so there is no cookie-only mode and no
 * admission the planner did not build.
 *
 * What each admission is answered with is this endpoint's, a JSON API a page
 * calls: a new login is the remedy for every session that cannot be used,
 * so all of them are `401 login_required`, each with the description it had
 * — a signed-out cookie, or one that names no user, "an authenticated
 * end-user session is required to approve a device"; a cookie with no `sid`,
 * "session identifier (sid) is required", so a login of the deployment's own
 * that set `isAuthenticated` and `user.id` without the `UserSession` is told
 * what is missing; a record gone, expired, another subject's or covered by
 * the boundary, "the session is no longer active; sign in again" — and a
 * requirement's `reauthenticate` or `unmet` "sign in again to continue": the
 * page has no other remedy to offer a device. A `step_up` is
 * `403 step_up_required` with the `requirement` that asked and its `page` —
 * the requirement's registered step-up page as an absolute URL on the
 * issuer, its params on the query and no return parameter, since the page
 * that called knows where it returns (the ADR's D8: a browser-facing
 * consumer answers the page) — on any of the three actions: the MFA requirement never steps up `lookup` or `deny` (a
 * user refuses a phished device request without one, the ADR's D6), but
 * another requirement may. An outage — the store, the boundary, or a
 * requirement that throws — fails closed as `503 temporarily_unavailable`,
 * described by what could not answer as `/oauth/consent` describes it
 * (core's `describeAdmissionOutage`: "session store unavailable",
 * "revocation store unavailable" or "session requirement unavailable"), not
 * `login_required`, which would tell the page the user is signed out when
 * the store said nothing. Admission writes the lines — one at error for an
 * outage (`session_admission_unavailable`, with the store and the action,
 * never the `sid`), one at warn for a record of another subject
 * (`session_admission_subject_mismatch`, audited as
 * `session.admission.subject_mismatch` with the `sid`) — through this
 * handler's logger, core's console logger when none is wired. Every
 * refusal comes before the budget is spent and before the code is read.
 *
 * ### `oauth.requireEmailVerified` holds an approval as it holds issuance
 *
 * `/authorize` and the session grant refuse a user the Store has not
 * published a verified email for (#297); an approval is what the device's
 * token is issued from, so `approve` is refused the same way —
 * `403 access_denied`, the code `/authorize` answers it with. Only `approve`:
 * a lookup shows the user what is asked, and a denial issues nothing. The
 * refusal comes before the budget is spent and before the code is read, so
 * it is neither an attempt nor an oracle.
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
 * ### JSON only, whatever parsed the body
 *
 * A form body — `application/x-www-form-urlencoded`, `multipart/form-data`,
 * `text/plain` — is a CORS "simple" request: a browser sends it cross-site
 * with the user's session cookie and no preflight, which is RFC 8628 §5.4's
 * remote-phishing attack in one auto-submitting form. `application/json` is
 * preflighted. So this handler answers anything that is not
 * `application/json` with `415 invalid_request` before it reads a field.
 *
 * It checks the media type itself rather than relying on no form parser
 * having run. In the route `deviceGrantModule` mounts none has — it mounts
 * JSON only, and `oauthModule`'s router beside it parses its own routes
 * only — but a composition that mounts this handler by hand may put one in
 * front of it, and the rule is the endpoint's either way.
 *
 * ### The origin check is the module's, and runs first
 *
 * This handler runs no body parser and no origin check. The router
 * `deviceGrantModule` mounts parses JSON and runs the session package's CSRF
 * guard ahead of it (see `module.mts`); a composition that mounts this
 * handler by hand must do the same. So a cross-site form is refused by the
 * guard, `403 access_denied`, before this handler sees it: only a request
 * the guard lets through can be answered `415`.
 */

import type {
	Admission,
	AdmissionAction,
	AdmissionDeps,
	Logger,
	RateLimitContext,
	RateLimiter,
	RateLimitFailMode,
	RateLimitOutageLogger,
	SessionRequirementResolver,
	SubjectRevocation,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	ADMISSION_ACTIONS,
	admitSession,
	checkCanonicalIssuer,
	checkResolver,
	checkWithFailMode,
	consoleLogger,
	cookieClaim,
	describeAdmissionOutage,
	describeIssuerRejection,
	emitAuditEvent,
	isEmailVerified,
	normaliseUserCode,
	rateLimiterUnavailableEnvelope,
	stepUpPageUrl,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { DEVICE_CODE_STORE_UNAVAILABLE, reportDeviceCodeStoreOutage } from "./storeOutage.mjs";
import { DEVICE_VERIFICATION_RATE_LIMIT_PREFIX, type DeviceGrantDependencies } from "./types.mjs";

type Action = "lookup" | "approve" | "deny";

const ACTIONS: readonly Action[] = ["lookup", "approve", "deny"];

const isAction = (value: unknown): value is Action =>
	typeof value === "string" && (ACTIONS as readonly string[]).includes(value);

/** Each body action as admission is asked about it: its own name, graded `use` (the session-admission ADR's D4). */
const ADMITTED_AS: Readonly<Record<Action, AdmissionAction>> = {
	lookup: ADMISSION_ACTIONS["device.lookup"],
	approve: ADMISSION_ACTIONS["device.approve"],
	deny: ADMISSION_ACTIONS["device.deny"],
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

/** The three descriptions `401 login_required` had before admission, and the one it adds. */
const NO_SESSION = "an authenticated end-user session is required to approve a device";
const NO_SID = "session identifier (sid) is required";
const ENDED = "the session is no longer active; sign in again";
const SIGN_IN_AGAIN = "sign in again to continue";

const loginRequired = (description: string) =>
	({ status: 401, body: { error: "login_required", error_description: description } }) as const;

/**
 * What an admission that did not admit a live session is answered with —
 * see the file header. An `admitted` without a record is one a handler
 * built with a store is never given, and is refused with the rest.
 */
const refusalOf = (
	admission: Admission,
	issuer: string,
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
					// Where the step-up starts, as every consumer answers it (core's
					// `stepUpPageUrl`). No return parameter: the deployment's
					// verification page knows where it comes back to.
					page: stepUpPageUrl(admission.page, issuer),
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
	/**
	 * Required: where admission reads the `UserSession` behind the cookie's
	 * `sid` — see the file header. Without it an approval would rest on the
	 * cookie's word alone, which is the defect the read closes.
	 */
	readonly userSessionStore: UserSessionStore;
	/**
	 * Required: the synthetic key `sessionRequirementResolver` the boot
	 * planner built (`resolverForTests` in a test) — the registered session
	 * requirements admission asks (the session-admission ADR's D1). Admission
	 * refuses any other object.
	 */
	readonly requirements: SessionRequirementResolver;
	/**
	 * Required: `oauth.jwt.issuer`, held to core's `checkCanonicalIssuer` — an
	 * absolute `https:` URL (`http:` on a loopback host) — what a step-up
	 * page, which may be a path, is answered on (see the file header).
	 */
	readonly issuer: string;
	/**
	 * `oauth.requireEmailVerified` (#297), resolved. Required rather than
	 * defaulted, so a composition that mounts this handler by hand states
	 * whether the gate holds instead of losing it by omission.
	 */
	readonly requireEmailVerified: boolean;
	/**
	 * Where admission reads the subject's sessions boundary (see the file
	 * header). Optional as it is at every surface that reads it: a
	 * composition that declared subject-level revocation absent has no
	 * boundary to honour.
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
	// Likewise the resolver — missing, or one the planner did not build — and
	// the issuer: refused here, not answered 500 on every request. The issuer
	// is held to core's canonical rule, the one `oauth.jwt.issuer` is held to:
	// `URL.canParse` also accepts `mailto:` or `urn:`, on which no page can be
	// resolved, so the first step-up would throw.
	const requirements = checkResolver(options.requirements, "createDeviceVerificationHandler");
	const issuerRejection = checkCanonicalIssuer(options.issuer);
	if (issuerRejection !== null) {
		throw new TypeError(
			`createDeviceVerificationHandler: issuer ${describeIssuerRejection(issuerRejection)} — ` +
				"it is oauth.jwt.issuer, on which a step-up page is answered",
		);
	}
	// `checkCanonicalIssuer` returned null above, which only a string satisfies.
	const issuer = options.issuer;
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
	const policy = {
		limiter: options.rateLimiter,
		tag: DEVICE_VERIFICATION_RATE_LIMIT_PREFIX,
		failMode: options.failMode,
		logger: hasErrorChannel(options.logger) ? options.logger : undefined,
		auditSink: options.auditSink,
	};

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
		const admission = await admitSession(admissionDeps, {
			claim: cookieClaim(req),
			action: ADMITTED_AS[action],
		});
		const session = admission.outcome === "admitted" ? admission.session : null;
		if (session === null) {
			const refusal = refusalOf(admission, issuer);
			respond(res, refusal.status, refusal.body);
			return;
		}
		const subject = session.sub;

		// #297, before the budget and the code — see the file header.
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

		if (action === "lookup") {
			let authorization: Awaited<ReturnType<typeof options.store.findPendingByUserCode>>;
			try {
				authorization = await options.store.findPendingByUserCode(userCode, nowMs);
			} catch (err) {
				storeUnavailable(err);
				return;
			}
			if (authorization === null) {
				respond(res, 404, {
					error: "invalid_user_code",
					error_description: "that code is not valid; check it and try again",
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

		let outcome: Awaited<ReturnType<typeof options.store.approve>>;
		try {
			outcome =
				action === "approve"
					? // `grantedScope` is deliberately omitted: the port grants
						// `requestedScope`, which was settled and filtered against the
						// client's allowlist when the device asked. Re-reading it here
						// to pass it back would open a window between the lookup that
						// showed the user a scope and the write that grants one.
						await options.store.approve({ userCode, subject, nowMs })
					: await options.store.deny(userCode, nowMs);
		} catch (err) {
			// The store may have recorded the decision before its reply was lost
			// — a timeout or a reset after the command was sent — and the device's
			// poll can then be handed tokens that no `device.approved` accounts
			// for. So an outcome nobody knows is audited as one, attributed as
			// the decision would have been: the subject, the action, the
			// request's address. It names no client, since the record could not
			// be read. (The log line names no subject; an audit event is where a
			// decision is attributed.)
			emitAuditEvent(options.auditSink, {
				timestamp: new Date(),
				type: "device.decision_outcome_unknown",
				subject,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { action },
			});
			storeUnavailable(err);
			return;
		}

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
