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
 * `webauthnSessionSubjectModule` — the bridge from the browser's cookie
 * session to `req.webauthnSubject`, which the two registration routes
 * require, as a module the deployment installs instead of writing (the
 * session-admission ADR's D8).
 *
 * Its one route runs on `POST /oauth/webauthn/registration/options` and
 * `/verify`, after `session-middleware` and before both registration
 * routes, and reads the session through core's `admitSession` as
 * `webauthn.register` — graded `credential_change`: a passkey is a new way
 * into the account, so a requirement's recent-authentication rule applies.
 * `admitted` sets the subject the deployment's `subjectFor` maps the live
 * record to (the README requires an opaque `userId`; the answer is held to
 * the subject's shape, and one that is not is `500 server_error`, logged
 * once as `webauthn_session_subject_invalid`); `unavailable` is
 * `503 temporarily_unavailable`, described by what failed (core's
 * `describeAdmissionOutage`), logged once by admission; `step_up` is
 * `403 step_up_required` with the requirement and its page — as registered,
 * one absolute URL resolved on the issuer at registration, as every
 * consumer answers it;
 * a browser that is not signed in passes on untouched (a bearer bridge's
 * subject stands); every other outcome clears any subject an earlier
 * middleware set, and the route answers its own `401`.
 *
 * It requires `userSessionStore`: the cookie path it serves is the
 * store-backed one, so an admitted session is always a record the mapper can
 * read. A subject taken from a bearer token, and a cookie-only composition
 * without a store, stay the deployment's own middleware.
 */

import {
	ADMISSION_ACTIONS,
	AUDIT_SINK_ABSENCE_POLICY,
	admitSession,
	type CookieCarrier,
	checkResolver,
	consoleLogger,
	cookieClaim,
	defineModule,
	describeAdmissionOutage,
	loggableError,
	type Module,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
	type UserSession,
} from "@o3co/auth-provider-core";
import express, { type RequestHandler, type Response } from "express";
import type { WebAuthnSubject } from "./request.mjs";

/** The id of the module's one route. */
export const WEBAUTHN_SESSION_SUBJECT_ROUTE_ID = "webauthn-session-subject";

/** What the deployment gives the module. */
export interface WebAuthnSessionSubjectOptions {
	/**
	 * The WebAuthn subject for an admitted session — synchronous, called with
	 * the live `UserSession` admission read. `userId` is the user handle an
	 * authenticator stores and may sync: opaque, 1–64 bytes, never an e-mail
	 * or a username (WebAuthn §5.4.3; the README's "`userId` opacity").
	 */
	readonly subjectFor: (session: UserSession) => WebAuthnSubject;
}

/** The registration routes ask admission for no `acr_values`: the table it selects against is empty. */
const NO_ACR_TABLE = Object.freeze({});

const isOptionalString = (value: unknown): value is string | undefined =>
	value === undefined || typeof value === "string";

/** The subject `answer` is, copied to its three fields, or `undefined` when it is not one. */
function subjectOf(answer: unknown): WebAuthnSubject | undefined {
	if (typeof answer !== "object" || answer === null) return undefined;
	const { userId, userName, userDisplayName } = answer as Record<string, unknown>;
	if (typeof userId !== "string" || userId.length === 0) return undefined;
	if (!isOptionalString(userName) || !isOptionalString(userDisplayName)) return undefined;
	return {
		userId,
		...(userName === undefined ? {} : { userName }),
		...(userDisplayName === undefined ? {} : { userDisplayName }),
	};
}

const refuseInvalidSubject = (res: Response): void => {
	res.status(500).json({
		error: "server_error",
		error_description: "subjectFor did not answer a WebAuthn subject",
	});
};

/**
 * The module (the session-admission ADR's D8): requires the resolver and
 * the user-session store; takes `subjectRevocation`, `auditSink` and
 * `logger` when they are wired, the first two under their shared absence
 * policies. Throws a `TypeError` when `subjectFor` is not a function, and
 * its route factory a `RangeError` for a resolver missing or not the
 * planner's (core's `checkResolver`).
 */
export function webauthnSessionSubjectModule(options: WebAuthnSessionSubjectOptions): Module {
	if (typeof options !== "object" || options === null || typeof options.subjectFor !== "function") {
		throw new TypeError(
			"webauthnSessionSubjectModule: subjectFor must be a function mapping a UserSession to a WebAuthnSubject",
		);
	}
	const { subjectFor } = options;
	return defineModule<
		"sessionRequirementResolver" | "userSessionStore",
		"subjectRevocation" | "auditSink" | "logger"
	>({
		name: "webauthn-session-subject",
		requires: ["sessionRequirementResolver", "userSessionStore"],
		optional: ["subjectRevocation", "auditSink", "logger"],
		// Optional to wire, not optional to decide — the same constants every
		// module attaches to these keys, which the declared-absence check
		// requires to agree.
		absencePolicies: {
			subjectRevocation: SUBJECT_REVOCATION_ABSENCE_POLICY,
			auditSink: AUDIT_SINK_ABSENCE_POLICY,
		},
		contributes: {
			routes: [
				(deps) => {
					// Refused here, when the route is built — a missing resolver, or
					// one the planner did not build — not on the first request.
					const requirements = checkResolver(
						deps.sessionRequirementResolver,
						"webauthnSessionSubjectModule",
					);
					const logger = deps.logger ?? consoleLogger;
					const admitRegistration: RequestHandler = async (req, res, next) => {
						const admission = await admitSession(
							{
								userSessionStore: deps.userSessionStore,
								subjectRevocation: deps.subjectRevocation,
								requirements,
								acrTable: NO_ACR_TABLE,
								logger,
								auditSink: deps.auditSink,
							},
							{
								// express-session's `req.session`, read without its type package.
								claim: cookieClaim(req as unknown as CookieCarrier),
								action: ADMISSION_ACTIONS["webauthn.register"],
							},
						);
						if (admission.outcome === "unavailable") {
							res.status(503).json({
								error: "temporarily_unavailable",
								error_description: describeAdmissionOutage(admission.store),
							});
							return;
						}
						if (admission.outcome === "step_up") {
							res.status(403).json({
								error: "step_up_required",
								error_description: "Registering a passkey requires a step-up first",
								requirement: admission.requirement,
								// Where the step-up starts, as registered — resolved then on
								// the issuer, not on the account page's origin. No return
								// parameter: the account page knows where it comes back to.
								page: admission.page.href,
							});
							return;
						}
						// Not signed in: this module has nothing to say, and a subject an
						// earlier middleware set — a bearer-token bridge — stands.
						if (admission.outcome === "unauthenticated") {
							next();
							return;
						}
						// A cookie session that is not live, is revoked, or a requirement
						// does not admit: no subject — one an earlier middleware set is
						// cleared, so a dead session registers nothing — and the
						// registration route answers its own 401.
						if (admission.outcome !== "admitted" || admission.session === null) {
							delete req.webauthnSubject;
							next();
							return;
						}
						let subject: WebAuthnSubject | undefined;
						try {
							// The answer is read inside the try: a field that throws when
							// it is read is the mapper's failure, as a throw of its own is.
							subject = subjectOf(subjectFor(admission.session));
						} catch (err) {
							// The deployment's mapper failed: its fault, not the user's.
							logger.error(
								{ reason: "threw", err: loggableError(err) },
								"webauthn_session_subject_invalid",
							);
							refuseInvalidSubject(res);
							return;
						}
						if (subject === undefined) {
							// Said without the answer: what it carries may be the very
							// identifier the handle must not be.
							logger.error({ reason: "shape" }, "webauthn_session_subject_invalid");
							refuseInvalidSubject(res);
							return;
						}
						req.webauthnSubject = subject;
						next();
					};
					// The two registration POSTs, on this router's own paths: core
					// mounts it by prefix, and nothing else beneath the path reads a
					// session through it.
					const router = express.Router();
					router.post(["/options", "/verify"], admitRegistration);
					return {
						id: WEBAUTHN_SESSION_SUBJECT_ROUTE_ID,
						mountPath: "/oauth/webauthn/registration",
						after: ["session-middleware"],
						before: ["webauthn-registration-options", "webauthn-registration-verify"],
						handler: router,
					};
				},
			],
		},
	});
}
