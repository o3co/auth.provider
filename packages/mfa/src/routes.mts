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
 * The MFA routes under `/session/mfa`: `GET /transaction`, `POST /challenge`,
 * `POST /verify`, an enrollment — a login's first binding, or one from a
 * signed-in session — `POST /enrollment` and `POST /enrollment/complete`,
 * and a session's step-up, `POST /step-up`, over the coordinator; a
 * verified second factor, or a factor bound at a login, resumes the login
 * through core's `resumePrimary` and finishes it through the
 * `loginCompletion` slot. See README, "The routes".
 *
 * - Every answer is `no-store`. Bodies are parsed on these paths alone.
 * - Every POST sits behind the deployment's CSRF guard, then the flood guard
 *   (`mfa:ip:<ip>`), before anything is read.
 * - The transaction id is read from the body or the `MFA-Transaction` header,
 *   never from the URL, and never logged; a missing, malformed, foreign,
 *   spent or expired one is answered alike.
 * - A signed-in session is admitted before its transaction is read: as
 *   `mfa.manage` to enroll, and through the step-up's remediation for its
 *   proof; its `User` is the one its cookie holds (`cookieSessionUser`).
 *   The step-up asks the requirement, as `mfa.manage`, what a first binding
 *   in the session is answered, and opens the proof only where it would not
 *   be refused outright; another requirement's step-up is answered as its
 *   own. Requirements are asked in order and the first that is not met
 *   answers, so where this one's gate asks the proof, the trip opens before
 *   a later requirement is asked, and that one may still hold the binding
 *   back once the proof is given. A binding in a session that the subject's
 *   factors no longer allow is `409`: the session stands.
 * - A factor bound beside another that cannot stand — past the limit, or
 *   its records unreadable — and cannot be removed stands: it is audited as
 *   enrolled and said once at error before the `503`.
 * - A factor's own failure is logged by its name and code, never its text.
 * - Each outage is answered `503` and logged once, at error. A mail the
 *   sender refused at its limit is `429`; a factor whose recorded address no
 *   longer matches the login's is `403`, recorded as
 *   `mfa.email_address_mismatch`. Neither the code nor the address is logged.
 * - A guessable proof the subject lock holds is `429 mfa_locked`, with the
 *   hold, the kinds that still work, and `Retry-After` in whole seconds
 *   rounded up — none for the hard hold — recorded as `mfa.locked`, and
 *   also as `mfa.locked.first` when it begins an episode.
 * - A recovery code spent answers, and records as `mfa.recovery_code.used`,
 *   how many codes the set has left.
 */

import {
	type Admission,
	type AdmissionDeps,
	type AuditSink,
	admitSession,
	type CookieCarrier,
	type CsrfGuard,
	cookieClaim,
	cookieSessionUser,
	describeAdmissionOutage,
	emitAuditEvent,
	errorEnvelope,
	type IssuedRemediationAction,
	isMfaFactorId,
	type Logger,
	type LoginCompletion,
	loggableError,
	type PrimaryAdmission,
	resumePrimary,
} from "@o3co/auth-provider-core";
import express, { type Request, type RequestHandler, type Response, type Router } from "express";
import type { MfaAdmissionAction } from "./admissionActions.mjs";
import type {
	MfaCeremonyCall,
	MfaCeremonySession,
	MfaFactorUnreadable,
	MfaStoreOutage,
	MfaVerifyOutcome,
} from "./ceremony.mjs";
import type { MfaCoordinator } from "./coordinator.mjs";
import { type MfaMailRefusal, mailFailureOf } from "./mail.mjs";
import { RECOVERY_CODE_FACTOR_KIND } from "./recovery/factor.mjs";
import { MFA_REQUIREMENT_NAME } from "./requirement.mjs";
import type { MfaWitnessMark } from "./witness.mjs";

/** The header a transaction id may travel in beside the body. */
const TRANSACTION_HEADER = "MFA-Transaction";

const UNKNOWN_TRANSACTION = errorEnvelope("invalid_request", "Unknown or expired MFA transaction");
const UNKNOWN_FACTOR = errorEnvelope("invalid_request", "Unknown second factor");
const MFA_UNAVAILABLE = errorEnvelope("temporarily_unavailable", "MFA temporarily unavailable");
const SESSION_STORE_UNAVAILABLE = errorEnvelope(
	"temporarily_unavailable",
	"Session store unavailable",
);
const LOGIN_REQUIRED = errorEnvelope("login_required", "Log in again");
const ENROLLMENT_REQUIRED = errorEnvelope(
	"mfa_enrollment_required",
	"A second factor that counts must be enrolled",
);
const FACTOR_REFUSED = errorEnvelope(
	"mfa_factor_refused",
	"This second factor cannot be used: use another",
);
const MAIL_LIMITED = errorEnvelope("rate_limited", "Too many codes sent: try again later");
const NOT_OPEN = errorEnvelope("invalid_request", "No enrollment is open in this MFA transaction");
const NO_PENDING = errorEnvelope(
	"invalid_request",
	"No enrollment is pending in this MFA transaction",
);
const UNKNOWN_KIND = errorEnvelope("invalid_request", "Unknown second factor kind");
const INVALID_LABEL = errorEnvelope("invalid_request", "Invalid label");
const EMAIL_PROOF_REQUIRED = errorEnvelope(
	"mfa_email_proof_required",
	"The account-email proof comes first",
);
const EMAIL_PROOF_UNAVAILABLE = errorEnvelope(
	"mfa_email_proof_unavailable",
	"The account-email proof cannot be given for this account",
);
const FACTOR_LIMIT = errorEnvelope(
	"mfa_factor_limit",
	"The subject holds as many second factors as it may",
);
const NOT_FOUND = errorEnvelope("not_found", "Not found");
const ENROLLMENT_CONFLICT = errorEnvelope(
	"mfa_enrollment_conflict",
	"The account's second factors changed while enrolling: start again",
);

/** What adding a factor from a session is admitted as: it adds a way into the account. */
const MFA_MANAGE: MfaAdmissionAction = "mfa.manage";

/** A proof the subject lock held, unchecked: the hold, and the kinds that still work. */
const locked = (hold: string, usableKinds: readonly string[]) => ({
	...errorEnvelope(
		"mfa_locked",
		"Too many failed attempts: use another second factor, or try later",
	),
	hold,
	usable_kinds: usableKinds,
});

/** A refused proof, with the attempts the transaction has left. */
const notAccepted = (attemptsRemaining: number) => ({
	...errorEnvelope("mfa_invalid", "Second factor not accepted"),
	attempts_remaining: attemptsRemaining,
});

/** Which route a line is logged by: the enrollment's two share one name. */
type RouteName = "transaction" | "challenge" | "verify" | "enrollment" | "step-up";

export interface MfaRoutesOptions {
	readonly coordinator: MfaCoordinator;
	/**
	 * What `admitSession` and `resumePrimary` are handed: the registered
	 * requirements, the session store, the subjects' revocation boundary, the
	 * logger.
	 */
	readonly admission: AdmissionDeps;
	/** The `mfa.step_up` remediation core issued the requirement: what the step-up's trip is admitted as. */
	readonly stepUp: IssuedRemediationAction;
	readonly loginCompletion: LoginCompletion;
	/** The deployment's CSRF guard: every POST runs its middleware, and a login it completes is handed a fresh token. */
	readonly csrfGuard: CsrfGuard;
	/** The flood guard every POST runs after the CSRF guard. */
	readonly floodGuard: RequestHandler;
	readonly logger: Logger;
	readonly auditSink: AuditSink | undefined;
}

/** The express session id the request presents; empty when it presents none, which no binding matches. */
const sessionIdOf = (req: Request): string => {
	const id: unknown = (req as { sessionID?: unknown }).sessionID;
	return typeof id === "string" ? id : "";
};

/** A header's value when it carries one. */
const headerOf = (req: Request, name: string): string | undefined => {
	const value = req.get(name);
	return typeof value === "string" && value !== "" ? value : undefined;
};

/**
 * The transaction a POST names: its body's `transaction_id`, or the
 * header's — `undefined` for none — or `"disagree"` when the two name
 * different ones.
 */
const postedTransaction = (req: Request): { readonly id: string | undefined } | "disagree" => {
	const posted: unknown = (req.body as { transaction_id?: unknown } | undefined)?.transaction_id;
	const body = typeof posted === "string" && posted !== "" ? posted : undefined;
	const header = headerOf(req, TRANSACTION_HEADER);
	if (body !== undefined && header !== undefined && body !== header) return "disagree";
	return { id: body ?? header };
};

/** The transaction id a POST names; two that disagree name none, which no transaction matches. */
const postedTransactionId = (req: Request): string | undefined => {
	const posted = postedTransaction(req);
	return posted === "disagree" ? undefined : posted.id;
};

/** The ceremony call a request makes, naming `transactionId`. */
const callOf = (req: Request, transactionId: string | undefined): MfaCeremonyCall => {
	const userAgent = headerOf(req, "user-agent");
	return {
		transactionId,
		binding: { kind: "session", id: sessionIdOf(req) },
		request: {
			...(typeof req.ip === "string" ? { ip: req.ip } : {}),
			...(userAgent === undefined ? {} : { userAgent }),
		},
	};
};

/** Every answer of these routes is kept by no cache. */
const noStore: RequestHandler = (_req, res, next) => {
	res.set("Cache-Control", "no-store");
	next();
};

/** The MFA routes' router (see this file's header). */
export function createMfaRouter(options: MfaRoutesOptions): Router {
	const {
		coordinator,
		admission,
		stepUp,
		loginCompletion,
		csrfGuard,
		floodGuard,
		logger,
		auditSink,
	} = options;
	const router = express.Router();

	/** The session the request's cookie carries, admitted for `action`. */
	const admitCookie = (
		req: Request,
		action: MfaAdmissionAction | IssuedRemediationAction,
	): Promise<Admission> =>
		// express-session's `req.session`, read without its type package.
		admitSession(admission, { claim: cookieClaim(req as unknown as CookieCarrier), action });

	/**
	 * A binding the subject's records no longer allow: a login starts again
	 * (`401 login_required`); a session, which stands, is told the factors
	 * changed (`409 mfa_enrollment_conflict`).
	 */
	const answerClosed = (res: Response, purpose: string): void => {
		if (purpose === "enroll") res.status(409).json(ENROLLMENT_CONFLICT);
		else res.status(401).json(LOGIN_REQUIRED);
	};

	/** An admission that is no session to go on: an outage `503`, anything else `401`. */
	const answerNoSession = (res: Response, admitted: Admission): void => {
		if (admitted.outcome === "unavailable") {
			// Admission logged it once.
			res
				.status(503)
				.json(errorEnvelope("temporarily_unavailable", describeAdmissionOutage(admitted.store)));
			return;
		}
		res.status(401).json(LOGIN_REQUIRED);
	};

	/** A requirement's step-up: `403 step_up_required`, naming the requirement and its page. */
	const answerStepUp = (res: Response, admitted: Extract<Admission, { outcome: "step_up" }>) => {
		res.status(403).json({
			error: "step_up_required",
			error_description: "This action requires a step-up first",
			requirement: admitted.requirement,
			page: admitted.page.href,
		});
	};

	/**
	 * The signed-in session the request's cookie carries, admitted for
	 * `action`, with the `User` its cookie holds; `undefined` once the refusal
	 * is answered — a requirement's step-up among them.
	 */
	const sessionFor = async (
		req: Request,
		res: Response,
		action: MfaAdmissionAction | IssuedRemediationAction,
	): Promise<MfaCeremonySession | undefined> => {
		const admitted = await admitCookie(req, action);
		if (admitted.outcome === "step_up") {
			answerStepUp(res, admitted);
			return undefined;
		}
		const session = admitted.outcome === "admitted" ? admitted.session : null;
		const user =
			session === null
				? undefined
				: cookieSessionUser(req as unknown as CookieCarrier, session.sub);
		if (session === null || user === undefined) {
			answerNoSession(res, admitted);
			return undefined;
		}
		return { sid: session.sid, subject: session.sub, user };
	};

	/**
	 * The call `req` makes, naming `transactionId`, in the session its cookie
	 * carries when it is signed in — admitted for `action` — and in none when
	 * it is not, as a login's ceremony is; `undefined` once a refusal is
	 * answered.
	 */
	const signedInCall = async (
		req: Request,
		res: Response,
		transactionId: string | undefined,
		action: MfaAdmissionAction | IssuedRemediationAction,
	): Promise<MfaCeremonyCall | undefined> => {
		const call = callOf(req, transactionId);
		if (!cookieClaim(req as unknown as CookieCarrier).authenticated) return call;
		const session = await sessionFor(req, res, action);
		return session === undefined ? undefined : { ...call, session };
	};

	const storeUnavailable = (
		route: RouteName,
		store: string,
		step: string,
		cause: unknown,
		context: { readonly sid?: string; readonly sub?: string } = {},
	): void => {
		logger.error(
			{ route, ...context, store, step, err: loggableError(cause) },
			"mfa_store_unavailable",
		);
	};

	/** An MFA store's outage or an unreadable factor: logged once, answered 503. */
	const answerOutage = (
		route: RouteName,
		res: Response,
		failure: MfaStoreOutage | MfaFactorUnreadable,
	): void => {
		if (failure.outcome === "unavailable") {
			storeUnavailable(route, failure.store, failure.step, failure.cause);
		} else {
			logger.error(
				{
					route,
					kind: failure.kind,
					...(isMfaFactorId(failure.factorId) ? { factorId: failure.factorId } : {}),
					state: failure.state,
					...(failure.keyId === undefined ? {} : { keyId: failure.keyId }),
					...(failure.cause === undefined
						? {}
						: {
								// A factor's own throw by its name and code alone: its text may quote the account.
								err:
									failure.state === "verification" || failure.state === "enrollment"
										? mailFailureOf(failure.cause)
										: loggableError(failure.cause),
							}),
				},
				"mfa_factor_unreadable",
			);
		}
		res.status(503).json(MFA_UNAVAILABLE);
	};

	/**
	 * A first binding that could not stand and whose factor could not be
	 * removed: the factor may be a password holder's, so it is said at error
	 * — the subject and the kind, never the factor's data.
	 */
	const factorStanding = (sub: string, kind: string, cause: unknown): void => {
		logger.error({ sub, kind, err: loggableError(cause) }, "mfa_first_binding_factor_standing");
	};

	/** A witness mark that failed: once at warn; what it followed stands, and the next login heals it. */
	const witnessUnwritten = (sub: string, mark: MfaWitnessMark | undefined): void => {
		if (mark?.outcome !== "unwritten") return;
		logger.warn({ sub, err: loggableError(mark.cause) }, "mfa_enrollment_witness_unwritten");
	};

	/** A mail the ceremony could not send: `429` at the sender's limit; else logged once and `503`. */
	const answerMail = (route: RouteName, res: Response, refusal: MfaMailRefusal): void => {
		if (refusal.outcome === "mail_refused_at_limit") {
			logger.warn(
				{ route, purpose: refusal.purpose, kind: refusal.kind, cleared: refusal.cleared },
				"mfa_mail_refused_at_limit",
			);
			res.status(429).json(MAIL_LIMITED);
			return;
		}
		// A sender's failure by its name, code and status: its text may quote the address or the code.
		logger.error(
			{
				route,
				purpose: refusal.purpose,
				kind: refusal.kind,
				reason: refusal.reason,
				...(refusal.cleared === undefined ? {} : { cleared: refusal.cleared }),
				...(refusal.cause === undefined ? {} : { err: mailFailureOf(refusal.cause) }),
			},
			"mfa_mail_unavailable",
		);
		res.status(503).json(MFA_UNAVAILABLE);
	};

	/**
	 * The login a verified second factor resumes: `resumePrimary`, then the
	 * session established, or another requirement's interruption answered. A
	 * continuation core refuses sends the user back to the password.
	 */
	const completeLogin = async (
		route: RouteName,
		req: Request,
		res: Response,
		verified: Pick<Extract<MfaVerifyOutcome, { outcome: "verified" }>, "continuation" | "adds">,
		answer: Readonly<Record<string, unknown>> = {},
	): Promise<void> => {
		let resumed: PrimaryAdmission;
		try {
			if (verified.continuation === undefined) {
				throw new RangeError("the login's transaction carries no continuation");
			}
			resumed = await resumePrimary(admission, verified.continuation, {
				requirement: MFA_REQUIREMENT_NAME,
				adds: verified.adds,
			});
		} catch (err) {
			if (!(err instanceof RangeError)) throw err;
			logger.warn({ err: loggableError(err) }, "mfa_login_not_resumed");
			res.status(401).json(LOGIN_REQUIRED);
			return;
		}
		if (resumed.outcome === "unavailable") {
			// Admission logged it once.
			res
				.status(503)
				.json(errorEnvelope("temporarily_unavailable", describeAdmissionOutage(resumed.store)));
			return;
		}
		if (resumed.outcome === "interrupt") {
			await loginCompletion.answerInterruption(resumed, {
				req,
				res,
				reporter: {
					storeUnavailable: (store, step, cause) => storeUnavailable(route, store, step, cause),
				},
			});
			return;
		}
		const established = await loginCompletion.establishSession(resumed.establishment, {
			req,
			reporter: ({ sid, sub }) => {
				const named = sid === undefined ? {} : { sid };
				return {
					storeUnavailable: (store, step, cause) =>
						storeUnavailable(
							route,
							store,
							step,
							cause,
							step === "create" ? { ...named, sub } : named,
						),
					cleanupFailed: (store, step, cause) =>
						logger.warn(
							{ ...named, store, step, err: loggableError(cause) },
							"mfa_login_cleanup_failed",
						),
					subjectIndexWriteFailed: (cause) =>
						logger.error(
							{ err: loggableError(cause), sub, ...named },
							"subject_session_index_write_failed",
						),
				};
			},
		});
		if (established.outcome === "unavailable") {
			res.status(503).json(SESSION_STORE_UNAVAILABLE);
			return;
		}
		csrfGuard.issue(res);
		res.status(200).json({ message: "Logged in successfully", ...answer });
	};

	router
		.all(
			["/transaction", "/challenge", "/verify", "/enrollment", "/enrollment/complete", "/step-up"],
			noStore,
		)
		// These paths' own bodies, parsed here: the mount is under `/session`,
		// where other modules mount routes too.
		.post(
			["/challenge", "/verify", "/enrollment", "/enrollment/complete", "/step-up"],
			express.json(),
			express.urlencoded({ extended: false }),
			csrfGuard.middleware,
			floodGuard,
		)
		.get("/transaction", async (req: Request, res: Response) => {
			// The id travels in the header alone: a GET has no body, and never a URL.
			const call = await signedInCall(req, res, headerOf(req, TRANSACTION_HEADER), stepUp);
			if (call === undefined) return;
			const outcome = await coordinator.describe(call);
			if (outcome.outcome === "unknown_transaction") {
				res.status(400).json(UNKNOWN_TRANSACTION);
				return;
			}
			if (outcome.outcome === "unavailable") {
				answerOutage("transaction", res, outcome);
				return;
			}
			const { view } = outcome;
			res.status(200).json({
				purpose: view.purpose,
				factors: view.factors,
				enrollment: view.enrollment,
				email_proof: view.emailProof,
				expires_in: view.expiresIn,
				attempts_remaining: view.attemptsRemaining,
			});
		})
		.post("/challenge", async (req: Request, res: Response) => {
			const call = await signedInCall(req, res, postedTransactionId(req), stepUp);
			if (call === undefined) return;
			const outcome = await coordinator.challenge({
				...call,
				factorId: (req.body as { factor_id?: unknown } | undefined)?.factor_id,
			});
			switch (outcome.outcome) {
				case "unknown_transaction":
					res.status(400).json(UNKNOWN_TRANSACTION);
					return;
				case "unknown_factor":
					res.status(400).json(UNKNOWN_FACTOR);
					return;
				case "unavailable":
				case "unreadable":
					answerOutage("challenge", res, outcome);
					return;
				case "challenge_failed":
					logger.error(
						{
							kind: outcome.kind,
							...(isMfaFactorId(outcome.factorId) ? { factorId: outcome.factorId } : {}),
							// The factor's failure by its name and code alone: its text may quote the account.
							err: mailFailureOf(outcome.cause),
						},
						"mfa_factor_challenge_unavailable",
					);
					res.status(503).json(MFA_UNAVAILABLE);
					return;
				case "mail_unavailable":
				case "mail_refused_at_limit":
					answerMail("challenge", res, outcome);
					return;
				case "address_mismatch":
					emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "mfa.email_address_mismatch",
						subject: outcome.subject,
						ip: call.request.ip,
						userAgent: call.request.userAgent,
						details: { kind: outcome.kind, purpose: outcome.purpose },
					});
					res.status(403).json(FACTOR_REFUSED);
					return;
				case "proof_unavailable":
					res.status(403).json(EMAIL_PROOF_UNAVAILABLE);
					return;
				case "none":
					res.status(200).json({});
					return;
				case "sent":
					emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "mfa.challenge.sent",
						subject: outcome.subject,
						ip: call.request.ip,
						userAgent: call.request.userAgent,
						details: { kind: outcome.kind, purpose: outcome.purpose },
					});
					res.status(200).json(outcome.response);
					return;
			}
		})
		.post("/verify", async (req: Request, res: Response) => {
			const call = await signedInCall(req, res, postedTransactionId(req), stepUp);
			if (call === undefined) return;
			const body = req.body as { factor_id?: unknown; proof?: unknown } | undefined;
			const outcome = await coordinator.verify({
				...call,
				factorId: body?.factor_id,
				proof: body?.proof,
			});
			switch (outcome.outcome) {
				case "unknown_transaction":
				case "spent":
					res.status(400).json(UNKNOWN_TRANSACTION);
					return;
				case "unknown_factor":
					res.status(400).json(UNKNOWN_FACTOR);
					return;
				case "enrollment_required":
					res.status(403).json(ENROLLMENT_REQUIRED);
					return;
				case "unavailable":
				case "unreadable":
					answerOutage("verify", res, outcome);
					return;
				case "locked": {
					const held = { kind: outcome.kind, purpose: outcome.purpose, hold: outcome.hold };
					emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "mfa.locked",
						subject: outcome.subject,
						ip: call.request.ip,
						userAgent: call.request.userAgent,
						details: held,
					});
					if (outcome.first) {
						emitAuditEvent(auditSink, {
							timestamp: new Date(),
							type: "mfa.locked.first",
							subject: outcome.subject,
							ip: call.request.ip,
							userAgent: call.request.userAgent,
							details: {
								...held,
								...(outcome.binding === undefined ? {} : { binding: outcome.binding }),
							},
						});
					}
					if (outcome.retryAfterMs !== null) {
						res.set("Retry-After", String(Math.max(1, Math.ceil(outcome.retryAfterMs / 1000))));
					}
					res.status(429).json(locked(outcome.hold, outcome.usableKinds));
					return;
				}
				case "refused":
					if (outcome.factorIdDropped === true) {
						// A factor answering outside its contract: the value it named is never logged.
						logger.warn({ kind: outcome.kind }, "mfa_refusal_factor_id_dropped");
					}
					emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "mfa.verify.failure",
						subject: outcome.subject,
						ip: call.request.ip,
						userAgent: call.request.userAgent,
						details: {
							kind: outcome.kind,
							purpose: outcome.purpose,
							reason: outcome.reason,
							...(isMfaFactorId(outcome.factorId) ? { factorId: outcome.factorId } : {}),
						},
					});
					res.status(401).json(notAccepted(outcome.attemptsRemaining));
					return;
				case "proved":
					emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "mfa.verified",
						subject: outcome.subject,
						ip: call.request.ip,
						userAgent: call.request.userAgent,
						details: { kind: outcome.kind, purpose: outcome.purpose },
					});
					res.status(200).json({ email_proof: "verified" });
					return;
				case "verified":
					emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "mfa.verified",
						subject: outcome.subject,
						ip: call.request.ip,
						userAgent: call.request.userAgent,
						details: { kind: outcome.kind, purpose: outcome.purpose },
					});
					witnessUnwritten(outcome.subject, outcome.witness);
					if (outcome.recoveryCodesRemaining !== undefined) {
						emitAuditEvent(auditSink, {
							timestamp: new Date(),
							type: "mfa.recovery_code.used",
							subject: outcome.subject,
							ip: call.request.ip,
							userAgent: call.request.userAgent,
							details: {
								kind: outcome.kind,
								purpose: outcome.purpose,
								remaining: outcome.recoveryCodesRemaining,
							},
						});
					}
					await completeLogin(
						"verify",
						req,
						res,
						outcome,
						outcome.recoveryCodesRemaining === undefined
							? {}
							: { recovery_codes_remaining: outcome.recoveryCodesRemaining },
					);
					return;
			}
		});

	router
		.post("/enrollment", async (req: Request, res: Response) => {
			const posted = postedTransaction(req);
			if (posted === "disagree") {
				res.status(400).json(UNKNOWN_TRANSACTION);
				return;
			}
			const transactionId = posted.id;
			// With no transaction named, the enrollment is the signed-in session's own.
			let call: MfaCeremonyCall | undefined;
			if (transactionId === undefined) {
				const session = await sessionFor(req, res, MFA_MANAGE);
				call = session === undefined ? undefined : { ...callOf(req, undefined), session };
			} else {
				call = await signedInCall(req, res, transactionId, MFA_MANAGE);
			}
			if (call === undefined) return;
			const outcome = await coordinator.beginEnrollment({
				...call,
				kind: (req.body as { kind?: unknown } | undefined)?.kind,
			});
			switch (outcome.outcome) {
				case "unknown_transaction":
					res.status(400).json(UNKNOWN_TRANSACTION);
					return;
				case "enrollment_not_open":
					res.status(400).json(NOT_OPEN);
					return;
				case "email_proof_required":
					res.status(403).json(EMAIL_PROOF_REQUIRED);
					return;
				case "unknown_kind":
					res.status(400).json(UNKNOWN_KIND);
					return;
				case "first_binding_closed":
					answerClosed(res, outcome.purpose);
					return;
				case "factor_limit":
					res.status(409).json(FACTOR_LIMIT);
					return;
				case "unavailable":
					answerOutage("enrollment", res, outcome);
					return;
				case "mail_unavailable":
				case "mail_refused_at_limit":
					answerMail("enrollment", res, outcome);
					return;
				case "enrollment_failed":
					logger.error(
						{ route: "enrollment", kind: outcome.kind, err: mailFailureOf(outcome.cause) },
						"mfa_factor_enrollment_unavailable",
					);
					res.status(503).json(MFA_UNAVAILABLE);
					return;
				case "begun": {
					const opened = outcome.transaction;
					// A session's enrollment names its transaction, which the page completes on.
					res
						.status(200)
						.json(
							opened === undefined
								? outcome.response
								: { ...outcome.response, transaction: opened.id, expires_in: opened.expiresIn },
						);
					return;
				}
			}
		})
		.post("/enrollment/complete", async (req: Request, res: Response) => {
			const call = await signedInCall(req, res, postedTransactionId(req), MFA_MANAGE);
			if (call === undefined) return;
			const body = req.body as { proof?: unknown; label?: unknown } | undefined;
			const outcome = await coordinator.completeEnrollment({
				...call,
				proof: body?.proof,
				label: body?.label,
			});
			switch (outcome.outcome) {
				case "unknown_transaction":
				case "spent":
					res.status(400).json(UNKNOWN_TRANSACTION);
					return;
				case "enrollment_not_open":
					res.status(400).json(NOT_OPEN);
					return;
				case "email_proof_required":
					res.status(403).json(EMAIL_PROOF_REQUIRED);
					return;
				case "no_pending_enrollment":
					res.status(400).json(NO_PENDING);
					return;
				case "unknown_kind":
					res.status(400).json(UNKNOWN_KIND);
					return;
				case "invalid_label":
					res.status(400).json(INVALID_LABEL);
					return;
				case "first_binding_closed":
					answerClosed(res, outcome.purpose);
					return;
				case "factor_limit":
					res.status(409).json(FACTOR_LIMIT);
					return;
				case "first_binding_conflict":
					// Another transaction bound the subject's first factor at once: a
					// password holder may be racing the owner.
					emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "mfa.first_binding_conflict",
						subject: outcome.subject,
						ip: call.request.ip,
						userAgent: call.request.userAgent,
						details: { kind: outcome.kind, removed: outcome.standing === undefined },
					});
					if (outcome.standing !== undefined) {
						factorStanding(outcome.subject, outcome.kind, outcome.standing.cause);
						res.status(503).json(MFA_UNAVAILABLE);
						return;
					}
					answerClosed(res, outcome.purpose);
					return;
				case "factor_standing":
					// The factor stands and is usable: audited as bound, and said, so the
					// account holder's notice is not missed.
					emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "mfa.factor.enrolled",
						subject: outcome.subject,
						ip: call.request.ip,
						userAgent: call.request.userAgent,
						details: {
							kind: outcome.kind,
							purpose: outcome.purpose,
							binding: outcome.binding,
							by: "user",
						},
					});
					if (outcome.listing !== undefined) {
						storeUnavailable(
							"enrollment",
							outcome.listing.store,
							outcome.listing.step,
							outcome.listing.cause,
						);
					}
					logger.error(
						{
							sub: outcome.subject,
							kind: outcome.kind,
							err: loggableError(outcome.standing.cause),
						},
						"mfa_enrollment_factor_standing",
					);
					res.status(503).json(MFA_UNAVAILABLE);
					return;
				case "first_binding_unchecked":
					answerOutage("enrollment", res, outcome.listing);
					if (outcome.standing !== undefined) {
						factorStanding(outcome.subject, outcome.kind, outcome.standing.cause);
					}
					return;
				case "unavailable":
				case "unreadable":
					answerOutage("enrollment", res, outcome);
					return;
				case "refused":
					res.status(401).json(notAccepted(outcome.attemptsRemaining));
					return;
				case "enrolled": {
					const audited = {
						timestamp: new Date(),
						subject: outcome.subject,
						ip: call.request.ip,
						userAgent: call.request.userAgent,
					};
					emitAuditEvent(auditSink, {
						...audited,
						type: "mfa.factor.enrolled",
						details: {
							kind: outcome.kind,
							purpose: outcome.purpose,
							binding: outcome.binding,
							by: "user",
						},
					});
					const codes = outcome.recoveryCodes;
					if (codes?.issued === true) {
						emitAuditEvent(auditSink, {
							...audited,
							type: "mfa.recovery_codes.generated",
							details: {
								kind: RECOVERY_CODE_FACTOR_KIND,
								purpose: outcome.purpose,
								binding: outcome.binding,
								by: "user",
								regenerated: false,
							},
						});
					} else if (codes?.issued === false) {
						logger.error(
							{ sub: outcome.subject, err: loggableError(codes.cause) },
							"mfa_recovery_codes_unwritten",
						);
					}
					witnessUnwritten(outcome.subject, outcome.witness);
					if (outcome.flagUncleared !== undefined) {
						logger.warn(
							{ sub: outcome.subject, err: loggableError(outcome.flagUncleared) },
							"mfa_email_proof_flag_uncleared",
						);
					}
					// The codes are answered here, once; a page that got none points to their regeneration.
					const answer = {
						factor: outcome.factor,
						...(codes === undefined
							? {}
							: codes.issued
								? { recovery_codes: codes.codes }
								: { recovery_codes_issued: false }),
					};
					if (outcome.purpose === "enroll") {
						// The session is left as it was.
						res.status(200).json(answer);
						return;
					}
					await completeLogin("enrollment", req, res, outcome, answer);
					return;
				}
			}
		})
		.post("/step-up", async (req: Request, res: Response) => {
			const posted = postedTransaction(req);
			if (posted === "disagree") {
				res.status(400).json(UNKNOWN_TRANSACTION);
				return;
			}
			// The trip is admitted as the remediation: a live session, whatever it lacks.
			const session = await sessionFor(req, res, stepUp);
			if (session === undefined) return;
			// What a first binding in this session is answered: an outage, a new
			// login, another requirement's step-up — answered as its own — or one
			// this requirement's proof can meet, or none owed.
			const judged = await admitCookie(req, MFA_MANAGE);
			if (judged.outcome === "step_up" && judged.requirement !== MFA_REQUIREMENT_NAME) {
				answerStepUp(res, judged);
				return;
			}
			if (judged.outcome !== "admitted" && judged.outcome !== "step_up") {
				answerNoSession(res, judged);
				return;
			}
			const outcome = await coordinator.stepUp({ ...callOf(req, posted.id), session });
			switch (outcome.outcome) {
				case "unknown_transaction":
					res.status(400).json(UNKNOWN_TRANSACTION);
					return;
				case "unavailable":
					answerOutage("step-up", res, outcome);
					return;
				case "counting_factor_held":
					res.status(404).json(NOT_FOUND);
					return;
				case "opened":
					res.status(200).json({
						transaction: outcome.transaction.id,
						expires_in: outcome.transaction.expiresIn,
						email_proof: true,
					});
					return;
			}
		});

	return router;
}
