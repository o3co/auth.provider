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
 * The MFA routes under `/session/mfa`: `GET /transaction`, `POST /challenge`
 * and `POST /verify`, over the coordinator; a verified second factor resumes
 * the login through core's `resumePrimary` and finishes it through the
 * `loginCompletion` slot. See README, "The routes".
 *
 * - Every answer is `no-store`. Bodies are parsed on these paths alone.
 * - Every POST sits behind the deployment's CSRF guard, then the flood guard
 *   (`mfa:ip:<ip>`), before anything is read.
 * - The transaction id is read from the body or the `MFA-Transaction` header,
 *   never from the URL, and never logged; a missing, malformed, foreign,
 *   spent or expired one is answered alike.
 * - Each outage is answered `503` and logged once, at error.
 */

import {
	type AdmissionDeps,
	type AuditSink,
	type CsrfGuard,
	describeAdmissionOutage,
	emitAuditEvent,
	errorEnvelope,
	isMfaFactorId,
	type Logger,
	type LoginCompletion,
	loggableError,
	type PrimaryAdmission,
	resumePrimary,
} from "@o3co/auth-provider-core";
import express, { type Request, type RequestHandler, type Response, type Router } from "express";
import type {
	MfaCeremonyCall,
	MfaCoordinator,
	MfaFactorUnreadable,
	MfaStoreOutage,
	MfaVerifyOutcome,
} from "./coordinator.mjs";
import { MFA_REQUIREMENT_NAME } from "./requirement.mjs";

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

/** A refused proof, with the attempts the transaction has left. */
const notAccepted = (attemptsRemaining: number) => ({
	...errorEnvelope("mfa_invalid", "Second factor not accepted"),
	attempts_remaining: attemptsRemaining,
});

/** Which route a line is logged by. */
type RouteName = "transaction" | "challenge" | "verify";

export interface MfaRoutesOptions {
	readonly coordinator: MfaCoordinator;
	/** What `resumePrimary` is handed: the registered requirements, the session store, the logger. */
	readonly admission: AdmissionDeps;
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
 * The transaction id a POST names: its body's `transaction_id`, or the
 * header's. Two that disagree name none.
 */
const postedTransactionId = (req: Request): string | undefined => {
	const posted: unknown = (req.body as { transaction_id?: unknown } | undefined)?.transaction_id;
	const body = typeof posted === "string" && posted !== "" ? posted : undefined;
	const header = headerOf(req, TRANSACTION_HEADER);
	if (body !== undefined && header !== undefined && body !== header) return undefined;
	return body ?? header;
};

/** The ceremony call a request makes, naming `transactionId`. */
const callOf = (req: Request, transactionId: string | undefined): MfaCeremonyCall => ({
	transactionId,
	binding: { kind: "session", id: sessionIdOf(req) },
	request: {
		...(typeof req.ip === "string" ? { ip: req.ip } : {}),
		...(headerOf(req, "user-agent") === undefined
			? {}
			: { userAgent: headerOf(req, "user-agent") as string }),
	},
});

/** Every answer of these routes is kept by no cache. */
const noStore: RequestHandler = (_req, res, next) => {
	res.set("Cache-Control", "no-store");
	next();
};

/** The MFA routes' router (see this file's header). */
export function createMfaRouter(options: MfaRoutesOptions): Router {
	const { coordinator, admission, loginCompletion, csrfGuard, floodGuard, logger, auditSink } =
		options;
	const router = express.Router();

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
					...(failure.cause === undefined ? {} : { err: loggableError(failure.cause) }),
				},
				"mfa_factor_unreadable",
			);
		}
		res.status(503).json(MFA_UNAVAILABLE);
	};

	/**
	 * The login a verified second factor resumes: `resumePrimary`, then the
	 * session established, or another requirement's interruption answered. A
	 * continuation core refuses sends the user back to the password.
	 */
	const completeLogin = async (
		req: Request,
		res: Response,
		verified: Extract<MfaVerifyOutcome, { outcome: "verified" }>,
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
					storeUnavailable: (store, step, cause) => storeUnavailable("verify", store, step, cause),
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
							"verify",
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
		res.status(200).json({ message: "Logged in successfully" });
	};

	router
		.all(["/transaction", "/challenge", "/verify"], noStore)
		// These paths' own bodies, parsed here: the mount is under `/session`,
		// where other modules mount routes too.
		.post(
			["/challenge", "/verify"],
			express.json(),
			express.urlencoded({ extended: false }),
			csrfGuard.middleware,
			floodGuard,
		)
		.get("/transaction", async (req: Request, res: Response) => {
			// The id travels in the header alone: a GET has no body, and never a URL.
			const outcome = await coordinator.describe(callOf(req, headerOf(req, TRANSACTION_HEADER)));
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
			const call = callOf(req, postedTransactionId(req));
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
							err: loggableError(outcome.cause),
						},
						"mfa_factor_challenge_unavailable",
					);
					res.status(503).json(MFA_UNAVAILABLE);
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
			const call = callOf(req, postedTransactionId(req));
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
				case "unavailable":
				case "unreadable":
					answerOutage("verify", res, outcome);
					return;
				case "refused":
					emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "mfa.verify.failure",
						subject: outcome.subject,
						ip: call.request.ip,
						userAgent: call.request.userAgent,
						details: { kind: outcome.kind, purpose: outcome.purpose, reason: outcome.reason },
					});
					res.status(401).json(notAccepted(outcome.attemptsRemaining));
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
					await completeLogin(req, res, outcome);
					return;
			}
		});

	return router;
}
