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
 * The tail of a login as a contract, and the `loginCompletion` slot it is
 * reached through (#728; the session-admission ADR's D5).
 *
 * Establishing a session is the session package's: the `UserSession`
 * record, its subject-index entry, the express session's regeneration, its
 * signed-in state and its save, and the rollback at each point one of them
 * fails. A requirement's completion — the MFA package's, after
 * `resumePrimary` — finishes a login the same way, and a package imports
 * only core, so it requires this slot instead of importing
 * `establishSession` and `answerInterruption`. The contract is those two
 * functions with what the provider holds taken out of their arguments: the
 * session stores, the session's lifetime and the CSRF mechanism are the
 * provider's, and a caller hands only the request, the response where one
 * is answered, and a reporter that logs in its own vocabulary.
 *
 * The contract suite and a recording double are published on
 * `@o3co/auth-provider-core/testing` (`loginCompletionContract`,
 * `createRecordingLoginCompletion`). Types only.
 */

import type { Request, Response } from "express";
import type { Establishment, InterruptAdmission } from "./requirement.mjs";

/**
 * What the caller logs while a session is established, in its own
 * vocabulary. Built once per login, with the record's `sid` (when one is
 * made) and the subject, before the first write.
 */
export interface LoginEstablishmentReporter {
	/** A store the login cannot do without could not answer; the caller answers the outage. */
	storeUnavailable(
		store: "user_session" | "cookie_session",
		step: "create" | "regenerate" | "save",
		cause: unknown,
	): void;
	/** A best-effort rollback step failed; the login's own answer stands. */
	cleanupFailed(
		store: "user_session" | "subject_session_index",
		step: "delete" | "remove_sid",
		cause: unknown,
	): void;
	/** The subject index could not record the session; the login proceeds. */
	subjectIndexWriteFailed(cause: unknown): void;
}

/** What a caller hands `establishSession` besides the establishment. */
export interface LoginEstablishmentCall {
	/** The request whose express session is signed in. */
	readonly req: Request;
	readonly reporter: (record: {
		readonly sid: string | undefined;
		readonly sub: string;
	}) => LoginEstablishmentReporter;
}

/**
 * The session was established, with the record's `sid` (`undefined` when
 * the provider keeps no record); or a store the login cannot do without
 * could not answer, as the reporter was told, and everything written was
 * rolled back. Either way the caller answers the response.
 */
export type LoginEstablishmentResult =
	| { readonly outcome: "established"; readonly sid: string | undefined }
	| {
			readonly outcome: "unavailable";
			readonly store: "user_session" | "cookie_session";
			readonly step: "create" | "regenerate" | "save";
	  };

/** Where an interruption's answer failed. */
export type LoginInterruptionStep = "regenerate" | "open" | "save";

/**
 * What the caller logs while an interruption is answered. `store` is
 * `cookie_session` for the regeneration and the save, and the interrupting
 * requirement's name for `open`.
 */
export interface LoginInterruptionReporter {
	/** A store the answer cannot do without could not answer; the `503` is already being sent. */
	storeUnavailable(store: string, step: LoginInterruptionStep, cause: unknown): void;
}

/** What a caller hands `answerInterruption` besides the interruption. */
export interface LoginInterruptionCall {
	readonly req: Request;
	/** Answered here: the requirement's `403` with a fresh CSRF token, or a `503`. */
	readonly res: Response;
	readonly reporter: LoginInterruptionReporter;
}

/** The response has been sent: the requirement's answer, or a `503` naming the store and the step that could not answer. */
export type LoginInterruptionResult =
	| { readonly outcome: "answered" }
	| {
			readonly outcome: "unavailable";
			readonly store: string;
			readonly step: LoginInterruptionStep;
	  };

/**
 * The session package's two login tails, as one contract. Each rejects with
 * a `RangeError`, before the session is touched, what core did not build —
 * an object shaped like an `Establishment` or an interruption, or a copy of
 * one (`isEstablishment`, `isInterruptAdmission`).
 */
export interface LoginCompletion {
	/**
	 * Establish the session admission established, from
	 * `establishment.primary` alone: the session record, the express
	 * session's regeneration, its signed-in state and its save, each outage
	 * rolled back and answered as `unavailable`. Answers an outcome, never a
	 * response: the answer, and a fresh CSRF token on it (the deployment's
	 * `csrfGuard.issue`), are the caller's.
	 */
	establishSession(
		establishment: Establishment,
		call: LoginEstablishmentCall,
	): Promise<LoginEstablishmentResult>;
	/**
	 * Answer the login a requirement interrupted: regenerate the express
	 * session and leave it unauthenticated, open the requirement's ceremony
	 * on the new id, save, and answer the requirement's `403` with a fresh
	 * token from the deployment's `csrfGuard` (the MFA ADR's D27: the page
	 * goes on posting on the regenerated session) — or `503`, with no token,
	 * at whichever of those failed, the cookie session dropped. Sends the
	 * response either way and answers what it sent.
	 */
	answerInterruption(
		admission: InterruptAdmission,
		call: LoginInterruptionCall,
	): Promise<LoginInterruptionResult>;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** The tail of a login (#728): provided by the session module, required by a requirement's completion. */
		readonly loginCompletion?: LoginCompletion;
	}
}
