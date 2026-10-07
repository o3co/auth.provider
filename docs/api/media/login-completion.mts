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
 * reached through. Types only.
 *
 * Establishing a session (record, subject index, regeneration, sign-in,
 * save, rollback), and renewing a signed-in session's id, are the session
 * package's: it alone writes the signed-in cookie state. A requirement's completion
 * finishes a login the same way, but a package imports only core, so it
 * requires this slot. The session stores, the session's lifetime and the
 * CSRF mechanism stay the provider's: a caller hands only the request, the
 * response where one is answered, and a reporter in its own vocabulary.
 * The contract suite is on `@o3co/auth-provider-test-kit`, and a recording
 * double on `@o3co/auth-provider-core/testing`.
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

/** Where a renewal failed: the express session's regeneration, or its save. */
export type SessionRenewalStep = "regenerate" | "save";

/** What the caller logs while a session's id is renewed, in its own vocabulary. */
export interface SessionRenewalReporter {
	/** The cookie session's store could not answer; the caller answers the outage. */
	storeUnavailable(store: "cookie_session", step: SessionRenewalStep, cause: unknown): void;
}

/** What a caller hands `renewSession`. */
export interface SessionRenewalCall {
	/** The request whose signed-in express session is renewed. */
	readonly req: Request;
	readonly reporter: SessionRenewalReporter;
}

/**
 * The signed-in state is on a new express session id, saved; or the cookie
 * session's store could not answer, as the reporter was told, and the
 * request's cookie session was abandoned. Either way the caller answers the
 * response.
 */
export type SessionRenewalResult =
	| {
			readonly outcome: "renewed";
			/** The new cookie session's renewal nonce: what `recordSecondFactor` records with the escalation. */
			readonly renewalNonce: string;
	  }
	| {
			readonly outcome: "unavailable";
			readonly store: "cookie_session";
			readonly step: SessionRenewalStep;
	  };

/**
 * The session package's login tails, and the renewal of a signed-in
 * session's id, as one contract. Each login tail rejects with a
 * `RangeError`, before the session is touched, what core did not build — an
 * object shaped like an `Establishment` or an interruption, or a copy of one
 * (`isEstablishment`, `isInterruptAdmission`).
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
	 * token from the deployment's `csrfGuard` (the page goes on posting on
	 * the regenerated session), or a `503` with no token at whichever step
	 * failed, the cookie session dropped. Sends the response either way and
	 * answers what it sent.
	 */
	answerInterruption(
		admission: InterruptAdmission,
		call: LoginInterruptionCall,
	): Promise<LoginInterruptionResult>;
	/**
	 * Regenerate a signed-in browser's express session and keep its signed-in
	 * state on the new id — `isAuthenticated`, `user` and `sid` as they were —
	 * with a fresh renewal nonce (`newRenewalNonce`) it answers, then save it.
	 * Every other field is dropped, and no session record is written; a
	 * session not signed in stays so.
	 *
	 * Against session fixation after an escalation (the MFA ADR's D27), the
	 * nonce is what holds, not the old id's destruction: express-session's
	 * save overwrites whatever its store holds, so a request in flight on the
	 * old id can put it back after the renewal, signed in on the same `sid`.
	 * The caller records the escalation with the nonce (`recordSecondFactor`'s
	 * `renewalNonce`), and admission then refuses every cookie session but the
	 * one holding it.
	 *
	 * A failure, or a request with no express session, abandons the request's
	 * cookie session and saves nothing; the caller records nothing on
	 * `unavailable`. At `save` the old id is already destroyed; at
	 * `regenerate` the store could not destroy it, and it keeps what it held —
	 * no escalation, provided the caller records nothing. Records bound to the
	 * old id — a consent parked by `/authorize`, a federation-grant browser
	 * binding, the session's other open MFA transactions — are orphaned.
	 * Answers an outcome, never a response.
	 */
	renewSession(call: SessionRenewalCall): Promise<SessionRenewalResult>;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** The tail of a login: provided by the session module, required by a requirement's completion. */
		readonly loginCompletion?: LoginCompletion;
	}
}
