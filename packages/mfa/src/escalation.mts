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
 * The session's escalation: the second-factor authority's write that a
 * second factor was verified in a signed-in session, and what a step-up
 * answers it. The routes call `escalate` and `answer`; the sequence behind
 * them is this module's alone.
 *
 * - The `amr` added is held to the mfa requirement's sealed reach.
 * - The express id is renewed first, then the second factor recorded on the
 *   `UserSession` once, with the renewal's nonce and the one admission
 *   compared, never retried.
 * - A record left without the renewal's nonce ends the session (`unbound`).
 * - Each failure is logged here, once, and is its own outcome; a step-up
 *   answers each as `ESCALATION_REFUSALS` says.
 */

import {
	type CsrfGuard,
	errorEnvelope,
	isRenewalNonce,
	type Logger,
	type LoginCompletion,
	loggableError,
	type SupportsSecondFactorUpdate,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { OUTSIDE_CONTRACT } from "./ceremony.mjs";

const SESSION_STORE_UNAVAILABLE = errorEnvelope(
	"temporarily_unavailable",
	"Session store unavailable",
);
const LOGIN_REQUIRED = errorEnvelope("login_required", "Log in again");
const STEP_UP_UNRECORDED = errorEnvelope("server_error", "The step-up could not be recorded");
/** A step-up recorded on a session the store left unbound: the session was ended. */
const SESSION_NOT_SECURED = errorEnvelope(
	"server_error",
	"The session could not be secured: sign in again",
);

/** How a session's escalation ended (`escalate`). */
export type Escalation =
	| "escalated"
	| "unrecordable_store"
	| "not_renewed"
	| "not_recorded"
	| "unbound"
	| "invalid"
	| "unavailable";

/** What a step-up answers an escalation that did not land: a new login, an outage, or one nobody can retry. */
export const ESCALATION_REFUSALS: Readonly<
	Record<Exclude<Escalation, "escalated">, readonly [status: number, body: object]>
> = {
	unrecordable_store: [401, LOGIN_REQUIRED],
	not_recorded: [401, LOGIN_REQUIRED],
	not_renewed: [503, SESSION_STORE_UNAVAILABLE],
	unavailable: [503, SESSION_STORE_UNAVAILABLE],
	unbound: [500, SESSION_NOT_SECURED],
	invalid: [500, STEP_UP_UNRECORDED],
};

/**
 * Whether `value`, what `recordSecondFactor` answered other than `null`, is
 * the record of `session`: an object holding its `sid` and subject and the
 * record's dates. Anything else is outside the port's contract.
 */
const isSessionRecord = (
	value: unknown,
	session: { readonly sid: string; readonly sub: string },
): value is { readonly renewalNonce?: unknown } => {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
	const { sid, sub, authTime, expiresAt } = value as Readonly<Record<string, unknown>>;
	return (
		sid === session.sid &&
		sub === session.sub &&
		authTime instanceof Date &&
		expiresAt instanceof Date
	);
};

/** What an escalation is built over; `Route` names the route a line is logged by. */
export interface SessionEscalationOptions<Route extends string> {
	/** The session store's step-up capability, when it has it. */
	readonly secondFactorStore: (UserSessionStore & SupportsSecondFactorUpdate) | undefined;
	readonly loginCompletion: LoginCompletion;
	/** The mfa requirement's sealed reach, read at each escalation; `undefined` when none is registered. */
	readonly reach: () => ReadonlySet<string> | undefined;
	/** Issues the fresh CSRF token an escalation that landed answers with. */
	readonly csrfGuard: CsrfGuard;
	readonly logger: Logger;
	/** Logs a store's outage at `step`, once. */
	readonly storeUnavailable: (
		route: Route,
		store: string,
		step: string,
		cause: unknown,
		context: { readonly sid: string },
	) => void;
}

/** A session's escalation, and a step-up's answer for how it ended. */
export interface SessionEscalation<Route extends string> {
	/**
	 * The signed-in session `session` escalated by `adds`: its express id
	 * renewed, then the second factor recorded on its `UserSession` with the
	 * renewal nonce, expecting `expected`, the one admission compared — called
	 * once, never again, since a retry after a write that landed would expect
	 * the old nonce and undo it. A fresh CSRF token on `res` once recorded.
	 * Each failure is logged here, once; the caller chooses the answer.
	 *
	 * - No step-up capability: `unrecordable_store`, nothing renewed.
	 * - `adds` names a value outside the mfa requirement's sealed reach:
	 *   `invalid`, nothing renewed.
	 * - The renewal fails, or answers no renewal nonce: `not_renewed`, nothing
	 *   recorded.
	 * - The record answers `null` — the session is gone, another completion
	 *   from the same cookie session was recorded first, or it predates how a
	 *   session was established: `not_recorded`. The renewed cookie session is
	 *   left as it is: at its next admission each cause is `not_live` or
	 *   below the level the step-up was for.
	 * - A session without the renewal nonce: `unbound`. The escalation would
	 *   stand bound to no cookie session, so the session is ended.
	 * - A `RangeError`: `invalid`. Any other rejection, or an answer that is
	 *   not this session: `unavailable`.
	 *
	 * After a renewal, no failure but `unbound` ends the renewed cookie session.
	 */
	escalate(
		route: Route,
		req: Request,
		res: Response,
		session: { readonly sid: string; readonly sub: string },
		expected: string | undefined,
		adds: { readonly amr: readonly string[]; readonly mfaAt: Date },
	): Promise<Escalation>;
	/** A step-up's answer for how its escalation ended: `answer` once escalated, else its refusal. */
	answer(res: Response, escalation: Escalation, answer: object): void;
}

/** The session's escalation over `options` (see this file's header). */
export function createSessionEscalation<Route extends string>(
	options: SessionEscalationOptions<Route>,
): SessionEscalation<Route> {
	const {
		secondFactorStore,
		loginCompletion,
		reach: reachOf,
		csrfGuard,
		logger,
		storeUnavailable,
	} = options;
	return {
		async escalate(route, req, res, session, expected, adds) {
			if (secondFactorStore === undefined) return "unrecordable_store";
			const { amr, mfaAt } = adds;
			const reach = reachOf();
			if (reach === undefined || !amr.every((value) => reach.has(value))) {
				logger.error({ route, sub: session.sub }, "mfa_escalation_invalid");
				return "invalid";
			}
			const renewed = await loginCompletion.renewSession({
				req,
				reporter: {
					storeUnavailable: (store, step, cause) =>
						storeUnavailable(route, store, step, cause, { sid: session.sid }),
				},
			});
			if (renewed.outcome !== "renewed") return "not_renewed";
			if (!isRenewalNonce(renewed.renewalNonce)) {
				storeUnavailable(route, "cookie_session", "renewSession", OUTSIDE_CONTRACT, {
					sid: session.sid,
				});
				return "not_renewed";
			}
			let recorded: unknown;
			try {
				recorded = await secondFactorStore.recordSecondFactor(session.sid, {
					amr,
					at: mfaAt,
					renewalNonce: renewed.renewalNonce,
					expectedRenewalNonce: expected,
				});
			} catch (cause) {
				if (cause instanceof RangeError) {
					logger.error(
						{ route, sub: session.sub, err: loggableError(cause) },
						"mfa_escalation_invalid",
					);
					return "invalid";
				}
				storeUnavailable(route, "user_session", "recordSecondFactor", cause, { sid: session.sid });
				return "unavailable";
			}
			if (recorded === null) {
				logger.info({ route, sub: session.sub }, "mfa_escalation_not_recorded");
				return "not_recorded";
			}
			if (!isSessionRecord(recorded, session)) {
				storeUnavailable(route, "user_session", "recordSecondFactor", OUTSIDE_CONTRACT, {
					sid: session.sid,
				});
				return "unavailable";
			}
			if (recorded.renewalNonce !== renewed.renewalNonce) {
				logger.error({ route, sub: session.sub }, "mfa_escalation_unbound");
				try {
					await secondFactorStore.delete(session.sid);
				} catch (cause) {
					storeUnavailable(route, "user_session", "delete", cause, { sid: session.sid });
				}
				return "unbound";
			}
			csrfGuard.issue(res);
			return "escalated";
		},
		answer(res, escalation, answer) {
			if (escalation === "escalated") {
				res.status(200).json(answer);
				return;
			}
			const [status, body] = ESCALATION_REFUSALS[escalation];
			res.status(status).json(body);
		},
	};
}
