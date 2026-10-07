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
 * The recording test double of the `loginCompletion` slot. See ADR
 * 2026-09-28-session-admission. `createRecordingLoginCompletion` keeps the
 * slot's contract — what the session package's `establishSession`,
 * `answerInterruption` and `renewSession` do over an express session — with
 * made-up `sid`s, records what it was handed, and can stand in for a
 * session store that is down. The contract suite is
 * `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */

import type { Request, Response } from "express";
import type { CsrfGuard } from "../../browser-session/types.mjs";
import { isEstablishment, isInterruptAdmission } from "../../session-admission/admit.mjs";
import type {
	LoginCompletion,
	LoginEstablishmentResult,
	LoginInterruptionResult,
	LoginInterruptionStep,
	SessionRenewalResult,
	SessionRenewalStep,
} from "../../session-admission/login-completion.mjs";
import type {
	Establishment,
	InterruptAdmission,
	InterruptionAnswer,
} from "../../session-admission/requirement.mjs";
import { newRenewalNonce } from "../../user-sessions/renewalNonce.mjs";

/** The express session's id: express-session's field, which core's copy of Express's types does not carry. */
const sessionIdOf = (req: Request): string => (req as unknown as { sessionID: string }).sessionID;

/** A `LoginCompletion` for tests, that records what it was handed and can stand in for a session store that is down. */
export interface RecordingLoginCompletion extends LoginCompletion {
	/** Every establishment core built that `establishSession` was handed, oldest first. */
	readonly establishments: readonly Establishment[];
	/** Every interruption core answered that `answerInterruption` was handed, oldest first. */
	readonly interruptions: readonly InterruptAdmission[];
	/** The session records it holds: one per login established, none for one rolled back. */
	readonly records: number;
	/** From now on, `establishSession` answers the session store's outage at `create` and writes nothing. */
	failSessionStore(error: unknown): void;
	/** Answer again. */
	recover(): void;
}

/** The express session as the double drives it: express-session's operations, and the fields a login writes. */
interface CookieSession {
	regenerate(done: (err?: unknown) => void): void;
	save(done: (err?: unknown) => void): void;
	[field: string]: unknown;
}

const cookieSessionOf = (req: Request): CookieSession | undefined =>
	(req as unknown as { session?: CookieSession }).session;

/** Runs an express-session operation: whether it failed, and why. */
const sessionOperation = (
	operation: "regenerate" | "save",
	req: Request,
): Promise<{ readonly failed: false } | { readonly failed: true; readonly cause: unknown }> =>
	new Promise((resolve) => {
		try {
			const session = cookieSessionOf(req);
			if (session === undefined) throw new Error("the request has no express session");
			session[operation]((err) => resolve(err ? { failed: true, cause: err } : { failed: false }));
		} catch (cause) {
			resolve({ failed: true, cause });
		}
	});

/** The signed-in state a renewal keeps: what `establishSession` writes and `cookieClaim` reads. */
const SIGNED_IN_FIELDS = ["isAuthenticated", "user", "sid"] as const;

/** Drops the request's cookie session after an outage, so nothing is saved or named by a cookie. */
const abandon = (req: Request): void => {
	(req as unknown as { session?: unknown }).session = undefined;
};

const UNAVAILABLE = Object.freeze({
	error: "temporarily_unavailable",
	error_description: "The login could not be completed. Try again.",
});

export interface RecordingLoginCompletionOptions {
	/** The deployment's CSRF guard: `answerInterruption` issues the `403`'s fresh token through it. */
	readonly csrfGuard?: CsrfGuard;
	/**
	 * `false` for a completion over no session store — the session package's
	 * composition without a `UserSessionStore`: no record is written and no
	 * `sid` answered. A session record per login by default.
	 */
	readonly sessionRecords?: boolean;
}

/**
 * A `LoginCompletion` that keeps the contract over the express session it
 * is handed: `establishSession` counts a session record, regenerates the
 * session, writes the signed-in state and saves it, answering a made-up
 * `sid` — a failure after the record is counted rolls it back;
 * `answerInterruption` regenerates, opens the ceremony on the new id,
 * saves and answers the requirement's `403`, with a fresh token from
 * `options.csrfGuard` when it is given one; `renewSession` regenerates,
 * writes back the signed-in fields the session held and a fresh renewal
 * nonce, and saves.
 */
export function createRecordingLoginCompletion(
	options: RecordingLoginCompletionOptions = {},
): RecordingLoginCompletion {
	let established: readonly Establishment[] = Object.freeze([]);
	let interrupted: readonly InterruptAdmission[] = Object.freeze([]);
	let storeFailure: { readonly error: unknown } | undefined;
	let records = 0;
	let made = 0;
	/** The records a login writes: one, or none over no session store. */
	const writes = options.sessionRecords === false ? 0 : 1;

	return {
		get establishments() {
			return established;
		},
		get interruptions() {
			return interrupted;
		},
		get records() {
			return records;
		},
		failSessionStore(error: unknown): void {
			storeFailure = { error };
		},
		recover(): void {
			storeFailure = undefined;
		},
		async establishSession(establishment, { req, reporter }): Promise<LoginEstablishmentResult> {
			if (!isEstablishment(establishment)) {
				throw new RangeError(
					"establishSession: the establishment must be one admitPrimary, resumePrimary or establishWithoutAsking built",
				);
			}
			established = Object.freeze([...established, establishment]);
			const { subject: sub, user, redirectTo } = establishment.primary;
			made++;
			const sid = writes === 0 ? undefined : `recording-sid-${made}`;
			const report = reporter({ sid, sub });
			if (storeFailure !== undefined) {
				report.storeUnavailable("user_session", "create", storeFailure.error);
				return { outcome: "unavailable", store: "user_session", step: "create" };
			}
			records += writes;
			const regenerated = await sessionOperation("regenerate", req);
			if (regenerated.failed) {
				report.storeUnavailable("cookie_session", "regenerate", regenerated.cause);
				records -= writes;
				abandon(req);
				return { outcome: "unavailable", store: "cookie_session", step: "regenerate" };
			}
			const session = cookieSessionOf(req) as CookieSession;
			session.isAuthenticated = true;
			session.user = user;
			if (sid !== undefined) session.sid = sid;
			if (redirectTo) session.redirectTo = redirectTo;
			const saved = await sessionOperation("save", req);
			if (saved.failed) {
				report.storeUnavailable("cookie_session", "save", saved.cause);
				records -= writes;
				abandon(req);
				return { outcome: "unavailable", store: "cookie_session", step: "save" };
			}
			return { outcome: "established", sid };
		},
		async answerInterruption(admission, { req, res, reporter }): Promise<LoginInterruptionResult> {
			if (!isInterruptAdmission(admission)) {
				throw new RangeError(
					"answerInterruption: the admission must be an interruption admitPrimary or resumePrimary answered",
				);
			}
			interrupted = Object.freeze([...interrupted, admission]);
			const unavailable = (
				store: string,
				step: LoginInterruptionStep,
				cause: unknown,
			): LoginInterruptionResult => {
				reporter.storeUnavailable(store, step, cause);
				abandon(req);
				(res as Response).status(503).json(UNAVAILABLE);
				return { outcome: "unavailable", store, step };
			};
			const regenerated = await sessionOperation("regenerate", req);
			if (regenerated.failed) return unavailable("cookie_session", "regenerate", regenerated.cause);
			let answer: InterruptionAnswer;
			try {
				answer = await admission.open(sessionIdOf(req));
			} catch (cause) {
				return unavailable(admission.requirement, "open", cause);
			}
			const saved = await sessionOperation("save", req);
			if (saved.failed) return unavailable("cookie_session", "save", saved.cause);
			options.csrfGuard?.issue(res);
			res.status(answer.status).json(answer.body);
			return { outcome: "answered" };
		},
		async renewSession({ req, reporter }): Promise<SessionRenewalResult> {
			const renewalNonce = newRenewalNonce();
			const held = cookieSessionOf(req);
			const kept = SIGNED_IN_FIELDS.flatMap((field) =>
				held?.[field] === undefined ? [] : [[field, held[field]] as const],
			);
			const unavailable = (step: SessionRenewalStep, cause: unknown): SessionRenewalResult => {
				reporter.storeUnavailable("cookie_session", step, cause);
				abandon(req);
				return { outcome: "unavailable", store: "cookie_session", step };
			};
			const regenerated = await sessionOperation("regenerate", req);
			if (regenerated.failed) return unavailable("regenerate", regenerated.cause);
			Object.assign(cookieSessionOf(req) as CookieSession, Object.fromEntries(kept), {
				renewalNonce,
			});
			const saved = await sessionOperation("save", req);
			if (saved.failed) return unavailable("save", saved.cause);
			return { outcome: "renewed", renewalNonce };
		},
	};
}
