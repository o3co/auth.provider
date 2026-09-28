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
 * The tail of a login, as one function. `establishSession` turns a user the
 * route has verified into a `UserSession` record and an authenticated express
 * session, and undoes what it wrote when a store fails along the way. Both
 * login paths call it — `POST /session/login` (`routes/Session.mts`) and the
 * federation callback (`routes/Federation.mts`) — and nothing else does: it
 * is the package's own, not exported. What only one of them writes beside
 * the record (a federation's index entry, its upstream tokens) is a step the
 * caller supplies; what each of them logs is a reporter the caller supplies,
 * so the two routes' log vocabularies stay their own.
 *
 * The sequence, and the rollback at each point it can fail:
 *
 * 1. `UserSessionStore.create`. A `sid` is minted, the reporter is built with
 *    it before anything is written, and the record carries the claims,
 *    `authTime`, `expiresAt` (`authTime` plus the session lifetime) and the
 *    `amr` / `authentication` the caller recorded. Fails: reported as
 *    `user_session` / `create`; nothing to undo.
 * 2. `SubjectSessionIndex.addSid`, when wired — best-effort: a failure is
 *    reported (`subjectIndexWriteFailed`) and the login proceeds. Written
 *    here, at the earliest point the session exists, because the two failure
 *    modes are not symmetric: a missing entry is a live session a credential
 *    change will never find, while an orphan entry costs one redundant
 *    cascade that `cascadeLogout` absorbs. Every rollback below removes it.
 * 3. The caller's `beforeRegenerate` steps, in order. One that fails is
 *    reported under its own store and step; the steps before it are undone,
 *    then the record, then its index entry.
 * 4. `req.session.regenerate` — session fixation: a fresh session id before
 *    any authenticated state is written. Fails: reported as `cookie_session`
 *    / `regenerate`; the steps undone in reverse, the record, its index
 *    entry; and the request's cookie session dropped.
 * 5. The caller's `afterRegenerate` steps, in order — what needs the
 *    regenerated session to exist first. One that fails: as 3, and the cookie
 *    session dropped.
 * 6. `isAuthenticated`, `user`, `sid` (when there is a record) and
 *    `redirectTo` (when the login carried one) on the regenerated session.
 * 7. `req.session.save`, before the route answers: a store that cannot save
 *    it is the route's `503`, never a `200` for a session the next request
 *    would not find. Fails: as 5.
 *
 * Every rollback is best-effort: a step that fails is reported
 * (`cleanupFailed`) and the next one runs; the login's own answer stands. A
 * caller's step is undone only when its `run` completed, and only through
 * the `undo` it declares; the caller's steps are undone in reverse order,
 * then the record, and the index entry last, on every ladder. From the
 * regeneration on, a failure drops the request's cookie session
 * (`abandonCookieSession`): express-session generated a fresh session for
 * the request, and it must be neither saved against the store that failed
 * nor named by a cookie. Before the regeneration nothing of the cookie
 * session was touched, so it is left as it was.
 *
 * Without a `UserSessionStore` — a composition that authenticates the express
 * session alone, which `POST /session/login` keeps accepting — no record is
 * created, nothing is indexed, no caller's step runs (they write beside a
 * record), and the sequence is the regeneration, the flags and the save.
 *
 * The CSRF token, the `200` and the redirect stay with the routes: this
 * function answers an outcome, never a response.
 */

import { randomUUID } from "node:crypto";
import type {
	RecordedAuthentication,
	SubjectSessionIndex,
	User,
	UserSessionClaims,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request } from "express";
// The augmentation below extends express-session's `SessionData`. Naming the
// module in an import keeps it resolvable from the emitted declaration file,
// so a consumer compiling under `skipLibCheck: false` reads the augmentation
// as one and not as a stray ambient module.
import type {} from "express-session";
import { abandonCookieSession, sessionOperation } from "./internal/cookieSession.mjs";

declare module "express-session" {
	interface SessionData {
		/** Written by {@link establishSession}: the session is a login's. */
		isAuthenticated?: boolean;
		/** Written by {@link establishSession}: the `User` the login verified. */
		user?: Record<string, unknown>;
		/** Written by {@link establishSession} when the login carried a `redirect_to` its allowlist accepted. */
		redirectTo?: string;
		/** The `UserSession` record's id, written by {@link establishSession} when a record was created. */
		sid?: string;
	}
}

/** What a login verified, and what the session it establishes records. */
export interface EstablishSessionInput {
	/**
	 * The user the login verified: `user.id` is the session's subject, and
	 * the object is what the express session keeps as `user`.
	 */
	readonly user: User;
	/**
	 * The claims envelope the record is created with — the local claims, and
	 * a federation's merged under claim precedence where there is one.
	 */
	readonly claims: UserSessionClaims;
	/** When the user authenticated: the record's `authTime`, and what its expiry counts from. */
	readonly authTime: Date;
	/**
	 * The `amr` and `authentication` the record is created with — core's
	 * `passwordSessionAuthentication()` or `federatedSessionAuthentication(…)`.
	 */
	readonly recorded: RecordedAuthentication;
	/** Kept on the express session as `redirectTo`, when the login carried one its allowlist accepted. */
	readonly redirectTo?: string;
}

/** The record a login's tail wrote, as the caller's steps see it. */
export interface EstablishedRecord {
	readonly sid: string;
	readonly sub: string;
	readonly expiresAt: Date;
}

/**
 * A write the caller makes beside the record — a federation's index entry,
 * its upstream tokens — named as its log lines name it: `store` and `step`
 * for a `run` that fails, `undo.step` for an undo that fails.
 */
export interface EstablishSessionStep<S extends string = string, T extends string = string> {
	readonly store: S;
	readonly step: T;
	run(record: EstablishedRecord): Promise<unknown>;
	/** Undoes a completed `run` when a later write fails. Absent: nothing to undo. */
	readonly undo?: {
		readonly step: T;
		run(record: EstablishedRecord): Promise<unknown>;
	};
}

/**
 * What the caller logs, in its own vocabulary — the two routes' event names
 * and fields differ, and stay theirs. Built once per login, with the `sid`
 * (when a record is made) and the subject, before the first write, so a
 * caller can bind its logger to them.
 */
export interface EstablishSessionReporter<S extends string = never, T extends string = never> {
	/** A store the login cannot do without could not answer; the caller answers the outage. */
	storeUnavailable(
		store: "user_session" | "cookie_session" | S,
		step: "create" | "regenerate" | "save" | T,
		cause: unknown,
	): void;
	/** A best-effort rollback step failed; the login's own answer stands. */
	cleanupFailed(
		store: "user_session" | "subject_session_index" | S,
		step: "delete" | "remove_sid" | T,
		cause: unknown,
	): void;
	/** The subject index could not record the session; the login proceeds. */
	subjectIndexWriteFailed(cause: unknown): void;
}

/** The stores, the steps and the request a login's tail writes. */
export interface EstablishSessionDeps<S extends string = never, T extends string = never> {
	readonly req: Request;
	/** Absent: no record is created, and the express session alone is authenticated. */
	readonly userSessionStore?: UserSessionStore;
	readonly subjectSessionIndex?: SubjectSessionIndex;
	/** The session's lifetime: the record expires this long after `authTime`. */
	readonly sessionTtlMs: number;
	/** Writes beside the record before the express session is regenerated. */
	readonly beforeRegenerate?: ReadonlyArray<EstablishSessionStep<S, T>>;
	/** Writes beside the record after the regeneration — what needs the new session to exist. */
	readonly afterRegenerate?: ReadonlyArray<EstablishSessionStep<S, T>>;
	readonly reporter: (record: {
		readonly sid: string | undefined;
		readonly sub: string;
	}) => EstablishSessionReporter<S, T>;
}

/**
 * The session was established, with the record's `sid` when one was made;
 * or a store the login cannot do without could not answer, named as the
 * reporter was told, and everything written was rolled back.
 */
export type EstablishSessionResult<S extends string = never, T extends string = never> =
	| { readonly outcome: "established"; readonly sid: string | undefined }
	| {
			readonly outcome: "unavailable";
			readonly store: "user_session" | "cookie_session" | S;
			readonly step: "create" | "regenerate" | "save" | T;
	  };

/**
 * Establish the session a login verified: the `UserSession` record, its
 * subject-index entry, the caller's steps, the express session's
 * regeneration, its authenticated state and its save — the sequence, and the
 * rollback at each point it can fail, are in this file's header. Answers
 * `established` with the record's `sid` (`undefined` without a store), or
 * `unavailable` naming the store and the step that could not answer, after
 * everything written was rolled back and — from the regeneration on — the
 * request's cookie session dropped. The caller answers the response either
 * way; the reporter it supplied has already been told what to log.
 */
export async function establishSession<S extends string = never, T extends string = never>(
	input: EstablishSessionInput,
	deps: EstablishSessionDeps<S, T>,
): Promise<EstablishSessionResult<S, T>> {
	const { req, userSessionStore, subjectSessionIndex, sessionTtlMs } = deps;
	const { user, claims, authTime, recorded, redirectTo } = input;
	const sub = user.id;

	// The record is minted before it is written, so the reporter and every
	// line it emits can name the sid from the first write on.
	const record: EstablishedRecord | undefined =
		userSessionStore === undefined
			? undefined
			: { sid: randomUUID(), sub, expiresAt: new Date(authTime.getTime() + sessionTtlMs) };
	const reporter = deps.reporter({ sid: record?.sid, sub });

	const cleanUp = async (
		store: "user_session" | "subject_session_index" | S,
		step: "delete" | "remove_sid" | T,
		run: () => Promise<unknown>,
	): Promise<void> => {
		try {
			await run();
		} catch (err) {
			reporter.cleanupFailed(store, step, err);
		}
	};

	// The caller's steps whose `run` completed, most recent first: what a later
	// failure undoes, before the record itself.
	const completed: Array<{
		readonly store: S;
		readonly undo: NonNullable<EstablishSessionStep<S, T>["undo"]>;
	}> = [];

	const rollBack = async (): Promise<void> => {
		if (record === undefined || userSessionStore === undefined) return;
		for (const { store, undo } of completed) {
			await cleanUp(store, undo.step, () => undo.run(record));
		}
		await cleanUp("user_session", "delete", () => userSessionStore.delete(record.sid));
		if (subjectSessionIndex) {
			await cleanUp("subject_session_index", "remove_sid", () =>
				subjectSessionIndex.removeSid(sub, record.sid),
			);
		}
	};

	/** Run the caller's steps in order; the first that fails, with its cause. */
	const runSteps = async (
		steps: ReadonlyArray<EstablishSessionStep<S, T>>,
		written: EstablishedRecord,
	): Promise<
		{ readonly step: EstablishSessionStep<S, T>; readonly cause: unknown } | undefined
	> => {
		for (const step of steps) {
			try {
				await step.run(written);
			} catch (cause) {
				return { step, cause };
			}
			if (step.undo) completed.unshift({ store: step.store, undo: step.undo });
		}
		return undefined;
	};

	if (record !== undefined && userSessionStore !== undefined) {
		try {
			await userSessionStore.create({
				sid: record.sid,
				sub,
				authTime,
				expiresAt: record.expiresAt,
				claims,
				...recorded,
			});
		} catch (err) {
			// Fail-closed: the store's outage, answered as one — never a
			// session-less login.
			reporter.storeUnavailable("user_session", "create", err);
			return { outcome: "unavailable", store: "user_session", step: "create" };
		}

		if (subjectSessionIndex) {
			try {
				await subjectSessionIndex.addSid(sub, record.sid, record.expiresAt);
			} catch (err) {
				reporter.subjectIndexWriteFailed(err);
			}
		}

		const failed = await runSteps(deps.beforeRegenerate ?? [], record);
		if (failed) {
			reporter.storeUnavailable(failed.step.store, failed.step.step, failed.cause);
			await rollBack();
			return { outcome: "unavailable", store: failed.step.store, step: failed.step.step };
		}
	}

	// express-session regenerates by destroying the old record in its store,
	// so a failure is that store's outage.
	const regenerated = await sessionOperation((done) => req.session.regenerate(done));
	if (regenerated.failed) {
		reporter.storeUnavailable("cookie_session", "regenerate", regenerated.cause);
		await rollBack();
		abandonCookieSession(req);
		return { outcome: "unavailable", store: "cookie_session", step: "regenerate" };
	}

	if (record !== undefined) {
		const failed = await runSteps(deps.afterRegenerate ?? [], record);
		if (failed) {
			reporter.storeUnavailable(failed.step.store, failed.step.step, failed.cause);
			await rollBack();
			abandonCookieSession(req);
			return { outcome: "unavailable", store: failed.step.store, step: failed.step.step };
		}
	}

	// The authenticated state, on the regenerated session and nothing else:
	// `req.session` is the fresh one now, and any earlier reference is stale.
	req.session.isAuthenticated = true;
	req.session.user = user;
	if (record !== undefined) {
		req.session.sid = record.sid;
	}
	if (redirectTo) {
		req.session.redirectTo = redirectTo;
	}

	const saved = await sessionOperation((done) => req.session.save(done));
	if (saved.failed) {
		reporter.storeUnavailable("cookie_session", "save", saved.cause);
		await rollBack();
		abandonCookieSession(req);
		return { outcome: "unavailable", store: "cookie_session", step: "save" };
	}

	return { outcome: "established", sid: record?.sid };
}
