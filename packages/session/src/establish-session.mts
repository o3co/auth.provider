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
 * The tail of a login. `establishSession` turns an `Establishment` built by
 * core's session admission (`admitPrimary`, `resumePrimary`,
 * `establishWithoutAsking`) into a `UserSession` record and an authenticated
 * express session, rolling back what it wrote when a store fails. It writes
 * from `establishment.primary` alone, never from what a caller passes beside
 * it: what a session vouches for is what admission established. Both login
 * routes use it, and it is exported so a requirement's completion (e.g. MFA)
 * finishes a login the same way; callers supply their extra writes (steps)
 * and their log vocabulary (reporter).
 *
 * Sequence:
 * 1. `UserSessionStore.create` (a failure has nothing to undo);
 * 2. `SubjectSessionIndex.addSid`, best effort, at the earliest point the
 *    session exists: a missing entry is a live session a credential change
 *    never finds, while an orphan costs only a redundant cascade;
 * 3. the caller's `beforeRegenerate` steps;
 * 4. `req.session.regenerate`, against session fixation;
 * 5. the caller's `afterRegenerate` steps;
 * 6. the authenticated state, on the regenerated session;
 * 7. `req.session.save` before the route answers, so a store that cannot
 *    save is a `503`, never a `200` for a session the next request would not
 *    find.
 *
 * Rollback is best effort and ordered: completed caller steps in reverse,
 * then the record, then its index entry. From step 4 on, a failure also
 * drops the request's cookie session, which must be neither saved against
 * the failed store nor named by a cookie. Without a `UserSessionStore` only
 * steps 4, 6 and 7 run. The CSRF token and the response stay with the routes.
 */

import { randomUUID } from "node:crypto";
import {
	type Establishment,
	isEstablishment,
	type SubjectSessionIndex,
	type UserSessionStore,
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
 * Establish the session admission established (sequence and rollback in this
 * file's header). Answers `established` with the record's `sid` (`undefined`
 * without a store), or `unavailable` naming the store and step that failed,
 * after rolling back; the reporter has already been told what to log.
 *
 * @throws RangeError, before anything is written, when `establishment` was not
 * built by core.
 */
export async function establishSession<S extends string = never, T extends string = never>(
	establishment: Establishment,
	deps: EstablishSessionDeps<S, T>,
): Promise<EstablishSessionResult<S, T>> {
	if (!isEstablishment(establishment)) {
		throw new RangeError(
			"establishSession: the establishment must be one admitPrimary, resumePrimary or establishWithoutAsking built",
		);
	}
	const { req, userSessionStore, subjectSessionIndex, sessionTtlMs } = deps;
	const { subject: sub, user, claims, authTime, recorded, redirectTo } = establishment.primary;

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
