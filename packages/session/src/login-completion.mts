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
 * The tail of a login as core's `LoginCompletion` — the `loginCompletion`
 * slot `./modules/loginCompletionModule.mts` provides (see ADR
 * 2026-09-28-session-admission), over the deployment's `csrfGuard`.
 *
 * A requirement's completion (the MFA package's, after `resumePrimary`)
 * finishes a login as the login routes do, but a package imports only core,
 * so it requires this slot instead of importing `establishSession` and
 * `answerInterruption`, and renews a signed-in session's id the same way
 * (`renewSession`). The session stores, the session's lifetime and the
 * CSRF guard (whose fresh token an interruption's `403` carries) are bound
 * here, so a caller hands only the request, the response where one is
 * answered, and a reporter that logs in its own vocabulary.
 */

import type {
	CsrfGuard,
	LoginCompletion,
	SessionLifecycle,
	SubjectSessionIndex,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { answerInterruption } from "./answer-interruption.mjs";
import { establishSession, renewSession } from "./establish-session.mjs";

/** What the completion holds: what `establishSession` and `answerInterruption` take beside a call's own. */
export interface LoginCompletionDeps {
	/** Absent: no record is created, and the express session alone is signed in. */
	readonly userSessionStore?: UserSessionStore;
	readonly subjectSessionIndex?: SubjectSessionIndex;
	/**
	 * Core's session lifecycle: a login opens the session's lifecycle record
	 * in it. Required with a `userSessionStore`.
	 */
	readonly sessionLifecycle?: SessionLifecycle;
	/** The session's lifetime: a record expires this long after its `authTime`. */
	readonly sessionTtlMs: number;
	/** Issues the fresh token an interruption's `403` carries: the deployment's CSRF guard. */
	readonly csrf: Pick<CsrfGuard, "issue">;
}

/** The session package's two login tails and its session renewal over `deps`, as core's `LoginCompletion`. Frozen. */
export function createLoginCompletion(deps: LoginCompletionDeps): LoginCompletion {
	const { userSessionStore, subjectSessionIndex, sessionLifecycle, sessionTtlMs, csrf } = deps;
	if (userSessionStore !== undefined && sessionLifecycle === undefined) {
		throw new Error(
			"login completion: userSessionStore is wired, but sessionLifecycle is not. Where a user-session store is wired, core's session lifecycle is required: a login opens its session's record in it. Install sessionLifecycleModule from @o3co/auth-provider-core beside the session stores",
		);
	}
	return Object.freeze({
		// No steps of the caller's beside the record: the store and step names
		// are the contract's own.
		establishSession: (establishment, { req, reporter }) =>
			establishSession<never, never>(establishment, {
				req,
				...(userSessionStore === undefined ? {} : { userSessionStore }),
				...(subjectSessionIndex === undefined ? {} : { subjectSessionIndex }),
				...(sessionLifecycle === undefined ? {} : { sessionLifecycle }),
				sessionTtlMs,
				reporter,
			}),
		answerInterruption: (admission, { req, res, reporter }) =>
			answerInterruption(admission, { req, res, csrf, reporter }),
		renewSession: ({ req, reporter }) => renewSession(req, reporter),
	} satisfies LoginCompletion);
}
