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
 * slot the login-completion module provides (`./modules/loginCompletionModule.mts`;
 * #728; the session-admission ADR's D5), over the deployment's `csrfGuard`.
 *
 * A requirement's completion (the MFA package's, after `resumePrimary`)
 * finishes a login as the login routes do, and a package imports only core:
 * it requires this slot instead of importing `establishSession` and
 * `answerInterruption`. The two are this package's
 * (`./establish-session.mts`, `./answer-interruption.mts`), with what the
 * provider holds bound here — the session stores, the session's lifetime,
 * and the deployment's CSRF guard, whose fresh token an interruption's `403`
 * carries —
 * so that a caller hands only the request, the response where one is
 * answered, and a reporter that logs in its own vocabulary.
 */

import type {
	CsrfGuard,
	LoginCompletion,
	SubjectSessionIndex,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { answerInterruption } from "./answer-interruption.mjs";
import { establishSession } from "./establish-session.mjs";

/** What the completion holds: what `establishSession` and `answerInterruption` take beside a call's own. */
export interface LoginCompletionDeps {
	/** Absent: no record is created, and the express session alone is signed in. */
	readonly userSessionStore?: UserSessionStore;
	readonly subjectSessionIndex?: SubjectSessionIndex;
	/** The session's lifetime: a record expires this long after its `authTime`. */
	readonly sessionTtlMs: number;
	/** Issues the fresh token an interruption's `403` carries: the deployment's CSRF guard. */
	readonly csrf: Pick<CsrfGuard, "issue">;
}

/** The session package's two login tails over `deps`, as core's `LoginCompletion`. Frozen. */
export function createLoginCompletion(deps: LoginCompletionDeps): LoginCompletion {
	const { userSessionStore, subjectSessionIndex, sessionTtlMs, csrf } = deps;
	return Object.freeze({
		// No steps of the caller's beside the record: the store and step names
		// are the contract's own.
		establishSession: (establishment, { req, reporter }) =>
			establishSession<never, never>(establishment, {
				req,
				...(userSessionStore === undefined ? {} : { userSessionStore }),
				...(subjectSessionIndex === undefined ? {} : { subjectSessionIndex }),
				sessionTtlMs,
				reporter,
			}),
		answerInterruption: (admission, { req, res, reporter }) =>
			answerInterruption(admission, { req, res, csrf, reporter }),
	} satisfies LoginCompletion);
}
