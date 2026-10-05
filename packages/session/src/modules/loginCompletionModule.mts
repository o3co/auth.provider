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
 * The tail of a login as the `loginCompletion` slot (see ADR
 * 2026-09-28-session-admission), for a requirement's completion — the MFA
 * package's — to establish the session or answer an interruption without
 * importing this package.
 *
 * Its own module, not the session module's, because it answers with the
 * deployment's `csrfGuard`: the session module's, or one a composition put in
 * the slot in its place (`overrideComponents`). A provider in the session
 * module could not require the slot its own module fills (boot refuses the
 * self-cycle) and would bind a guard of its own, whose tokens a substituted
 * guard refuses. Load it beside the session module in a composition whose
 * requirements complete a login.
 */

import { type CsrfGuard, defineModule } from "@o3co/auth-provider-core";

import { createLoginCompletion } from "../login-completion.mjs";

export const loginCompletionModule = defineModule<
	"sessionCookiePolicy" | "userSessionStore" | "csrfGuard",
	"subjectSessionIndex" | "sessionLifecycle"
>({
	name: "login-completion",
	// `sessionCookiePolicy`: the session's lifetime, which the session store's
	// module owns.
	requires: ["sessionCookiePolicy", "userSessionStore", "csrfGuard"],
	// A composition without subject-level revocation has no index to record
	// the session in, as for the session routes; without core's session
	// lifecycle module, a login opens no lifecycle record.
	optional: ["subjectSessionIndex", "sessionLifecycle"],
	provides: {
		loginCompletion: (deps) =>
			createLoginCompletion({
				userSessionStore: deps.userSessionStore,
				...(deps.subjectSessionIndex ? { subjectSessionIndex: deps.subjectSessionIndex } : {}),
				...(deps.sessionLifecycle ? { sessionLifecycle: deps.sessionLifecycle } : {}),
				sessionTtlMs: deps.sessionCookiePolicy.maxAgeMs,
				csrf: deps.csrfGuard as CsrfGuard,
			}),
	},
});
