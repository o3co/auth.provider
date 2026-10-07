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
import { answerInterruption } from "./answer-interruption.mjs";
import { establishSession, renewSession } from "./establish-session.mjs";
/** The session package's two login tails and its session renewal over `deps`, as core's `LoginCompletion`. Frozen. */
export function createLoginCompletion(deps) {
    const { userSessionStore, subjectSessionIndex, sessionLifecycle, sessionTtlMs, csrf } = deps;
    if (userSessionStore !== undefined && sessionLifecycle === undefined) {
        throw new Error("login completion: userSessionStore is wired, but sessionLifecycle is not. Where a user-session store is wired, core's session lifecycle is required: a login opens its session's record in it. Install sessionLifecycleModule from @o3co/auth-provider-core beside the session stores.");
    }
    return Object.freeze({
        // No steps of the caller's beside the record: the store and step names
        // are the contract's own.
        establishSession: (establishment, { req, reporter }) => establishSession(establishment, {
            req,
            ...(userSessionStore === undefined ? {} : { userSessionStore }),
            ...(subjectSessionIndex === undefined ? {} : { subjectSessionIndex }),
            ...(sessionLifecycle === undefined ? {} : { sessionLifecycle }),
            sessionTtlMs,
            reporter,
        }),
        answerInterruption: (admission, { req, res, reporter }) => answerInterruption(admission, { req, res, csrf, reporter }),
        renewSession: ({ req, reporter }) => renewSession(req, reporter),
    });
}
