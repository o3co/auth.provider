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
 * The answer to a login a session requirement interrupted, as one function.
 * `POST /session/login` (`routes/Session.mts`) calls it when `admitPrimary`
 * answers `interrupt`, and a requirement's completion route when
 * `resumePrimary` does (another requirement interrupts the login the first
 * one resumed), so the package exports it and the MFA package's completion
 * answers the same way.
 *
 * Two phases, because the express session is regenerated between them:
 *
 * 1. `req.session.regenerate`: a fresh session id, left unauthenticated (no
 *    `isAuthenticated`, `user`, `sid` or `redirectTo` is written).
 * 2. `admission.open(req.sessionID)`: the requirement's ceremony, bound to
 *    that id. The requirement persists the continuation core built, and core
 *    validates its answer against the closed body before it comes back.
 * 3. `req.session.save`, before the answer.
 * 4. The requirement's `403` with its body, and a fresh CSRF token, as a
 *    successful login gets one after the regeneration.
 *
 * No `UserSession` is written: the requirement's completion establishes the
 * session, through `resumePrimary` and `establishSession`.
 *
 * Each point that can fail answers `503 temporarily_unavailable`, drops the
 * request's cookie session (`abandonCookieSession`) and tells the caller's
 * reporter once, so each caller logs in its own vocabulary: the regeneration
 * as `cookie_session` / `regenerate`; a throw from `open` (the requirement's
 * outage, or an answer core refused) under the requirement's name, `open`;
 * the save as `cookie_session` / `save`, after which the requirement's record
 * is left to its own expiry, bound to a session id no browser holds.
 * See ADR 2026-09-28-session-admission, D5.
 */
import { isInterruptAdmission, } from "@o3co/auth-provider-core";
import { abandonCookieSession, SESSION_STORE_UNAVAILABLE, sessionOperation, } from "./internal/cookieSession.mjs";
/**
 * Answer the login `admission` interrupted: regenerate, open, save, answer
 * the requirement's `403` with a fresh CSRF token — the sequence, and the
 * `503` at each point it can fail, are in this file's header. Sends the
 * response either way and answers what it sent. Rejects with a `RangeError`,
 * before the session is touched, when `admission` is not an interruption
 * `admitPrimary` or `resumePrimary` answered (core's `isInterruptAdmission`:
 * a copy, or an object shaped like one, is not).
 */
export async function answerInterruption(admission, { req, res, csrf, reporter }) {
    if (!isInterruptAdmission(admission)) {
        throw new RangeError("answerInterruption: the admission must be an interruption admitPrimary or resumePrimary answered");
    }
    const unavailable = (store, step, cause) => {
        reporter.storeUnavailable(store, step, cause);
        abandonCookieSession(req);
        res.status(503).json(SESSION_STORE_UNAVAILABLE);
        return { outcome: "unavailable", store, step };
    };
    const regenerated = await sessionOperation((done) => req.session.regenerate(done));
    if (regenerated.failed)
        return unavailable("cookie_session", "regenerate", regenerated.cause);
    let answer;
    try {
        answer = await admission.open(req.sessionID);
    }
    catch (err) {
        return unavailable(admission.requirement, "open", err);
    }
    const saved = await sessionOperation((done) => req.session.save(done));
    if (saved.failed)
        return unavailable("cookie_session", "save", saved.cause);
    csrf.issue(res);
    res.status(answer.status).json(answer.body);
    return { outcome: "answered" };
}
