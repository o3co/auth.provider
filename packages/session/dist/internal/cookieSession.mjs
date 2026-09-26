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
 * The cookie session's store failing: how the express-session middleware this
 * package mounts answers it, how a route that met it keeps express-session
 * from trying again, and the bodies this package answers an outage with — one
 * for every session-side store, one for the user directory. Internal to the
 * package; `modules/sessionStoreModule.mts` and the two routers are its
 * callers.
 */
import { loggableError } from "@o3co/auth-provider-core";
/**
 * What the session package answers, with `503`, when a session-side store —
 * the cookie session's, a `form_post` transaction's, the `UserSession`
 * store, a federation index or token store — cannot answer. RFC 6749's code
 * for a temporary condition, one wording everywhere.
 */
export const SESSION_STORE_UNAVAILABLE = Object.freeze({
    error: "temporarily_unavailable",
    error_description: "Session store unavailable",
});
/**
 * What the session package answers, with `503`, when the user directory (the
 * Store behind `UserRepository`) cannot answer — the password login, the
 * federation callback's lookup, a `?link=1` link. One wording everywhere.
 */
export const USER_DIRECTORY_UNAVAILABLE = Object.freeze({
    error: "temporarily_unavailable",
    error_description: "User directory temporarily unavailable",
});
/**
 * express-session's middleware, with its store failures answered here rather
 * than handed on as `next(err)`.
 *
 * express-session reports a store error two ways, and neither reached a log
 * line as the outage it is:
 *
 * - **Before the route runs**, when it cannot load the request's session (the
 *   store is unreachable or times out): the request used to end in the
 *   terminal handler as a `500`. It is `503 temporarily_unavailable` now,
 *   answered here, and no route runs — every route behind this middleware
 *   reads `req.session`. A record the store answers with but that cannot be
 *   read is not an outage and does not come here: the Redis store reads it as
 *   absent (`../store/factory.mts`), so the browser starts a fresh session.
 * - **After the route answered**, when it cannot save the session or refresh
 *   its expiry: the answer has gone, so it stands; the error used to reach
 *   Express's final handler, which printed its stack and dropped the
 *   connection. It is logged here and goes no further.
 *
 * Either way it is one line at error level, `session_middleware_store_unavailable`,
 * with `store: "cookie_session"`, `step` (`load` or `save`) and the error's
 * projection — never the error, which can carry the session record the store
 * was sent.
 */
export function guardCookieSession(middleware, logger) {
    return (req, res, next) => {
        middleware(req, res, (err) => {
            if (err === undefined || err === null) {
                next();
                return;
            }
            const step = res.headersSent ? "save" : "load";
            logger.error({ store: "cookie_session", step, err: loggableError(err) }, "session_middleware_store_unavailable");
            if (step === "save")
                return;
            res.status(503).json(SESSION_STORE_UNAVAILABLE);
        });
    };
}
/**
 * Drop the request's cookie session after a route met its store failing and
 * answered the outage itself. express-session writes a session when the
 * response ends — saving a regenerated one, refreshing an unchanged one's
 * expiry — and that write would wait on the store that just failed and report
 * the same outage a second time. With no session on the request it writes
 * nothing and sets no cookie.
 */
export function abandonCookieSession(req) {
    req.session = undefined;
}
