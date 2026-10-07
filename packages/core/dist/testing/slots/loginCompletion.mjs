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
import { isEstablishment, isInterruptAdmission } from "../../session-admission/admit.mjs";
import { newRenewalNonce } from "../../user-sessions/renewalNonce.mjs";
/** The express session's id: express-session's field, which core's copy of Express's types does not carry. */
const sessionIdOf = (req) => req.sessionID;
const cookieSessionOf = (req) => req.session;
/** Runs an express-session operation: whether it failed, and why. */
const sessionOperation = (operation, req) => new Promise((resolve) => {
    try {
        const session = cookieSessionOf(req);
        if (session === undefined)
            throw new Error("the request has no express session");
        session[operation]((err) => resolve(err ? { failed: true, cause: err } : { failed: false }));
    }
    catch (cause) {
        resolve({ failed: true, cause });
    }
});
/** The signed-in state a renewal keeps: what `establishSession` writes and `cookieClaim` reads. */
const SIGNED_IN_FIELDS = ["isAuthenticated", "user", "sid"];
/** Drops the request's cookie session after an outage, so nothing is saved or named by a cookie. */
const abandon = (req) => {
    req.session = undefined;
};
const UNAVAILABLE = Object.freeze({
    error: "temporarily_unavailable",
    error_description: "The login could not be completed. Try again.",
});
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
export function createRecordingLoginCompletion(options = {}) {
    let established = Object.freeze([]);
    let interrupted = Object.freeze([]);
    let storeFailure;
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
        failSessionStore(error) {
            storeFailure = { error };
        },
        recover() {
            storeFailure = undefined;
        },
        async establishSession(establishment, { req, reporter }) {
            if (!isEstablishment(establishment)) {
                throw new RangeError("establishSession: the establishment must be one admitPrimary, resumePrimary or establishWithoutAsking built");
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
            const session = cookieSessionOf(req);
            session.isAuthenticated = true;
            session.user = user;
            if (sid !== undefined)
                session.sid = sid;
            if (redirectTo)
                session.redirectTo = redirectTo;
            const saved = await sessionOperation("save", req);
            if (saved.failed) {
                report.storeUnavailable("cookie_session", "save", saved.cause);
                records -= writes;
                abandon(req);
                return { outcome: "unavailable", store: "cookie_session", step: "save" };
            }
            return { outcome: "established", sid };
        },
        async answerInterruption(admission, { req, res, reporter }) {
            if (!isInterruptAdmission(admission)) {
                throw new RangeError("answerInterruption: the admission must be an interruption admitPrimary or resumePrimary answered");
            }
            interrupted = Object.freeze([...interrupted, admission]);
            const unavailable = (store, step, cause) => {
                reporter.storeUnavailable(store, step, cause);
                abandon(req);
                res.status(503).json(UNAVAILABLE);
                return { outcome: "unavailable", store, step };
            };
            const regenerated = await sessionOperation("regenerate", req);
            if (regenerated.failed)
                return unavailable("cookie_session", "regenerate", regenerated.cause);
            let answer;
            try {
                answer = await admission.open(sessionIdOf(req));
            }
            catch (cause) {
                return unavailable(admission.requirement, "open", cause);
            }
            const saved = await sessionOperation("save", req);
            if (saved.failed)
                return unavailable("cookie_session", "save", saved.cause);
            options.csrfGuard?.issue(res);
            res.status(answer.status).json(answer.body);
            return { outcome: "answered" };
        },
        async renewSession({ req, reporter }) {
            const renewalNonce = newRenewalNonce();
            const held = cookieSessionOf(req);
            const kept = SIGNED_IN_FIELDS.flatMap((field) => held?.[field] === undefined ? [] : [[field, held[field]]]);
            const unavailable = (step, cause) => {
                reporter.storeUnavailable("cookie_session", step, cause);
                abandon(req);
                return { outcome: "unavailable", store: "cookie_session", step };
            };
            const regenerated = await sessionOperation("regenerate", req);
            if (regenerated.failed)
                return unavailable("regenerate", regenerated.cause);
            Object.assign(cookieSessionOf(req), Object.fromEntries(kept), {
                renewalNonce,
            });
            const saved = await sessionOperation("save", req);
            if (saved.failed)
                return unavailable("save", saved.cause);
            return { outcome: "renewed", renewalNonce };
        },
    };
}
