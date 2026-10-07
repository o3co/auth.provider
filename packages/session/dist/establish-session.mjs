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
 * it: what a session vouches for, and what it records of the login's `User`
 * for a first binding (`enrollmentFacts`), is what admission established.
 * Both login routes use it, and it is exported so a requirement's completion
 * (e.g. MFA) finishes a login the same way; callers supply their extra writes
 * (steps) and their log vocabulary (reporter).
 *
 * Where a `UserSessionStore` is wired, core's session lifecycle is required
 * beside it: the record's lifecycle is opened in it, and a rollback closes it
 * there.
 *
 * Sequence:
 * 1. the record: its lifecycle record opened first, then
 *    `UserSessionStore.create`. Either failing or throwing, or the open
 *    refused, is the record's outage at `create`; a lifecycle record the
 *    open wrote is closed again, best effort;
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
 * then the record — its lifecycle record closed, then the user session
 * deleted — then its index entry. A close that fails is reported as the
 * record's `delete`, with the lifecycle's own error when it rejects. From
 * step 4 on, a failure also drops the request's cookie session, which must be
 * neither saved against the failed store nor named by a cookie. Without a
 * `UserSessionStore` only steps 4, 6 and 7 run. The CSRF token and the
 * response stay with the routes.
 *
 * `renewSession` moves a signed-in session to a new id: the signed-in state
 * this file writes — `isAuthenticated`, `user`, `sid` — carried over, a fresh
 * renewal nonce (`newRenewalNonce`) written beside it, nothing else, saved.
 * The regeneration destroys the old id, but express-session's save overwrites
 * whatever the store holds: a request in flight on the old id that saves
 * after the renewal puts it back, signed in on the same `sid`. What keeps the
 * escalation off it is the nonce — the caller records it with the escalation
 * (`recordSecondFactor`), and admission refuses a cookie session that does not
 * hold it (the MFA ADR's D27). A failure drops the request's cookie session
 * as above, and a request with no express session is the cookie session's
 * outage at `regenerate`.
 */
import { randomUUID } from "node:crypto";
import { isEstablishment, newRenewalNonce, } from "@o3co/auth-provider-core";
import { abandonCookieSession, sessionOperation } from "./internal/cookieSession.mjs";
/**
 * Opens `record`'s lifecycle in `lifecycle`. A rejection propagates as the
 * lifecycle's own error, so the reporter's line carries its projection; any
 * answer but `opened` throws, named as the lifecycle's.
 */
const openLifecycle = async (lifecycle, record) => {
    const opened = await lifecycle.open(record.sid, {
        sub: record.sub,
        expiresAt: record.expiresAt,
    });
    if (opened.outcome !== "opened") {
        throw new Error(`the session lifecycle answered ${opened.outcome} to the open`);
    }
};
/**
 * Closes `record`'s lifecycle in `lifecycle`, for a rollback. A rejection
 * propagates as the lifecycle's own error; any answer but a committed close
 * (`done` or `pending`) throws, named as the lifecycle's.
 */
const closeLifecycle = async (lifecycle, record) => {
    const { outcome } = await lifecycle.close(record.sid, "session_logout");
    if (outcome !== "done" && outcome !== "pending") {
        throw new Error(`the session lifecycle answered ${outcome} to the close`);
    }
};
/**
 * Establish the session admission established (sequence and rollback in this
 * file's header). Answers `established` with the record's `sid` (`undefined`
 * without a store), or `unavailable` naming the store and step that failed,
 * after rolling back; the reporter has already been told what to log.
 *
 * @throws RangeError, before anything is written, when `establishment` was not
 * built by core; TypeError when a `userSessionStore` is handed without a
 * `sessionLifecycle`.
 */
export async function establishSession(establishment, deps) {
    if (!isEstablishment(establishment)) {
        throw new RangeError("establishSession: the establishment must be one admitPrimary, resumePrimary or establishWithoutAsking built");
    }
    const { req, userSessionStore, subjectSessionIndex, sessionLifecycle, sessionTtlMs } = deps;
    if (userSessionStore !== undefined && sessionLifecycle === undefined) {
        throw new TypeError("establishSession: userSessionStore is wired, but sessionLifecycle is not. Where a user-session store is wired, core's session lifecycle is required: the session's record is opened in it");
    }
    const { subject: sub, user, claims, authTime, recorded, enrollmentFacts, redirectTo, } = establishment.primary;
    // The record is minted before it is written, so the reporter and every
    // line it emits can name the sid from the first write on.
    const record = userSessionStore === undefined
        ? undefined
        : { sid: randomUUID(), sub, expiresAt: new Date(authTime.getTime() + sessionTtlMs) };
    const reporter = deps.reporter({ sid: record?.sid, sub });
    const cleanUp = async (store, step, run) => {
        try {
            await run();
        }
        catch (err) {
            reporter.cleanupFailed(store, step, err);
        }
    };
    // The caller's steps whose `run` completed, most recent first: what a later
    // failure undoes, before the record itself.
    const completed = [];
    const rollBack = async () => {
        if (record === undefined || userSessionStore === undefined || sessionLifecycle === undefined) {
            return;
        }
        for (const { store, undo } of completed) {
            await cleanUp(store, undo.step, () => undo.run(record));
        }
        await cleanUp("user_session", "delete", () => closeLifecycle(sessionLifecycle, record));
        await cleanUp("user_session", "delete", () => userSessionStore.delete(record.sid));
        if (subjectSessionIndex) {
            await cleanUp("subject_session_index", "remove_sid", () => subjectSessionIndex.removeSid(sub, record.sid));
        }
    };
    /** Run the caller's steps in order; the first that fails, with its cause. */
    const runSteps = async (steps, written) => {
        for (const step of steps) {
            try {
                await step.run(written);
            }
            catch (cause) {
                return { step, cause };
            }
            if (step.undo)
                completed.unshift({ store: step.store, undo: step.undo });
        }
        return undefined;
    };
    if (record !== undefined && userSessionStore !== undefined && sessionLifecycle !== undefined) {
        let opened = false;
        try {
            await openLifecycle(sessionLifecycle, record);
            opened = true;
            await userSessionStore.create({
                sid: record.sid,
                sub,
                authTime,
                expiresAt: record.expiresAt,
                claims,
                ...recorded,
                enrollmentFacts,
            });
        }
        catch (err) {
            // Fail-closed: the store's outage, answered as one — never a
            // session-less login.
            reporter.storeUnavailable("user_session", "create", err);
            if (opened) {
                await cleanUp("user_session", "delete", () => closeLifecycle(sessionLifecycle, record));
            }
            return { outcome: "unavailable", store: "user_session", step: "create" };
        }
        if (subjectSessionIndex) {
            try {
                await subjectSessionIndex.addSid(sub, record.sid, record.expiresAt);
            }
            catch (err) {
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
/**
 * Move the request's signed-in express session to a new id (sequence in this
 * file's header). Answers `renewed` with the new session's renewal nonce, or
 * `unavailable` at the step that failed after telling the reporter, the
 * request's cookie session dropped. A session that is not signed in stays
 * so: only the signed-in fields it holds are carried over.
 */
export async function renewSession(req, reporter) {
    // Read before the regeneration: `req.session` is the old one until then.
    const held = req.session;
    const { isAuthenticated, user, sid } = held ?? {};
    const unavailable = (step, cause) => {
        reporter.storeUnavailable("cookie_session", step, cause);
        abandonCookieSession(req);
        return { outcome: "unavailable", store: "cookie_session", step };
    };
    const regenerated = await sessionOperation((done) => req.session.regenerate(done));
    if (regenerated.failed)
        return unavailable("regenerate", regenerated.cause);
    if (isAuthenticated !== undefined)
        req.session.isAuthenticated = isAuthenticated;
    if (user !== undefined)
        req.session.user = user;
    if (sid !== undefined)
        req.session.sid = sid;
    const renewalNonce = newRenewalNonce();
    req.session.renewalNonce = renewalNonce;
    const saved = await sessionOperation((done) => req.session.save(done));
    if (saved.failed)
        return unavailable("save", saved.cause);
    return { outcome: "renewed", renewalNonce };
}
