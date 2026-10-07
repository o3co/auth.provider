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
 * The contract suite of core's `loginCompletion` slot.
 * See ADR 2026-09-28-session-admission.
 *
 * `loginCompletionContract(input)` drives a completion over the fake
 * express session of `fakeHttp.mts` and holds it to what the session
 * package's `establishSession` and `answerInterruption` do:
 *
 * - What core did not build is refused with a `RangeError` before anything
 *   is touched: session, reporter, ceremony, record.
 * - An establishment builds the reporter once, for `{ sid, sub }`, and
 *   saves a regenerated session that `cookieClaim` reads as signed in for
 *   its subject; one record per `sid` answered. The response is the
 *   caller's.
 * - An interruption answers the requirement's `403` (with a fresh token in
 *   `csrfCookieName`, when given), its ceremony opened on the regenerated
 *   session id, saved and not signed in.
 * - An outage (store `create`, cookie `regenerate` / `save`, ceremony
 *   `open`) is reported once, leaves no record and the browser not signed
 *   in; an interruption's is `503 temporarily_unavailable` with no token.
 * - A renewal moves the session it established to a regenerated id, saved
 *   with `isAuthenticated`, `user` and `sid` as they were, a fresh renewal
 *   nonce it answers, and no other field, writing no session record; a
 *   session not signed in stays so. A `regenerate` or `save` that fails, or
 *   a request with no express session, is reported once, saves nothing, and
 *   abandons the request's cookie session. The fake session has no store,
 *   so the suite cannot see the old id destroyed: that is express-session's
 *   regeneration, which the session package's own tests drive.
 *
 * Core's `createRecordingLoginCompletion` keeps that contract.
 */
import assert from "node:assert/strict";
import { admitPrimary, cookieClaim, isRenewalNonce, newRenewalNonce, passwordPrimary, readAcrTable, } from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { fakeRequest, fakeResponse, } from "./fakeHttp.mjs";
const SUBJECT = "contract-subject";
const REQUIREMENT = "contract-interrupting";
const ANSWER = { status: 403, body: { error: "contract_interrupted" } };
const admissionDeps = (requirements) => ({
    userSessionStore: undefined,
    subjectRevocation: undefined,
    // No session store, so no live record for the lifecycle to be read after.
    sessionLifecycleStore: undefined,
    requirements: resolverForTests(requirements),
    acrTable: readAcrTable({}),
    logger: undefined,
    auditSink: undefined,
});
const primary = () => passwordPrimary({
    subject: SUBJECT,
    user: { id: SUBJECT, name: "Contract" },
    claims: {},
    authTime: new Date(),
    redirectTo: undefined,
    request: {},
});
/** A password login no requirement interrupts: the `Establishment` core builds for it. */
async function establishment() {
    const admission = await admitPrimary(admissionDeps([]), primary());
    assert.equal(admission.outcome, "establish", "core did not establish a login nothing interrupts");
    return admission.establishment;
}
/** A member of a fixture requirement that answers `value`, whatever it is asked. */
const answering = (value) => async () => value;
/** A ceremony that answers the requirement's `403` and notes each session id it is opened on. */
const ceremony = (opened) => async (sessionId) => {
    opened.push(sessionId);
    return ANSWER;
};
/** A password login a requirement interrupts, the ceremony `open` stands for. */
async function interruption(open) {
    const requirement = {
        name: REQUIREMENT,
        reach: new Set(),
        stepUpPage: undefined,
        remediations: [],
        hintKeys: [],
        admit: answering({ outcome: "met" }),
        admitPrimary: answering({ open: (sessionId) => open(sessionId) }),
    };
    const admission = await admitPrimary(admissionDeps([requirement]), primary());
    assert.equal(admission.outcome, "interrupt", "core did not interrupt the login");
    return admission;
}
/** A reporter for `establishSession` that records every record it is built for and every report. */
function establishmentReporter() {
    const built = [];
    const reports = [];
    return {
        built,
        reports,
        unavailable: () => reports.filter(([kind]) => kind === "unavailable").map(([, store, step]) => [store, step]),
        reporter: (record) => {
            built.push({ sid: record?.sid, sub: record?.sub });
            return {
                storeUnavailable: (store, step) => {
                    reports.push(["unavailable", store, step]);
                },
                cleanupFailed: (store, step) => {
                    reports.push(["cleanup", store, step]);
                },
                subjectIndexWriteFailed: () => {
                    reports.push(["index", "subject_session_index", "add_sid"]);
                },
            };
        },
    };
}
/** A reporter for `answerInterruption` that records every report. */
function interruptionReporter() {
    const unavailable = [];
    return {
        unavailable,
        reporter: {
            storeUnavailable: (store, step) => {
                unavailable.push([store, step]);
            },
        },
    };
}
/** A reporter for `renewSession` that records every report. */
function renewalReporter() {
    const unavailable = [];
    return {
        unavailable,
        reporter: {
            storeUnavailable: (store, step) => {
                unavailable.push([store, step]);
            },
        },
    };
}
/** Fields a renewal must drop: what another flow left on the session beside its signed-in state. */
const BESIDE_SIGNED_IN = Object.freeze({
    redirectTo: "https://rp.contract.test/after",
    parkedByAnotherFlow: "contract-parked",
});
/**
 * A request whose express session carries the signed-in state `completion`
 * established — its own fields, copied from the request it signed in — and
 * fields beside it, on a fake session that fails where `options` says.
 */
async function signedInRequest(completion, options = {}) {
    const signing = fakeRequest();
    const { reporter } = establishmentReporter();
    const result = await completion.establishSession(await establishment(), {
        req: signing.req,
        reporter,
    });
    assert.equal(result.outcome, "established", "the completion did not establish the session to renew");
    const signedIn = Object.freeze({ ...cookieSessionOf(signing.req) });
    const { req, session } = fakeRequest(options);
    Object.assign(cookieSessionOf(req), signedIn, BESIDE_SIGNED_IN);
    return { req, session, signedIn };
}
/** The express session's id: express-session's field, which core's copy of Express's types does not carry. */
const sessionIdOf = (req) => req.sessionID;
/** Whether core's admission reads the request's cookie as signed in. */
const signedIn = (req) => cookieClaim(req).authenticated;
const OUTAGE = new Error("contract: store down");
/** The cases of the `loginCompletion` contract over the completion `input` builds. */
export function loginCompletionContract(input) {
    const { build, withSessionStoreOutage, records, csrfCookieName } = input;
    /** The token cookies `record` was set, when the input names the cookie. */
    const tokensSet = (record) => csrfCookieName === undefined
        ? 0
        : record.cookies.filter((cookie) => cookie.name === csrfCookieName).length;
    const cases = [
        {
            name: "establishSession refuses, before the session is touched, an establishment core did not build",
            run: async () => {
                const real = await establishment();
                for (const forged of [{ ...real }, { primary: real.primary }]) {
                    const completion = build();
                    const before = records?.();
                    const { req, session } = fakeRequest();
                    const { reporter, built, reports } = establishmentReporter();
                    await assert.rejects(completion.establishSession(forged, { req, reporter }), RangeError, "an object shaped like an establishment, or a copy of one, must be refused with a RangeError");
                    assert.equal(session.regenerated, 0, "the session was regenerated for a forged establishment");
                    assert.equal(session.saved, 0, "the session was saved for a forged establishment");
                    assert.deepEqual(reports, [], "a forged establishment is the caller's fault, not an outage");
                    assert.deepEqual(built, [], "a reporter was built for a forged establishment");
                    if (records !== undefined) {
                        assert.equal(records(), before, "a forged establishment wrote a session record");
                    }
                    assert.equal(signedIn(req), false);
                }
            },
        },
        {
            name: "an established login is one admission reads as signed in, for its subject, on a regenerated session saved signed in",
            run: async () => {
                const completion = build();
                const held = records?.();
                const { req, session } = fakeRequest();
                const before = sessionIdOf(req);
                const { reporter, built, reports } = establishmentReporter();
                const result = await completion.establishSession(await establishment(), { req, reporter });
                assert.equal(result.outcome, "established", `answered ${result.outcome}`);
                assert.deepEqual(reports, [], "an established login reported an outage, a failed rollback or a lost index write");
                assert.equal(session.regenerated, 1, "the session id is regenerated once: session fixation");
                assert.notEqual(sessionIdOf(req), before, "the session is established on a regenerated id");
                const claim = cookieClaim(req);
                assert.equal(claim.authenticated, true, "admission does not read the session as signed in");
                assert.equal(claim.subject, SUBJECT, "the session is signed in for another subject");
                const sid = result.sid;
                assert.ok(sid === undefined || (typeof sid === "string" && sid.length > 0), "an established sid is a non-empty string, or undefined without a session record");
                if (sid !== undefined)
                    assert.equal(claim.sid, sid, "the cookie names another session record");
                assert.deepEqual(built, [{ sid, sub: SUBJECT }], "the reporter is built once, for the record the login wrote");
                if (records !== undefined) {
                    assert.equal(records(), held + (sid === undefined ? 0 : 1), "an established login writes one session record when it answers a sid, none otherwise");
                }
                assert.ok(session.saved >= 1, "the session was not saved before the outcome was answered");
                assert.equal(cookieClaim({ session: session.lastSaved }).authenticated, true, "the session saved is not the signed-in one");
            },
        },
        {
            name: "a cookie session that cannot be regenerated or saved is its outage: reported once, never established, the browser not signed in",
            run: async () => {
                const failures = [
                    [{ regenerateFails: OUTAGE }, "regenerate"],
                    [{ saveFails: OUTAGE }, "save"],
                ];
                for (const [options, step] of failures) {
                    const completion = build();
                    const held = records?.();
                    const { req } = fakeRequest(options);
                    const { reporter, unavailable } = establishmentReporter();
                    const result = await completion.establishSession(await establishment(), {
                        req,
                        reporter,
                    });
                    assert.deepEqual(result, { outcome: "unavailable", store: "cookie_session", step }, `a cookie session whose ${step} fails is answered as its outage`);
                    assert.deepEqual(unavailable(), [["cookie_session", step]], "the outage is reported once");
                    if (records !== undefined) {
                        assert.equal(records(), held, `the ${step} failure left a session record behind`);
                    }
                    assert.equal(signedIn(req), false, `the browser is signed in although the ${step} failed`);
                }
            },
        },
    ];
    if (withSessionStoreOutage !== undefined) {
        cases.push({
            name: "a session store that is down is its outage at create: reported once, the cookie session untouched",
            run: async () => {
                const completion = withSessionStoreOutage();
                const held = records?.();
                const { req, session } = fakeRequest();
                const { reporter, unavailable } = establishmentReporter();
                const result = await completion.establishSession(await establishment(), {
                    req,
                    reporter,
                });
                assert.deepEqual(result, { outcome: "unavailable", store: "user_session", step: "create" });
                assert.deepEqual(unavailable(), [["user_session", "create"]], "the outage is reported once");
                if (records !== undefined) {
                    assert.equal(records(), held, "a session-store outage left a session record behind");
                }
                assert.equal(session.regenerated, 0, "the cookie session was regenerated with no session record");
                assert.equal(signedIn(req), false);
            },
        });
    }
    cases.push({
        name: "answerInterruption refuses, before the session is touched, an interruption core did not answer",
        run: async () => {
            const opened = [];
            const real = await interruption(ceremony(opened));
            for (const forged of [
                { ...real },
                { outcome: "interrupt", requirement: REQUIREMENT, open: ceremony(opened) },
            ]) {
                const { req, session } = fakeRequest();
                const { res, record } = fakeResponse();
                const { reporter, unavailable } = interruptionReporter();
                await assert.rejects(build().answerInterruption(forged, {
                    req,
                    res,
                    reporter,
                }), RangeError, "an object shaped like an interruption, or a copy of one, must be refused with a RangeError");
                assert.equal(session.regenerated, 0, "the session was regenerated for a forged interruption");
                assert.equal(record.ended, false, "a forged interruption was answered");
                assert.deepEqual(unavailable, []);
                assert.deepEqual(opened, [], "a forged interruption's ceremony was opened");
            }
        },
    }, {
        name: "an interruption is answered with the requirement's 403, its ceremony opened on the regenerated session, saved and not signed in",
        run: async () => {
            const opened = [];
            const admission = await interruption(ceremony(opened));
            const { req, session } = fakeRequest();
            const before = sessionIdOf(req);
            const { res, record } = fakeResponse();
            const { reporter, unavailable } = interruptionReporter();
            const result = await build().answerInterruption(admission, {
                req,
                res,
                reporter,
            });
            assert.deepEqual(result, { outcome: "answered" });
            assert.deepEqual(unavailable, []);
            assert.equal(session.regenerated, 1, "the session id is regenerated once before the ceremony");
            assert.deepEqual(opened, [sessionIdOf(req)], "the ceremony is opened once, on the regenerated id");
            assert.notEqual(opened[0], before, "the ceremony is bound to the id from before the password");
            assert.ok(session.saved >= 1, "the session was not saved before the answer");
            assert.equal(record.status, ANSWER.status, "the requirement's status is the answer's");
            assert.deepEqual(record.body, ANSWER.body, "the requirement's body is the answer's");
            assert.equal(signedIn(req), false, "an interrupted login is signed in");
            assert.equal(cookieClaim({ session: session.lastSaved }).authenticated, false);
            if (csrfCookieName !== undefined) {
                assert.equal(tokensSet(record), 1, `the 403 carries no fresh token in ${csrfCookieName}: the page cannot post on the regenerated session`);
            }
        },
    }, {
        name: "an interruption that cannot be answered is 503: the ceremony's outage, or the cookie session's, reported once, the browser not signed in",
        run: async () => {
            const failures = [
                [{}, true, REQUIREMENT, "open"],
                [{ regenerateFails: OUTAGE }, false, "cookie_session", "regenerate"],
                [{ saveFails: OUTAGE }, false, "cookie_session", "save"],
            ];
            for (const [options, ceremonyDown, store, step] of failures) {
                const admission = await interruption(async () => {
                    if (ceremonyDown)
                        throw OUTAGE;
                    return ANSWER;
                });
                const { req } = fakeRequest(options);
                const { res, record } = fakeResponse();
                const { reporter, unavailable } = interruptionReporter();
                const result = await build().answerInterruption(admission, { req, res, reporter });
                assert.deepEqual(result, { outcome: "unavailable", store, step }, `an interruption whose ${step} fails is answered as ${store}'s outage`);
                assert.deepEqual(unavailable, [[store, step]], "the outage is reported once");
                assert.equal(record.status, 503, `the ${step} failure is not answered 503`);
                assert.equal(record.body?.error, "temporarily_unavailable");
                assert.equal(tokensSet(record), 0, `the ${step} failure's 503 carries a fresh token`);
                assert.equal(signedIn(req), false);
            }
        },
    }, {
        name: "renewSession moves a signed-in session to a regenerated id, saved with isAuthenticated, user and sid as they were, a fresh renewal nonce and no other field, writing no session record",
        run: async () => {
            const completion = build();
            const { req, session, signedIn: kept } = await signedInRequest(completion);
            // A nonce an earlier renewal left: the renewal mints another.
            const earlier = newRenewalNonce();
            cookieSessionOf(req).renewalNonce = earlier;
            const held = records?.();
            const before = sessionIdOf(req);
            const { reporter, unavailable } = renewalReporter();
            const result = await completion.renewSession({ req, reporter });
            assert.equal(result.outcome, "renewed", `answered ${result.outcome}`);
            const { renewalNonce } = result;
            assert.ok(isRenewalNonce(renewalNonce), "the renewal answers no renewal nonce");
            assert.notEqual(renewalNonce, earlier, "the renewal kept the nonce an earlier one left");
            assert.deepEqual(unavailable, [], "a renewal reported an outage");
            assert.equal(session.regenerated, 1, "the session id is regenerated once");
            assert.notEqual(sessionIdOf(req), before, "the session is renewed on the id it had");
            const renewed = { ...kept, renewalNonce };
            assert.deepEqual({ ...cookieSessionOf(req) }, renewed, "the renewed session holds the signed-in state as it was and the nonce answered, and nothing beside them");
            const claim = cookieClaim(req);
            assert.equal(claim.authenticated, true, "admission does not read the renewed session as signed in");
            assert.equal(claim.subject, SUBJECT, "the renewed session is signed in for another subject");
            assert.equal(claim.sid, kept.sid, "the renewed session names another session record");
            assert.equal(claim.renewalNonce, renewalNonce, "admission does not read the nonce the renewal answered off the renewed session");
            assert.ok(session.saved >= 1, "the renewed session was not saved before the outcome was answered");
            assert.deepEqual(session.lastSaved, renewed, "the session saved is not the renewed one");
            if (records !== undefined) {
                assert.equal(records(), held, "a renewal wrote a session record");
            }
            const again = await completion.renewSession({ req, reporter });
            assert.equal(again.outcome, "renewed", `a second renewal answered ${again.outcome}`);
            assert.notEqual(again.renewalNonce, renewalNonce, "two renewals answered one nonce");
        },
    }, {
        name: "renewSession leaves a session that is not signed in so: no signed-in field is written",
        run: async () => {
            const { req } = fakeRequest();
            const { reporter, unavailable } = renewalReporter();
            const result = await build().renewSession({ req, reporter });
            assert.equal(result.outcome, "renewed", `answered ${result.outcome}`);
            assert.deepEqual(unavailable, []);
            const fields = cookieSessionOf(req);
            for (const field of ["isAuthenticated", "user", "sid"]) {
                assert.equal(Object.hasOwn(fields, field), false, `the renewal wrote ${field}`);
            }
            assert.equal(signedIn(req), false, "a session not signed in was signed in by a renewal");
        },
    }, {
        name: "a renewal whose regenerate or save fails, or of a request with no express session, is the cookie session's outage: reported once, nothing saved, the request's cookie session abandoned",
        run: async () => {
            const failures = [
                [{ regenerateFails: OUTAGE }, "regenerate"],
                [{ saveFails: OUTAGE }, "save"],
            ];
            for (const [options, step] of failures) {
                const completion = build();
                const { req, session } = await signedInRequest(completion, options);
                const { reporter, unavailable } = renewalReporter();
                const result = await completion.renewSession({ req, reporter });
                assert.deepEqual(result, { outcome: "unavailable", store: "cookie_session", step }, `a renewal whose ${step} fails is answered as the cookie session's outage`);
                assert.deepEqual(unavailable, [["cookie_session", step]], "the outage is reported once");
                assert.equal(session.saved, 0, `the ${step} failure saved a session`);
                assert.equal(signedIn(req), false, `the request's cookie session is still signed in after the ${step} failed`);
            }
            const { req } = fakeRequest();
            req.session = undefined;
            const { reporter, unavailable } = renewalReporter();
            assert.deepEqual(await build().renewSession({ req, reporter }), { outcome: "unavailable", store: "cookie_session", step: "regenerate" }, "a request with no express session is not the cookie session's outage at regenerate");
            assert.deepEqual(unavailable, [["cookie_session", "regenerate"]]);
        },
    });
    return cases;
}
const cookieSessionOf = (req) => req.session;
