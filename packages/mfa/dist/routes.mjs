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
 * The MFA routes under `/session/mfa`: `GET /transaction`, `POST /challenge`,
 * `POST /verify`, an enrollment — a login's first binding, or one from a
 * signed-in session — `POST /enrollment` and `POST /enrollment/complete`,
 * and a session's step-up, `POST /step-up`, over the coordinator; a
 * verified second factor, or a factor bound at a login that counts at once,
 * resumes the login through core's `resumePrimary` and finishes it through
 * the `loginCompletion` slot; one verified on a session's step-up, or bound
 * in a session and counting at once, escalates that session. See README,
 * "The routes".
 *
 * - Every answer is `no-store`. Bodies are parsed on these paths alone.
 * - Every POST sits behind the deployment's CSRF guard, then the flood guard
 *   (`mfa:ip:<ip>`), before anything is read.
 * - The transaction id is read from the body or the `MFA-Transaction` header,
 *   never from the URL, and never logged; a missing, malformed, foreign,
 *   spent or expired one is answered alike. A login's begun at or before
 *   its subject's sessions boundary is `401 login_required`.
 * - A signed-in session is admitted before its transaction is read: as
 *   `mfa.manage` to enroll, and through the step-up's remediation for its
 *   proof; its `User` is the one its cookie holds (`cookieSessionUser`).
 *   The step-up asks the requirement, as `mfa.manage`, what a first binding
 *   in the session is answered, and opens the proof only where it would not
 *   be refused outright — this requirement's `unmet`, a session without
 *   `mfa` whose subject holds nothing that adds it, is not: the step-up
 *   still serves the baseline and an `acr`; another requirement's step-up
 *   is answered as its own. Requirements are asked in order and the first that is not met
 *   answers, so where this one's gate asks the proof, the trip opens before
 *   a later requirement is asked, and that one may still hold the binding
 *   back once the proof is given. A binding in a session that the subject's
 *   factors no longer allow is `409`: the session stands.
 * - For a subject holding a record that may count, the step-up opens a
 *   `step_up` transaction, with the `acr_values` the body hints read
 *   strictly — at most 16 values of at most 256 characters, else none — as a
 *   hint only; `403 mfa_no_qualifying_factor` when no factor can be used, and
 *   `401` where admission's view says no second factor can be recorded on
 *   the session (`secondFactorRecordable`), before anything is opened.
 * - The account page's management of the subject's factors, under
 *   `/factors`, is `management.mts`'s, mounted here behind the same guards
 *   and admitted through `sessionFor`, which takes a session admitted as
 *   `mfa.manage` with where its factor-set write begins (`factorSet.mts`),
 *   read before the admission. The subject's own release of its lock,
 *   `POST /lock/release`, is `lockRelease.mts`'s, and the regeneration of its
 *   recovery codes, `POST /recovery-codes`, `recoveryCodes.mts`'s, each
 *   mounted and admitted the same way.
 * - A factor that is not guessable verified at a login once its session is
 *   established, or at a step-up once its session is escalated, mints the
 *   authorization that release takes (`lockRecovery.mts`), for that session;
 *   one that cannot be minted is said at warn, the answer standing.
 * - A step-up's verification and a binding in a session escalate that
 *   session (`escalation.mts`). A step-up answers as the escalation came to;
 *   a binding answers its factor and codes, shown once, whatever it came to.
 *   Neither reaches a login's completion.
 * - A binding that adds nothing — a first binding by a sign-in alone, whose
 *   factor counts from the next sign-in that uses it (`enrollment.mts`) —
 *   escalates no session and completes no login: it answers its factor and
 *   codes alone, with no `message`, and a login's establishes no session.
 * - A login's binding marks its recovery codes shown just before the answer
 *   that carries them, once nothing else can answer the login: one answered
 *   otherwise — another requirement's interruption, `401`, `503` — leaves
 *   the set unshown, and a mark that fails answers `recovery_codes_issued:
 *   false`.
 * - A factor's own failure is logged by its name and code, never its text;
 *   one that cannot start an enrollment, or say whether the user may enroll
 *   it, is `503` (`mfa_factor_enrollment_unavailable`, its kind).
 * - An enrollment of a factor the subject holds already is `409
 *   mfa_factor_duplicate`, at its start or its completion, naming no record.
 * - Each outage is answered `503` and logged once, at error. A mail the
 *   sender refused at its limit is `429`; a factor whose recorded address no
 *   longer matches the login's is `403`, recorded as
 *   `mfa.email_address_mismatch`. Neither the code nor the address is logged.
 * - A guessable proof the subject lock holds is `429 mfa_locked`, with the
 *   hold, the exempt kinds the subject holds, the transaction's attempts
 *   left, and `Retry-After` in whole seconds rounded up — none for the hard
 *   hold — recorded as `mfa.locked`, and also as `mfa.locked.first` when it
 *   begins an episode.
 * - A recovery code spent answers, and records as `mfa.recovery_code.used`,
 *   how many codes the set has left.
 * - A verified proof that completes no login under `required` — it does not
 *   count, and the subject has no counting factor it can use — answers the
 *   login's own `403 mfa_enrollment_required`, naming the transaction
 *   reopened for a binding; a proof that gate asks nobody can give is said at
 *   warn, as at a login. A new transaction that cannot be opened is `503`, the
 *   proof spent; a login's `User` that says the subject enrolled is `503`,
 *   recorded as `mfa.enrollment_state_inconsistent`, nothing spent.
 */
import { admitSession, cookieClaim, cookieSessionUser, describeAdmissionOutage, emitAuditEvent, errorEnvelope, FEDERATED_AMR, isMfaFactorId, loggableError, readSpaceDelimitedParameter, resumePrimary, sessionAuthentication, } from "@o3co/auth-provider-core";
import express from "express";
import { createSessionEscalation } from "./escalation.mjs";
import { createMfaLockReleaseRouter } from "./lockRelease.mjs";
import { mailFailureOf } from "./mail.mjs";
import { createMfaManagementRouter, } from "./management.mjs";
import { RECOVERY_CODE_FACTOR_KIND } from "./recovery/factor.mjs";
import { createMfaRecoveryCodesRouter } from "./recoveryCodes.mjs";
import { MFA_REQUIREMENT_NAME } from "./requirement.mjs";
/** The header a transaction id may travel in beside the body. */
const TRANSACTION_HEADER = "MFA-Transaction";
const UNKNOWN_TRANSACTION = errorEnvelope("invalid_request", "Unknown or expired MFA transaction");
const UNKNOWN_FACTOR = errorEnvelope("invalid_request", "Unknown second factor");
const MFA_UNAVAILABLE = errorEnvelope("temporarily_unavailable", "MFA temporarily unavailable");
const SESSION_STORE_UNAVAILABLE = errorEnvelope("temporarily_unavailable", "Session store unavailable");
const LOGIN_REQUIRED = errorEnvelope("login_required", "Log in again");
/** A proof that would reopen a login for a binding nobody could complete: refused, nothing spent. */
const ENROLLMENT_REQUIRED = errorEnvelope("mfa_enrollment_required", "A second factor that counts must be enrolled");
const FACTOR_REFUSED = errorEnvelope("mfa_factor_refused", "This second factor cannot be used: use another");
const MAIL_LIMITED = errorEnvelope("rate_limited", "Too many codes sent: try again later");
const NOT_OPEN = errorEnvelope("invalid_request", "No enrollment is open in this MFA transaction");
const NO_PENDING = errorEnvelope("invalid_request", "No enrollment is pending in this MFA transaction");
const UNKNOWN_KIND = errorEnvelope("invalid_request", "Unknown second factor kind");
const INVALID_LABEL = errorEnvelope("invalid_request", "Invalid label");
const EMAIL_PROOF_REQUIRED = errorEnvelope("mfa_email_proof_required", "The account-email proof comes first");
const EMAIL_PROOF_UNAVAILABLE = errorEnvelope("mfa_email_proof_unavailable", "The account-email proof cannot be given for this account");
const FACTOR_LIMIT = errorEnvelope("mfa_factor_limit", "The subject holds as many second factors as it may");
const FACTOR_DUPLICATE = errorEnvelope("mfa_factor_duplicate", "This second factor is already enrolled");
const NO_QUALIFYING_FACTOR = errorEnvelope("mfa_no_qualifying_factor", "No second factor of this account can be used for a step-up");
const FACTORS_BUSY = errorEnvelope("mfa_factors_busy", "The account's second factors are being changed: try again");
const ENROLLMENT_CONFLICT = errorEnvelope("mfa_enrollment_conflict", "The account's second factors changed while enrolling: start again");
/** What adding a factor from a session is admitted as: it adds a way into the account. */
const MFA_MANAGE = "mfa.manage";
/** What a hold tells the user: the hard hold ends at no time. */
const LOCKED_DESCRIPTION = {
    backoff: "Too many failed attempts: try again later, or use another second factor",
    weekly: "Too many failed attempts this week: try again later, or use another second factor",
    hard: "Too many failed attempts: use another second factor",
};
/** A proof the subject lock held, unchecked: the hold, the exempt kinds the subject holds, and the attempts the transaction has left. */
const locked = (hold, exemptKinds, attemptsRemaining) => ({
    ...errorEnvelope("mfa_locked", LOCKED_DESCRIPTION[hold]),
    hold,
    usable_kinds: exemptKinds,
    attempts_remaining: attemptsRemaining,
});
/** A refused proof, with the attempts the transaction has left. */
const notAccepted = (attemptsRemaining) => ({
    ...errorEnvelope("mfa_invalid", "Second factor not accepted"),
    attempts_remaining: attemptsRemaining,
});
/** The express session id the request presents; empty when it presents none, which no binding matches. */
const sessionIdOf = (req) => {
    const id = req.sessionID;
    return typeof id === "string" ? id : "";
};
/** A header's value when it carries one. */
const headerOf = (req, name) => {
    const value = req.get(name);
    return typeof value === "string" && value !== "" ? value : undefined;
};
/**
 * The transaction a POST names: its body's `transaction_id`, or the
 * header's — `undefined` for none — or `"disagree"` when the two name
 * different ones.
 */
const postedTransaction = (req) => {
    const posted = req.body?.transaction_id;
    const body = typeof posted === "string" && posted !== "" ? posted : undefined;
    const header = headerOf(req, TRANSACTION_HEADER);
    if (body !== undefined && header !== undefined && body !== header)
        return "disagree";
    return { id: body ?? header };
};
/** The most `acr_values` a step-up records, and the longest one. */
const ACR_VALUES_LIMIT = { count: 16, length: 256 };
/**
 * The `acr_values` a step-up's body hints: a string read strictly
 * (`readSpaceDelimitedParameter`), within {@link ACR_VALUES_LIMIT};
 * `undefined` for anything else, which records none.
 */
const postedAcrValues = (req) => {
    const posted = req.body?.acr_values;
    if (typeof posted !== "string")
        return undefined;
    const values = readSpaceDelimitedParameter(posted);
    return values !== null &&
        values.length > 0 &&
        values.length <= ACR_VALUES_LIMIT.count &&
        values.every((value) => value.length <= ACR_VALUES_LIMIT.length)
        ? values
        : undefined;
};
/** The transaction id a POST names; two that disagree name none, which no transaction matches. */
const postedTransactionId = (req) => {
    const posted = postedTransaction(req);
    return posted === "disagree" ? undefined : posted.id;
};
/** The ceremony call a request makes, naming `transactionId`. */
const callOf = (req, transactionId) => {
    const userAgent = headerOf(req, "user-agent");
    return {
        transactionId,
        binding: { kind: "session", id: sessionIdOf(req) },
        request: {
            ...(typeof req.ip === "string" ? { ip: req.ip } : {}),
            ...(userAgent === undefined ? {} : { userAgent }),
        },
    };
};
/** Every answer of these routes is kept by no cache. */
const noStore = (_req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
};
/**
 * Where a user-session store is wired, core's session lifecycle is required:
 * admission reads the session's lifecycle record through the port, so a
 * session closing or closed is admitted to nothing. Throws when the store is
 * wired without the port.
 */
export function requireSessionLifecycleStore(admission) {
    if (admission.userSessionStore !== undefined && admission.sessionLifecycleStore === undefined) {
        throw new Error("mfa: userSessionStore is wired, but sessionLifecycleStore is not. Where a user-session " +
            "store is wired, core's session lifecycle is required: the MFA routes' admission reads " +
            "the session's lifecycle record through it. Wire core's session lifecycle: a " +
            "session-store module that fills sessionLifecycleStore (memorySessionStoresModule or " +
            "redisSessionStoresModule) and sessionLifecycleModule.");
    }
}
/** The MFA routes' router (see this file's header). */
export function createMfaRouter(options) {
    requireSessionLifecycleStore(options.admission);
    const { coordinator, admission, stepUp, loginCompletion, secondFactorStore, csrfGuard, floodGuard, logger, auditSink, management, lockRecovery, recoveryCodes, } = options;
    const router = express.Router();
    /**
     * The session the request's cookie carries, admitted for `action`, and the
     * record's renewal nonce as admission read it — what an escalation of this
     * session expects the record to hold. None for a record that holds none,
     * whatever the cookie session holds.
     */
    const admitCookie = async (req, action) => {
        // express-session's `req.session`, read without its type package.
        const claim = cookieClaim(req);
        const admitted = await admitSession(admission, { claim, action });
        return {
            admitted,
            expectedRenewalNonce: admitted.outcome === "admitted" ? admitted.renewalNonce : undefined,
        };
    };
    /** A factor that could not start an enrollment, or say whether the user may enroll it: `503`, once at error, by its kind. */
    const answerEnrollmentFailed = (route, res, kind, cause) => {
        logger.error({ route, kind, err: mailFailureOf(cause) }, "mfa_factor_enrollment_unavailable");
        res.status(503).json(MFA_UNAVAILABLE);
    };
    /**
     * A binding the subject's records no longer allow: a login starts again
     * (`401 login_required`); a session, which stands, is told the factors
     * changed (`409 mfa_enrollment_conflict`).
     */
    const answerClosed = (res, purpose) => {
        if (purpose === "enroll")
            res.status(409).json(ENROLLMENT_CONFLICT);
        else
            res.status(401).json(LOGIN_REQUIRED);
    };
    /** An admission that is no session to go on: an outage `503`, anything else `401`. */
    const answerNoSession = (res, admitted) => {
        if (admitted.outcome === "unavailable") {
            // Admission logged it once.
            res
                .status(503)
                .json(errorEnvelope("temporarily_unavailable", describeAdmissionOutage(admitted.store)));
            return;
        }
        res.status(401).json(LOGIN_REQUIRED);
    };
    /** A requirement's step-up: `403 step_up_required`, naming the requirement and its page. */
    const answerStepUp = (res, admitted) => {
        res.status(403).json({
            error: "step_up_required",
            error_description: "This action requires a step-up first",
            requirement: admitted.requirement,
            page: admitted.page.href,
        });
    };
    /**
     * The signed-in session the request's cookie carries, admitted for
     * `action`, with the `User` its cookie holds and the renewal nonce
     * admission compared; `undefined` once the refusal is answered — a
     * requirement's step-up among them.
     */
    const sessionFor = async (req, res, action) => {
        // A session admitted to change the factor set is held to the subject's generation read before its admission.
        const claim = cookieClaim(req);
        const factorSetStart = action === MFA_MANAGE && claim.authenticated && claim.subject !== undefined
            ? await management.factorSet.begin(claim.subject, "change")
            : undefined;
        const { admitted, expectedRenewalNonce } = await admitCookie(req, action);
        if (admitted.outcome === "step_up") {
            answerStepUp(res, admitted);
            return undefined;
        }
        const session = admitted.outcome === "admitted" ? admitted.session : null;
        const user = session === null
            ? undefined
            : cookieSessionUser(req, session.sub);
        if (session === null || user === undefined) {
            answerNoSession(res, admitted);
            return undefined;
        }
        let authTimeMs;
        let witness;
        let secondFactorRecordable = false;
        if (admitted.outcome === "admitted" && admitted.view !== null) {
            const view = admitted.view;
            authTimeMs = view.authTime.getTime();
            witness = view.enrollmentFacts?.witness;
            secondFactorRecordable = view.secondFactorRecordable === true;
        }
        return {
            session: {
                sid: session.sid,
                subject: session.sub,
                user,
                authTimeMs,
                federated: sessionAuthentication(session)?.primary === FEDERATED_AMR,
                witness,
                secondFactorRecordable,
                ...(factorSetStart === undefined ? {} : { factorSetStart }),
            },
            expectedRenewalNonce,
        };
    };
    /**
     * The call `req` makes, naming `transactionId`, in the session its cookie
     * carries when it is signed in — admitted for `action`, with the renewal
     * nonce admission compared — and in none when it is not, as a login's
     * ceremony is; `undefined` once a refusal is answered.
     */
    const signedInCall = async (req, res, transactionId, action) => {
        const call = callOf(req, transactionId);
        if (!cookieClaim(req).authenticated) {
            return { call, expectedRenewalNonce: undefined };
        }
        const signedIn = await sessionFor(req, res, action);
        return signedIn === undefined
            ? undefined
            : {
                call: { ...call, session: signedIn.session },
                expectedRenewalNonce: signedIn.expectedRenewalNonce,
            };
    };
    const storeUnavailable = (route, store, step, cause, context = {}) => {
        logger.error({ route, ...context, store, step, err: loggableError(cause) }, "mfa_store_unavailable");
    };
    /** An MFA store's outage or an unreadable factor: logged once, answered 503. */
    const answerOutage = (route, res, failure) => {
        if (failure.outcome === "unavailable") {
            storeUnavailable(route, failure.store, failure.step, failure.cause);
        }
        else {
            logger.error({
                route,
                kind: failure.kind,
                ...(isMfaFactorId(failure.factorId) ? { factorId: failure.factorId } : {}),
                state: failure.state,
                ...(failure.keyId === undefined ? {} : { keyId: failure.keyId }),
                ...(failure.cause === undefined
                    ? {}
                    : {
                        // A factor's own throw by its name and code alone: its text may quote the account.
                        err: failure.state === "verification" || failure.state === "enrollment"
                            ? mailFailureOf(failure.cause)
                            : loggableError(failure.cause),
                    }),
            }, "mfa_factor_unreadable");
        }
        res.status(503).json(MFA_UNAVAILABLE);
    };
    /** A witness mark that failed: once at warn; what it followed stands, and the next login heals it. */
    const witnessUnwritten = (sub, mark) => {
        if (mark?.outcome !== "unwritten")
            return;
        logger.warn({ sub, err: loggableError(mark.cause) }, "mfa_enrollment_witness_unwritten");
    };
    /** A login begun at or before its subject's sessions boundary: said at info, and `401 login_required`. */
    const answerRevoked = (route, res, revoked) => {
        logger.info({ sub: revoked.subject, route }, "mfa_login_revoked");
        res.status(401).json(LOGIN_REQUIRED);
    };
    /**
     * A first binding the subject's first-binding mark distrusts: said at
     * info, and `401 login_required` with `Retry-After`, the whole seconds,
     * rounded up, until a fresh sign-in can bind on this replica's clock.
     */
    const answerDistrusted = (route, res, distrusted) => {
        logger.info({ sub: distrusted.subject, route }, "mfa_first_binding_distrusted");
        res.set("Retry-After", String(Math.max(1, Math.ceil(distrusted.retryAfterMs / 1000))));
        res.status(401).json(LOGIN_REQUIRED);
    };
    /** A first-binding mark a verification could not note: once at warn; the witness was left unmarked, and the next login heals it. */
    const firstBindingUnnoted = (sub, unnoted) => {
        if (unnoted === undefined)
            return;
        logger.warn({ sub, store: unnoted.store, step: unnoted.step, err: loggableError(unnoted.cause) }, "mfa_first_binding_unnoted");
    };
    /** A mail the ceremony could not send: `429` at the sender's limit; else logged once and `503`. */
    const answerMail = (route, res, refusal) => {
        if (refusal.outcome === "mail_refused_at_limit") {
            logger.warn({ route, purpose: refusal.purpose, kind: refusal.kind, cleared: refusal.cleared }, "mfa_mail_refused_at_limit");
            res.status(429).json(MAIL_LIMITED);
            return;
        }
        // A sender's failure by its name, code and status: its text may quote the address or the code.
        logger.error({
            route,
            purpose: refusal.purpose,
            kind: refusal.kind,
            reason: refusal.reason,
            ...(refusal.cleared === undefined ? {} : { cleared: refusal.cleared }),
            ...(refusal.cause === undefined ? {} : { err: mailFailureOf(refusal.cause) }),
        }, "mfa_mail_unavailable");
        res.status(503).json(MFA_UNAVAILABLE);
    };
    /**
     * The login a verified second factor resumes: `resumePrimary`, then the
     * session established, or another requirement's interruption answered. A
     * continuation core refuses sends the user back to the password.
     */
    const completeLogin = async (route, req, res, verified, 
    /** What the login's answer carries: made last, after the session and the CSRF token; must not throw. */
    answer = {}, 
    /** Run once the session is established, before the answer: what follows from the login's sid. */
    onEstablished) => {
        let resumed;
        try {
            if (verified.continuation === undefined) {
                throw new RangeError("the login's transaction carries no continuation");
            }
            resumed = await resumePrimary(admission, verified.continuation, {
                requirement: MFA_REQUIREMENT_NAME,
                adds: verified.adds,
            });
        }
        catch (err) {
            if (!(err instanceof RangeError))
                throw err;
            logger.warn({ err: loggableError(err) }, "mfa_login_not_resumed");
            res.status(401).json(LOGIN_REQUIRED);
            return;
        }
        if (resumed.outcome === "unavailable") {
            // Admission logged it once.
            res
                .status(503)
                .json(errorEnvelope("temporarily_unavailable", describeAdmissionOutage(resumed.store)));
            return;
        }
        if (resumed.outcome === "interrupt") {
            await loginCompletion.answerInterruption(resumed, {
                req,
                res,
                reporter: {
                    storeUnavailable: (store, step, cause) => storeUnavailable(route, store, step, cause),
                },
            });
            return;
        }
        const established = await loginCompletion.establishSession(resumed.establishment, {
            req,
            reporter: ({ sid, sub }) => {
                const named = sid === undefined ? {} : { sid };
                return {
                    storeUnavailable: (store, step, cause) => storeUnavailable(route, store, step, cause, step === "create" ? { ...named, sub } : named),
                    cleanupFailed: (store, step, cause) => logger.warn({ ...named, store, step, err: loggableError(cause) }, "mfa_login_cleanup_failed"),
                    subjectIndexWriteFailed: (cause) => logger.error({ err: loggableError(cause), sub, ...named }, "subject_session_index_write_failed"),
                };
            },
        });
        if (established.outcome === "unavailable") {
            res.status(503).json(SESSION_STORE_UNAVAILABLE);
            return;
        }
        if (established.sid !== undefined)
            await onEstablished?.(established.sid);
        csrfGuard.issue(res);
        const carried = typeof answer === "function" ? await answer() : answer;
        res.status(200).json({ message: "Logged in successfully", ...carried });
    };
    const { escalate: escalateSession, answer: answerEscalation } = createSessionEscalation({
        secondFactorStore,
        loginCompletion,
        reach: () => admission.requirements.get(MFA_REQUIREMENT_NAME)?.reach,
        csrfGuard,
        logger,
        storeUnavailable,
    });
    /**
     * The authorization a factor of `kind` verified at `atMs` in session `sid`
     * mints (`lockRecovery.mts`): none for a guessable one; one that cannot be
     * recorded said once at warn, the answer standing.
     */
    const mintRecovery = async (route, subject, sid, kind, atMs) => {
        const minted = await lockRecovery.authorize(subject, sid, kind, atMs);
        if (minted.outcome === "unavailable") {
            logger.warn({ route, sub: subject, err: loggableError(minted.cause) }, "mfa_lock_recovery_unauthorized");
        }
    };
    router
        .all([
        "/transaction",
        "/challenge",
        "/verify",
        "/enrollment",
        "/enrollment/complete",
        "/step-up",
        "/factors",
        "/factors/rename",
        "/factors/remove",
        "/lock/release",
        "/recovery-codes",
    ], noStore)
        // These paths' own bodies, parsed here: the mount is under `/session`,
        // where other modules mount routes too.
        .post([
        "/challenge",
        "/verify",
        "/enrollment",
        "/enrollment/complete",
        "/step-up",
        "/factors/rename",
        "/factors/remove",
        "/lock/release",
        "/recovery-codes",
    ], express.json(), express.urlencoded({ extended: false }), csrfGuard.middleware, floodGuard)
        .use(createMfaManagementRouter({
        ...management,
        admit: (async (req, res, action) => (await sessionFor(req, res, action))?.session),
        logger,
        auditSink,
    }))
        .use(createMfaLockReleaseRouter({
        lockRecovery,
        admit: async (req, res) => (await sessionFor(req, res, MFA_MANAGE))?.session,
        logger,
        auditSink,
    }))
        .use(createMfaRecoveryCodesRouter({
        factors: management.factors,
        factorSet: management.factorSet,
        sealing: management.sealing,
        ...recoveryCodes,
        admit: async (req, res) => (await sessionFor(req, res, MFA_MANAGE))?.session,
        logger,
        auditSink,
    }))
        .get("/transaction", async (req, res) => {
        // The id travels in the header alone: a GET has no body, and never a URL.
        const signed = await signedInCall(req, res, headerOf(req, TRANSACTION_HEADER), stepUp);
        if (signed === undefined)
            return;
        const { call } = signed;
        const outcome = await coordinator.describe(call);
        if (outcome.outcome === "unknown_transaction") {
            res.status(400).json(UNKNOWN_TRANSACTION);
            return;
        }
        if (outcome.outcome === "revoked") {
            answerRevoked("transaction", res, outcome);
            return;
        }
        if (outcome.outcome === "unavailable") {
            answerOutage("transaction", res, outcome);
            return;
        }
        const { view } = outcome;
        res.status(200).json({
            purpose: view.purpose,
            factors: view.factors,
            enrollment: view.enrollment,
            email_proof: view.emailProof,
            expires_in: view.expiresIn,
            attempts_remaining: view.attemptsRemaining,
        });
    })
        .post("/challenge", async (req, res) => {
        const signed = await signedInCall(req, res, postedTransactionId(req), stepUp);
        if (signed === undefined)
            return;
        const { call } = signed;
        const outcome = await coordinator.challenge({
            ...call,
            factorId: req.body?.factor_id,
        });
        switch (outcome.outcome) {
            case "unknown_transaction":
                res.status(400).json(UNKNOWN_TRANSACTION);
                return;
            case "revoked":
                answerRevoked("challenge", res, outcome);
                return;
            case "unknown_factor":
                res.status(400).json(UNKNOWN_FACTOR);
                return;
            case "unavailable":
            case "unreadable":
                answerOutage("challenge", res, outcome);
                return;
            case "challenge_failed":
                logger.error({
                    kind: outcome.kind,
                    ...(isMfaFactorId(outcome.factorId) ? { factorId: outcome.factorId } : {}),
                    // The factor's failure by its name and code alone: its text may quote the account.
                    err: mailFailureOf(outcome.cause),
                }, "mfa_factor_challenge_unavailable");
                res.status(503).json(MFA_UNAVAILABLE);
                return;
            case "mail_unavailable":
            case "mail_refused_at_limit":
                answerMail("challenge", res, outcome);
                return;
            case "address_mismatch":
                emitAuditEvent(auditSink, {
                    timestamp: new Date(),
                    type: "mfa.email_address_mismatch",
                    subject: outcome.subject,
                    ip: call.request.ip,
                    userAgent: call.request.userAgent,
                    details: { kind: outcome.kind, purpose: outcome.purpose },
                });
                res.status(403).json(FACTOR_REFUSED);
                return;
            case "proof_unavailable":
                res.status(403).json(EMAIL_PROOF_UNAVAILABLE);
                return;
            case "none":
                res.status(200).json({});
                return;
            case "sent":
                emitAuditEvent(auditSink, {
                    timestamp: new Date(),
                    type: "mfa.challenge.sent",
                    subject: outcome.subject,
                    ip: call.request.ip,
                    userAgent: call.request.userAgent,
                    details: { kind: outcome.kind, purpose: outcome.purpose },
                });
                res.status(200).json(outcome.response);
                return;
        }
    })
        .post("/verify", async (req, res) => {
        const signed = await signedInCall(req, res, postedTransactionId(req), stepUp);
        if (signed === undefined)
            return;
        const { call, expectedRenewalNonce } = signed;
        const body = req.body;
        const outcome = await coordinator.verify({
            ...call,
            factorId: body?.factor_id,
            proof: body?.proof,
        });
        /** A verified proof's events: `mfa.verified`, and `mfa.recovery_code.used` for a recovery code spent. */
        const verifiedEvents = (verified) => {
            emitAuditEvent(auditSink, {
                timestamp: new Date(),
                type: "mfa.verified",
                subject: verified.subject,
                ip: call.request.ip,
                userAgent: call.request.userAgent,
                details: {
                    kind: verified.kind,
                    purpose: verified.purpose,
                    ...(verified.outcome === "binding_reopened" ||
                        verified.outcome === "binding_not_reopened"
                        ? { reopened: true }
                        : {}),
                },
            });
            if (verified.recoveryCodesRemaining !== undefined) {
                emitAuditEvent(auditSink, {
                    timestamp: new Date(),
                    type: "mfa.recovery_code.used",
                    subject: verified.subject,
                    ip: call.request.ip,
                    userAgent: call.request.userAgent,
                    details: {
                        kind: verified.kind,
                        purpose: verified.purpose,
                        remaining: verified.recoveryCodesRemaining,
                    },
                });
            }
        };
        switch (outcome.outcome) {
            case "unknown_transaction":
            case "spent":
                res.status(400).json(UNKNOWN_TRANSACTION);
                return;
            case "revoked":
                answerRevoked("verify", res, outcome);
                return;
            case "first_binding_distrusted":
                answerDistrusted("verify", res, outcome);
                return;
            case "unknown_factor":
                res.status(400).json(UNKNOWN_FACTOR);
                return;
            case "enrollment_state_inconsistent":
                emitAuditEvent(auditSink, {
                    timestamp: new Date(),
                    type: "mfa.enrollment_state_inconsistent",
                    subject: outcome.subject,
                    ip: call.request.ip,
                    userAgent: call.request.userAgent,
                    details: { purpose: outcome.purpose, witness: outcome.witness },
                });
                logger.error({ route: "verify", sub: outcome.subject, witness: outcome.witness }, "mfa_enrollment_state_inconsistent");
                res.status(503).json(MFA_UNAVAILABLE);
                return;
            case "nothing_enrollable":
                logger.warn({ kinds: outcome.countingKinds }, "mfa_enrollment_nothing_enrollable");
                res.status(503).json(MFA_UNAVAILABLE);
                return;
            case "enrollable_failed":
                answerEnrollmentFailed("verify", res, outcome.factorKind, outcome.cause);
                return;
            case "binding_refused":
                if (outcome.unprovable !== undefined) {
                    logger.warn({ sub: outcome.subject, reason: outcome.unprovable }, "mfa_email_proof_unprovable");
                }
                res.status(403).json(ENROLLMENT_REQUIRED);
                return;
            case "binding_reopened":
                verifiedEvents(outcome);
                res.status(outcome.answer.status).json(outcome.answer.body);
                return;
            case "binding_not_reopened":
                verifiedEvents(outcome);
                answerOutage("verify", res, outcome.outage);
                return;
            case "unavailable":
            case "unreadable":
                answerOutage("verify", res, outcome);
                return;
            case "locked": {
                const held = { kind: outcome.kind, purpose: outcome.purpose, hold: outcome.hold };
                emitAuditEvent(auditSink, {
                    timestamp: new Date(),
                    type: "mfa.locked",
                    subject: outcome.subject,
                    ip: call.request.ip,
                    userAgent: call.request.userAgent,
                    details: held,
                });
                if (outcome.first) {
                    emitAuditEvent(auditSink, {
                        timestamp: new Date(),
                        type: "mfa.locked.first",
                        subject: outcome.subject,
                        ip: call.request.ip,
                        userAgent: call.request.userAgent,
                        details: {
                            ...held,
                            ...(outcome.binding === undefined ? {} : { binding: outcome.binding }),
                        },
                    });
                }
                if (outcome.retryAfterMs !== null) {
                    res.set("Retry-After", String(Math.max(1, Math.ceil(outcome.retryAfterMs / 1000))));
                }
                res
                    .status(429)
                    .json(locked(outcome.hold, outcome.exemptKinds, outcome.attemptsRemaining));
                return;
            }
            case "refused":
                if (outcome.factorIdDropped === true) {
                    // A factor answering outside its contract: the value it named is never logged.
                    logger.warn({ kind: outcome.kind }, "mfa_refusal_factor_id_dropped");
                }
                emitAuditEvent(auditSink, {
                    timestamp: new Date(),
                    type: "mfa.verify.failure",
                    subject: outcome.subject,
                    ip: call.request.ip,
                    userAgent: call.request.userAgent,
                    details: {
                        kind: outcome.kind,
                        purpose: outcome.purpose,
                        reason: outcome.reason,
                        ...(isMfaFactorId(outcome.factorId) ? { factorId: outcome.factorId } : {}),
                    },
                });
                res.status(401).json(notAccepted(outcome.attemptsRemaining));
                return;
            case "proved":
                emitAuditEvent(auditSink, {
                    timestamp: new Date(),
                    type: "mfa.verified",
                    subject: outcome.subject,
                    ip: call.request.ip,
                    userAgent: call.request.userAgent,
                    details: { kind: outcome.kind, purpose: outcome.purpose },
                });
                res.status(200).json({ email_proof: "verified" });
                return;
            case "stepped_up": {
                verifiedEvents(outcome);
                firstBindingUnnoted(outcome.subject, outcome.firstBindingUnnoted);
                witnessUnwritten(outcome.subject, outcome.witness);
                const escalation = await escalateSession("verify", req, res, { sid: outcome.sid, sub: outcome.subject }, expectedRenewalNonce, outcome.adds);
                if (escalation === "escalated") {
                    await mintRecovery("verify", outcome.subject, outcome.sid, outcome.kind, outcome.adds.mfaAt.getTime());
                }
                answerEscalation(res, escalation, {
                    step_up: "verified",
                    ...(outcome.recoveryCodesRemaining === undefined
                        ? {}
                        : { recovery_codes_remaining: outcome.recoveryCodesRemaining }),
                });
                return;
            }
            case "verified":
                verifiedEvents(outcome);
                firstBindingUnnoted(outcome.subject, outcome.firstBindingUnnoted);
                witnessUnwritten(outcome.subject, outcome.witness);
                await completeLogin("verify", req, res, outcome, outcome.recoveryCodesRemaining === undefined
                    ? {}
                    : { recovery_codes_remaining: outcome.recoveryCodesRemaining }, (sid) => mintRecovery("verify", outcome.subject, sid, outcome.kind, outcome.adds.mfaAt.getTime()));
                return;
        }
    });
    router
        .post("/enrollment", async (req, res) => {
        const posted = postedTransaction(req);
        if (posted === "disagree") {
            res.status(400).json(UNKNOWN_TRANSACTION);
            return;
        }
        const transactionId = posted.id;
        // With no transaction named, the enrollment is the signed-in session's own.
        let call;
        if (transactionId === undefined) {
            const signedIn = await sessionFor(req, res, MFA_MANAGE);
            call =
                signedIn === undefined
                    ? undefined
                    : { ...callOf(req, undefined), session: signedIn.session };
        }
        else {
            call = (await signedInCall(req, res, transactionId, MFA_MANAGE))?.call;
        }
        if (call === undefined)
            return;
        const outcome = await coordinator.beginEnrollment({
            ...call,
            kind: req.body?.kind,
        });
        switch (outcome.outcome) {
            case "unknown_transaction":
                res.status(400).json(UNKNOWN_TRANSACTION);
                return;
            case "revoked":
                answerRevoked("enrollment", res, outcome);
                return;
            case "first_binding_distrusted":
                answerDistrusted("enrollment", res, outcome);
                return;
            case "enrollment_not_open":
                res.status(400).json(NOT_OPEN);
                return;
            case "email_proof_required":
                res.status(403).json(EMAIL_PROOF_REQUIRED);
                return;
            case "unknown_kind":
                res.status(400).json(UNKNOWN_KIND);
                return;
            case "first_binding_closed":
                answerClosed(res, outcome.purpose);
                return;
            case "factor_limit":
                res.status(409).json(FACTOR_LIMIT);
                return;
            case "factor_duplicate":
                res.status(409).json(FACTOR_DUPLICATE);
                return;
            case "unavailable":
                answerOutage("enrollment", res, outcome);
                return;
            case "mail_unavailable":
            case "mail_refused_at_limit":
                answerMail("enrollment", res, outcome);
                return;
            case "enrollment_failed":
                answerEnrollmentFailed("enrollment", res, outcome.kind, outcome.cause);
                return;
            case "begun": {
                const opened = outcome.transaction;
                // A session's enrollment names its transaction, which the page completes on,
                // and how long it can: a mailed code's life, else the transaction's.
                res.status(200).json(opened === undefined
                    ? outcome.response
                    : {
                        ...outcome.response,
                        transaction: opened.id,
                        expires_in: outcome.expiresIn ?? opened.expiresIn,
                    });
                return;
            }
        }
    })
        .post("/enrollment/complete", async (req, res) => {
        const signed = await signedInCall(req, res, postedTransactionId(req), MFA_MANAGE);
        if (signed === undefined)
            return;
        const { call, expectedRenewalNonce } = signed;
        const body = req.body;
        const outcome = await coordinator.completeEnrollment({
            ...call,
            proof: body?.proof,
            label: body?.label,
        });
        if (outcome.overran === true) {
            // What the binding wrote stands; a reset or a recovery may have run beside it.
            logger.error({ route: "enrollment", ...("subject" in outcome ? { sub: outcome.subject } : {}) }, "mfa_subject_lease_overrun");
        }
        switch (outcome.outcome) {
            case "unknown_transaction":
            case "spent":
                res.status(400).json(UNKNOWN_TRANSACTION);
                return;
            case "revoked":
                answerRevoked("enrollment", res, outcome);
                return;
            case "first_binding_distrusted":
                answerDistrusted("enrollment", res, outcome);
                return;
            case "enrollment_not_open":
                res.status(400).json(NOT_OPEN);
                return;
            case "email_proof_required":
                res.status(403).json(EMAIL_PROOF_REQUIRED);
                return;
            case "no_pending_enrollment":
                res.status(400).json(NO_PENDING);
                return;
            case "factors_busy":
                res.set("Retry-After", String(Math.max(1, outcome.retryAfterSeconds)));
                res.status(409).json(FACTORS_BUSY);
                return;
            case "unknown_kind":
                res.status(400).json(UNKNOWN_KIND);
                return;
            case "invalid_label":
                res.status(400).json(INVALID_LABEL);
                return;
            case "first_binding_closed":
                answerClosed(res, outcome.purpose);
                return;
            case "factor_limit":
                res.status(409).json(FACTOR_LIMIT);
                return;
            case "factor_duplicate":
                res.status(409).json(FACTOR_DUPLICATE);
                return;
            case "first_binding_conflict":
                // Another transaction bound the subject's first factor at once: a
                // password holder may be racing the owner.
                emitAuditEvent(auditSink, {
                    timestamp: new Date(),
                    type: "mfa.first_binding_conflict",
                    subject: outcome.subject,
                    ip: call.request.ip,
                    userAgent: call.request.userAgent,
                    details: { kind: outcome.kind },
                });
                answerClosed(res, outcome.purpose);
                return;
            case "unavailable":
            case "unreadable":
                answerOutage("enrollment", res, outcome);
                return;
            case "enrollment_failed":
                answerEnrollmentFailed("enrollment", res, outcome.kind, outcome.cause);
                return;
            case "refused":
                res.status(401).json(notAccepted(outcome.attemptsRemaining));
                return;
            case "enrolled": {
                const audited = {
                    timestamp: new Date(),
                    subject: outcome.subject,
                    ip: call.request.ip,
                    userAgent: call.request.userAgent,
                };
                emitAuditEvent(auditSink, {
                    ...audited,
                    type: "mfa.factor.enrolled",
                    details: {
                        kind: outcome.kind,
                        purpose: outcome.purpose,
                        binding: outcome.binding,
                        by: "user",
                    },
                });
                /** What the binding's codes came to, audited and said once: a failed write before the answer, the mark's outcome once it is sent. */
                const codesSaid = (codes) => {
                    if (codes?.issued === true) {
                        emitAuditEvent(auditSink, {
                            ...audited,
                            type: "mfa.recovery_codes.generated",
                            details: {
                                kind: RECOVERY_CODE_FACTOR_KIND,
                                purpose: outcome.purpose,
                                binding: outcome.binding,
                                by: "user",
                                regenerated: codes.regenerated,
                                // A set that stood may still stand beside the new one: kept, or not removed.
                                ...(codes.unreplaced === undefined ? {} : { unreplaced: true }),
                                ...(codes.unreplaced !== undefined && "kept" in codes.unreplaced
                                    ? { kept: codes.unreplaced.kept }
                                    : {}),
                            },
                        });
                        if (codes.unreplaced !== undefined && "cause" in codes.unreplaced) {
                            logger.error({ sub: outcome.subject, err: loggableError(codes.unreplaced.cause) }, "mfa_recovery_codes_unreplaced");
                        }
                    }
                    else if (codes?.issued === false && codes.conflict === true) {
                        // Another writer's set landed first: a conflict, not an outage.
                        logger.warn({ sub: outcome.subject }, "mfa_recovery_codes_conflict");
                    }
                    else if (codes?.issued === false) {
                        logger.error({ sub: outcome.subject, err: loggableError(codes.cause) }, "mfa_recovery_codes_unwritten");
                    }
                };
                const written = outcome.recoveryCodes;
                // A set that could not be written is said now, whatever the answer comes to.
                if (written !== undefined && !("written" in written) && !written.issued) {
                    codesSaid(written);
                }
                /** The codes a sent answer carried, or said it could not carry: `undefined` until it is made. */
                let answered;
                /** The binding's answer, made just before it is sent: a set written unshown is shown there, nothing else done. */
                const answer = async () => {
                    let codes;
                    if (written !== undefined && "written" in written) {
                        codes = await written.show();
                        answered = { codes };
                    }
                    else {
                        codes = written;
                        if (written?.issued === true)
                            answered = { codes };
                    }
                    // A page that got none points to their regeneration.
                    return {
                        factor: outcome.factor,
                        ...(codes === undefined
                            ? {}
                            : codes.issued
                                ? { recovery_codes: codes.codes }
                                : { recovery_codes_issued: false }),
                    };
                };
                /**
                 * Once the answer is sent: what the codes it carried came to. A logger
                 * that throws here no longer changes the answer, and is not let past it.
                 */
                const answerSaid = () => {
                    try {
                        if (answered !== undefined)
                            codesSaid(answered.codes);
                    }
                    catch {
                        // The answer stands; there is nowhere left to say it.
                    }
                };
                witnessUnwritten(outcome.subject, outcome.witness);
                if (outcome.flagUncleared !== undefined) {
                    logger.warn({ sub: outcome.subject, err: loggableError(outcome.flagUncleared) }, "mfa_email_proof_flag_uncleared");
                }
                // What the binding adds, when it counts in this sign-in (`enrollment.mts`).
                const { adds } = outcome;
                if (outcome.purpose !== "enroll" && adds !== undefined) {
                    await completeLogin("enrollment", req, res, { continuation: outcome.continuation, adds }, answer);
                    answerSaid();
                    return;
                }
                // A binding in a session that adds escalates it. One that adds nothing
                // leaves the sign-in as it was: a login's establishes no session. The
                // codes are shown this once, so the binding is answered whether or not
                // an escalation lands; each failure is logged there.
                if (outcome.purpose === "enroll" && call.session !== undefined && adds !== undefined) {
                    await escalateSession("enrollment", req, res, { sid: call.session.sid, sub: outcome.subject }, expectedRenewalNonce, adds);
                }
                res.status(200).json(await answer());
                answerSaid();
                return;
            }
        }
    })
        .post("/step-up", async (req, res) => {
        const posted = postedTransaction(req);
        if (posted === "disagree") {
            res.status(400).json(UNKNOWN_TRANSACTION);
            return;
        }
        // The trip is admitted as the remediation: a live session, whatever it lacks.
        const signedIn = await sessionFor(req, res, stepUp);
        if (signedIn === undefined)
            return;
        const { session } = signedIn;
        // What a first binding in this session is answered: an outage, a new
        // login, another requirement's step-up — answered as its own — or one
        // this requirement's proof can meet, or none owed.
        const { admitted: judged } = await admitCookie(req, MFA_MANAGE);
        if (judged.outcome === "step_up" && judged.requirement !== MFA_REQUIREMENT_NAME) {
            answerStepUp(res, judged);
            return;
        }
        // This requirement's unmet says a management action cannot be met through
        // the factors held; the step-up itself, which other asks reach, still opens.
        const unmetHere = judged.outcome === "unmet" && judged.requirement === MFA_REQUIREMENT_NAME;
        if (judged.outcome !== "admitted" && judged.outcome !== "step_up" && !unmetHere) {
            answerNoSession(res, judged);
            return;
        }
        const outcome = await coordinator.stepUp({
            ...callOf(req, posted.id),
            session,
            acrValues: postedAcrValues(req),
        });
        switch (outcome.outcome) {
            case "unknown_transaction":
                res.status(400).json(UNKNOWN_TRANSACTION);
                return;
            case "unavailable":
                answerOutage("step-up", res, outcome);
                return;
            case "step_up_unrecordable":
                res.status(401).json(LOGIN_REQUIRED);
                return;
            case "no_qualifying_factor":
                res.status(403).json(NO_QUALIFYING_FACTOR);
                return;
            case "opened":
                res.status(200).json({
                    transaction: outcome.transaction.id,
                    expires_in: outcome.transaction.expiresIn,
                    email_proof: outcome.emailProof,
                });
                return;
        }
    });
    return router;
}
