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
import { clientReturn, jsonError, NO_PENDING } from "./browserAnswers.mjs";
import { pendingFor } from "./browserPendingConsent.mjs";
import { redirectUpstream } from "./browserUpstreamRedirect.mjs";
import { requestIdOf } from "./requestId.mjs";
/** The consent answer's `error_description` for each {@link CsrfRefusalReason}. */
const CSRF_REFUSAL = Object.freeze({
    foreign_origin: "cross-site answer refused",
    token_absent: "no origin and no valid csrf token",
    token_invalid: "no origin and no valid csrf token",
    unrecognized: "cross-site answer refused",
});
/**
 * The guard's verdict read fail-closed: `null` for an acceptance, otherwise
 * why not. Only `{ outcome: "accepted" }` accepts; a promise, another outcome
 * or an unknown reason refuses, and a promise's rejection is handled here.
 */
function csrfRefusal(verdict) {
    const read = verdict;
    if (typeof verdict?.then === "function") {
        verdict.then(undefined, () => undefined);
        return "unrecognized";
    }
    if (read?.outcome === "accepted")
        return null;
    const reason = read?.outcome === "refused" ? read.reason : undefined;
    return typeof reason === "string" && Object.hasOwn(CSRF_REFUSAL, reason)
        ? reason
        : "unrecognized";
}
/** `POST /consent`: the user's answer. */
export function createConsentAnswerHandler(flow) {
    const { options, now, log, failed } = flow;
    return async (req, res) => {
        try {
            // Asked before the route reads the session binding, the challenge or
            // the intent store, so a refused answer spends no consent.
            const refusal = csrfRefusal(options.csrfGuard.check(req));
            if (refusal !== null) {
                log.refused("federation_grant_consent_csrf_refused", {
                    reason: refusal,
                    correlationId: requestIdOf(res),
                    origin: req.get("origin"),
                });
                jsonError(res, 403, "invalid_request", CSRF_REFUSAL[refusal]);
                return;
            }
            const body = (req.body ?? {});
            const found = await pendingFor(flow, req, res, body.challenge);
            if (found === null)
                return;
            const { intent, binding, challenge } = found;
            /** What every line of this answer carries. */
            const context = {
                method: req.method,
                grantId: intent.grantId,
                correlationId: requestIdOf(res),
            };
            /** A `503` this answer gives: one line at error, audited as `unavailable`. */
            const consentUnavailable = (description, at, ...cause) => {
                log.outage("federation_grant_consent_unavailable", { ...context, reason: description, ...at }, ...cause);
                failed(req, res, "unavailable", intent);
                jsonError(res, 503, "temporarily_unavailable", description);
            };
            /**
             * The answer recorded, or `null` after a `503`: an intent store that
             * cannot record it is its outage, not an unexpected error.
             */
            const record = async (answer) => {
                try {
                    return await options.intentStore.answerConsent({
                        challenge,
                        binding,
                        answer,
                        now: now(),
                    });
                }
                catch (error) {
                    consentUnavailable("storage", { store: "federation_grant_intent", step: "answer_consent" }, error);
                    return null;
                }
            };
            const decision = body.decision;
            if (decision !== "accept" && decision !== "deny") {
                // Refused with the question still parked: nothing was answered.
                jsonError(res, 400, "invalid_request", "decision must be 'accept' or 'deny'");
                return;
            }
            if (decision === "deny") {
                const answered = await record({ decision: "deny" });
                if (answered === null)
                    return;
                if (answered.outcome !== "denied") {
                    jsonError(res, 400, "invalid_request", NO_PENDING);
                    return;
                }
                if (intent.kind === "reauthorization") {
                    // Only this renewal's pointer, never a newer one: a refusal for
                    // a superseded intent must not end the intent that replaced it.
                    try {
                        await options.grantStore.retireIntent({
                            grantId: intent.grantId,
                            handle: intent.handle,
                            now: now(),
                        });
                    }
                    catch (error) {
                        // The consent is already spent, so nothing can activate
                        // through this pointer; it lapses with the flow budget.
                        log.degraded("federation_grant_consent_step_failed", { ...context, store: "federation_grant", step: "retire_intent" }, error);
                    }
                }
                failed(req, res, "access_denied", intent);
                res.redirect(303, clientReturn(intent, "access_denied"));
                return;
            }
            await redirectUpstream(flow, res, intent, record, consentUnavailable);
        }
        catch (error) {
            log.unexpected("consent", { method: req.method, correlationId: requestIdOf(res) }, error);
            jsonError(res, 500, "server_error", "unexpected_error");
        }
    };
}
