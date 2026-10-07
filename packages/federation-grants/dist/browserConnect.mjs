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
 * `GET /connect`: the lodged intent read by its handle, a browser that is not
 * signed in sent to login, the judgement as `federation_grants.connect`, and the
 * consent question parked for this browser's binding before the browser is sent
 * to the consent page. Connect never approves or creates an upstream transaction.
 * A session a requirement asks to step up is sent once to the requirement's
 * page, returning here with the one-trip marker; a marked return still asked
 * to step up is refused as a dead session is, never sent again.
 * An unknown handle, every refusal after the handle is read, and every `503` this
 * handler answers are audited as `federation.grant.authorization_failed`, with only
 * what is established by then.
 */
import { LOGIN_RETURN_PARAMETER, } from "@o3co/auth-provider-core";
import { plain } from "./browserAnswers.mjs";
import { CONNECT, judge, judgementUnavailable, } from "./browserJudgement.mjs";
import { claimOf, isPrefetch, isSteppedUpReturn, single } from "./browserRequest.mjs";
import { federationGrantConnectUri } from "./lodgeRoute.mjs";
import { requestIdOf } from "./requestId.mjs";
export function createConnectHandler({ options, now, randomId, log, admissionFor, failed, }) {
    return async (req, res) => {
        try {
            // A prefetch is not the user asking: nothing is parked for it.
            if (isPrefetch(req)) {
                res.status(204).end();
                return;
            }
            const handle = single(req.query.request);
            if (handle === undefined) {
                plain(res, 400, "This link is not valid.");
                return;
            }
            let intent;
            try {
                intent = await options.intentStore.getIntent(handle, now());
            }
            catch (error) {
                log.outage("federation_grant_connect_unavailable", {
                    correlationId: requestIdOf(res),
                    reason: "storage",
                    store: "federation_grant_intent",
                    step: "get_intent",
                }, error);
                failed(req, res, "unavailable");
                plain(res, 503, "Temporarily unavailable.");
                return;
            }
            if (intent === null) {
                failed(req, res, "stale");
                plain(res, 400, "This link has expired or has already been used. Start again.");
                return;
            }
            // Not signed in: sign in and come back to exactly this link (its handle only).
            // Read from the claim before the session is asked anything, as `/authorize` does.
            const claim = claimOf(req);
            if (!claim.authenticated) {
                res.redirect(303, options.login.urlFor(federationGrantConnectUri(options.issuer, handle)));
                return;
            }
            const judged = await judge(options, admissionFor({ grantId: intent.grantId, correlationId: requestIdOf(res) }), req, claim, CONNECT, intent, now);
            if (!judged.ok) {
                if (judged.reason !== "unavailable" &&
                    judged.stepUp !== undefined &&
                    !isSteppedUpReturn(req)) {
                    const location = stepUpLocation(judged.stepUp, options.issuer, intent.handle);
                    if (location === undefined) {
                        // Registration holds a page to the issuer's origin; a resolver built
                        // without the issuer does not. A composition fault, never followed.
                        log.misconfigured("federation_grant_step_up_page_off_origin", {
                            grantId: intent.grantId,
                            correlationId: requestIdOf(res),
                            requirement: judged.stepUp.requirement,
                        });
                        plain(res, 500, "Something went wrong.");
                        return;
                    }
                    res.redirect(303, location);
                    return;
                }
                if (judged.reason === "unavailable" && judged.unanswered !== undefined) {
                    judgementUnavailable(log, "connect", { grantId: intent.grantId, correlationId: requestIdOf(res) }, intent, judged.unanswered);
                }
                failed(req, res, judged.reason, intent);
                plain(res, judged.status, messageFor(judged.reason));
                return;
            }
            let parked;
            try {
                parked = await options.intentStore.parkConsent({
                    handle,
                    challenge: randomId(),
                    binding: judged.binding,
                    now: now(),
                });
            }
            catch (error) {
                log.outage("federation_grant_connect_unavailable", {
                    grantId: intent.grantId,
                    correlationId: requestIdOf(res),
                    reason: "storage",
                    store: "federation_grant_intent",
                    step: "park_consent",
                }, error);
                failed(req, res, "unavailable", intent);
                plain(res, 503, "Temporarily unavailable.");
                return;
            }
            if (parked === null) {
                // Parked for another browser, or no longer live: the store does not say
                // which, so the audit carries the one outcome the answer gives both.
                failed(req, res, "stale", intent);
                plain(res, 400, "This link has expired or has already been used. Start again.");
                return;
            }
            res.redirect(303, consentLocation(options.consentUrl, options.issuer, parked.challenge));
        }
        catch (error) {
            log.unexpected("connect", { correlationId: requestIdOf(res) }, error);
            plain(res, 500, "Something went wrong.");
        }
    };
}
/**
 * The step-up page with `redirect_to` naming this connect, marked: built from
 * the issuer and the intent's handle alone, never from the request. `undefined`
 * for a page off the issuer's origin.
 */
function stepUpLocation(trip, issuer, handle) {
    const target = new URL(trip.page);
    if (target.origin !== new URL(issuer).origin)
        return undefined;
    target.searchParams.set(LOGIN_RETURN_PARAMETER, federationGrantConnectUri(issuer, handle, { steppedUp: true }));
    return target.href;
}
/** The consent page's URL with the challenge on it. */
function consentLocation(consentUrl, issuer, challenge) {
    const url = new URL(consentUrl, issuer);
    url.searchParams.set("challenge", challenge);
    // Always absolute on the issuer: a normalised path would turn
    // `/.//evil.example/consent` into a protocol-relative `//evil.example/consent`
    // Location carrying the challenge to another host. Boot refuses such a path too.
    return url.href;
}
function messageFor(reason) {
    switch (reason) {
        case "subject_mismatch":
            return "This request was made for another account.";
        case "reauthentication_required":
            return "Sign in again to continue.";
        case "stale":
            return "This request was replaced by a newer one. Start again.";
        case "connection_not_permitted":
            return "This application may no longer use this connection.";
        case "connection_changed":
            return "The connection has changed since this request was made. Start again.";
        case "unavailable":
            return "Temporarily unavailable.";
    }
}
