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
import { jsonError, NO_PENDING } from "./browserAnswers.mjs";
export async function redirectUpstream({ options, randomId }, res, intent, record, consentUnavailable) {
    const authorizer = options.authorizerFor(intent.federation);
    if (authorizer === undefined) {
        // Boot refuses a connection whose federation lacks the
        // capability; reaching here is a composition fault, and nothing
        // has been spent.
        consentUnavailable("upstream_unavailable", { step: "authorizer" });
        return;
    }
    const state = randomId();
    const nonce = randomId();
    const codeVerifier = randomId();
    let upstream;
    try {
        // Built BEFORE the answer is spent: a configuration fault in the
        // URL must not consume the user's consent.
        upstream = authorizer.buildDelegatedAuthorizationUrl({
            redirectUri: intent.callbackUri,
            state,
            codeVerifier,
            nonce,
            scopes: intent.scopes,
            ...(intent.resource === undefined ? {} : { resource: intent.resource }),
            authorizationParams: intent.authorizationParams,
        });
    }
    catch (error) {
        consentUnavailable("upstream_unavailable", { step: "authorization_url" }, error);
        return;
    }
    const answered = await record({ decision: "accept", state, codeVerifier, nonce });
    if (answered === null)
        return;
    if (answered.outcome === "refused") {
        // A fault on this side, and nothing was thrown: the store names it.
        consentUnavailable("storage", {
            store: "federation_grant_intent",
            step: "answer_consent",
            refusal: answered.reason,
        });
        return;
    }
    if (answered.outcome !== "accepted") {
        jsonError(res, 400, "invalid_request", NO_PENDING);
        return;
    }
    // No transaction-store outage can reach this line: the redirect
    // upstream happens only once the transaction exists.
    res.redirect(303, upstream.href);
}
