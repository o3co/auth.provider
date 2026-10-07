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
import { invalidRequest } from "./answers.mjs";
/**
 * The refusal, or `null` when the subject token names the client or the
 * registration lets the client exchange tokens issued to others. Reads the
 * validator's answer: its `aud`, and `azp` from its claims. A `client_id` claim
 * is not read: this provider stamps one only beside an `azp` of the same value.
 */
export function callerBindingRefusal(deps, client, subjectValidated) {
    if (presentableBy(client, subjectValidated))
        return null;
    deps.logger?.warn({ subject: subjectValidated.sub, clientId: client.clientId }, "token_exchange_subject_not_for_client");
    return invalidRequest("subject_token azp and aud do not name this client");
}
/**
 * The actor token's refusal on the subject token's terms, or `null` when the
 * actor token names the client or the registration lets the client exchange
 * tokens issued to others.
 */
export function actorCallerBindingRefusal(deps, client, subjectValidated, actorValidated) {
    if (presentableBy(client, actorValidated))
        return null;
    deps.logger?.warn({ subject: subjectValidated.sub, actor: actorValidated.sub, clientId: client.clientId }, "token_exchange_actor_not_for_client");
    return invalidRequest("actor_token azp and aud do not name this client");
}
function presentableBy(client, validated) {
    return (client.allowExchangeOfTokensIssuedToOthers === true || namesClient(validated, client.clientId));
}
function namesClient({ aud, claims }, clientId) {
    if (claims.azp === clientId)
        return true;
    if (typeof aud === "string")
        return aud === clientId;
    return Array.isArray(aud) && aud.includes(clientId);
}
