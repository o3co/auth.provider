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
import { countActorChainDepth, matchesMayAct, matchesMayActClient } from "./act.mjs";
import { invalidRequest } from "./answers.mjs";
import { actorCallerBindingRefusal } from "./callerBinding.mjs";
/** The delegation's refusal, or `null` when the actor, or the client, may act. */
export function delegationRefusal(deps, client, subjectValidated, actorValidated) {
    if (actorValidated) {
        // The actor token is held to the caller binding the subject token passed: a
        // `may_act` naming the actor says who may act, not which client may present it.
        const notForClient = actorCallerBindingRefusal(deps, client, subjectValidated, actorValidated);
        if (notForClient)
            return notForClient;
        const subjectMayAct = subjectValidated.claims.may_act;
        if (subjectMayAct !== undefined &&
            subjectMayAct !== null &&
            !matchesMayAct(actorValidated, subjectMayAct)) {
            deps.logger?.warn({
                subject: subjectValidated.sub,
                actor: actorValidated.sub,
            }, "token_exchange_may_act_violation");
            return invalidRequest("may_act_violation: actor not authorized by subject token");
        }
        const maxActorChainDepth = getMaxActorChainDepth(deps);
        const currentActorChainDepth = countActorChainDepth(subjectValidated.act);
        if (currentActorChainDepth >= maxActorChainDepth) {
            deps.logger?.warn({
                subject: subjectValidated.sub,
                actor: actorValidated.sub,
                currentActorChainDepth,
                maxActorChainDepth,
            }, "token_exchange_actor_chain_too_deep");
            return invalidRequest("actor_chain_too_deep: actor chain depth limit exceeded");
        }
    }
    else {
        // Impersonation: with no actor_token the party acting for the subject is the
        // calling client, and `may_act` (RFC 8693 §4.4) constrains exactly that party.
        // It applies whether or not an actor_token was sent, or omitting the parameter
        // would opt out of it. `matchesMayActClient` compares `sub` with the client id
        // and refuses any entry pinning `iss` (see its doc comment).
        const subjectMayAct = subjectValidated.claims.may_act;
        if (subjectMayAct !== undefined &&
            subjectMayAct !== null &&
            !matchesMayActClient(client.clientId, subjectMayAct)) {
            deps.logger?.warn({
                subject: subjectValidated.sub,
                clientId: client.clientId,
            }, "token_exchange_may_act_violation");
            return invalidRequest("may_act_violation: client not authorized by subject token");
        }
    }
    return null;
}
function getMaxActorChainDepth(deps) {
    const maxActorChainDepth = deps.section?.maxActorChainDepth;
    return typeof maxActorChainDepth === "number" &&
        Number.isInteger(maxActorChainDepth) &&
        maxActorChainDepth > 0
        ? maxActorChainDepth
        : 3;
}
