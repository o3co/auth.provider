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
 * Who may act for the subject: an actor the subject token's `may_act` names, within
 * the deepest actor chain allowed; with no actor token, the calling client under the
 * same `may_act`, so omitting the actor cannot opt out of it. A refusal is
 * `invalid_request` with one warn line.
 */

import type {
	GrantDependencies,
	GrantHandlerResult,
	PublicClient,
	ValidatedToken,
} from "@o3co/auth-provider-core";
import { countActorChainDepth, matchesMayAct, matchesMayActClient } from "./act.mjs";
import { invalidRequest } from "./answers.mjs";

/** What delegation reads: the logger, and the module's section for the chain depth. */
type DelegationDependencies = Pick<GrantDependencies, "logger"> & {
	readonly section?: { readonly maxActorChainDepth?: number };
};

/** The delegation's refusal, or `null` when the actor, or the client, may act. */
export function delegationRefusal(
	deps: DelegationDependencies,
	client: PublicClient,
	subjectValidated: ValidatedToken,
	actorValidated: ValidatedToken | null,
): GrantHandlerResult | null {
	if (actorValidated) {
		const subjectMayAct = subjectValidated.claims.may_act;
		if (
			subjectMayAct !== undefined &&
			subjectMayAct !== null &&
			!matchesMayAct(actorValidated, subjectMayAct)
		) {
			deps.logger?.warn(
				{
					subject: subjectValidated.sub,
					actor: actorValidated.sub,
				},
				"token_exchange_may_act_violation",
			);
			return invalidRequest("may_act_violation: actor not authorized by subject token");
		}

		const maxActorChainDepth = getMaxActorChainDepth(deps);
		const currentActorChainDepth = countActorChainDepth(subjectValidated.act);
		if (currentActorChainDepth >= maxActorChainDepth) {
			deps.logger?.warn(
				{
					subject: subjectValidated.sub,
					actor: actorValidated.sub,
					currentActorChainDepth,
					maxActorChainDepth,
				},
				"token_exchange_actor_chain_too_deep",
			);
			return invalidRequest("actor_chain_too_deep: actor chain depth limit exceeded");
		}
	} else {
		// Impersonation: with no actor_token the party acting for the subject is the
		// calling client, and `may_act` (RFC 8693 §4.4) constrains exactly that party.
		// It applies whether or not an actor_token was sent, or omitting the parameter
		// would opt out of it. `matchesMayActClient` compares `sub` with the client id
		// and refuses any entry pinning `iss` (see its doc comment).
		const subjectMayAct = subjectValidated.claims.may_act;
		if (
			subjectMayAct !== undefined &&
			subjectMayAct !== null &&
			!matchesMayActClient(client.clientId, subjectMayAct)
		) {
			deps.logger?.warn(
				{
					subject: subjectValidated.sub,
					clientId: client.clientId,
				},
				"token_exchange_may_act_violation",
			);
			return invalidRequest("may_act_violation: client not authorized by subject token");
		}
	}
	return null;
}

function getMaxActorChainDepth(deps: DelegationDependencies): number {
	const maxActorChainDepth: unknown = deps.section?.maxActorChainDepth;
	return typeof maxActorChainDepth === "number" &&
		Number.isInteger(maxActorChainDepth) &&
		maxActorChainDepth > 0
		? maxActorChainDepth
		: 3;
}
