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
 * The presented tokens: each token type backed by a validator, the subject and the
 * actor validated, and each held to the sender constraint this request proves. A
 * validator that cannot reach an answer is a `503`, never a verdict on the token.
 */

import {
	type Confirmation,
	consoleLogger,
	type ExchangeTokenValidator,
	type GrantContext,
	type GrantDependencies,
	type GrantHandlerResult,
	loggableError,
	matchConfirmation,
	ownedConfirmation,
	type TokenExchangeValidatorResolver,
	type ValidatedToken,
} from "@o3co/auth-provider-core";
import { invalidRequest } from "./answers.mjs";
import type { TokenRequest } from "./tokenRequest.mjs";
import { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";

/** The validator for each presented token, and the issued token type, checked. */
export function resolveValidators(
	tokenExchangeValidatorResolver: Pick<TokenExchangeValidatorResolver, "get">,
	{
		subjectTokenType,
		actorToken,
		actorTokenType,
		requestedTokenType,
	}: Pick<
		TokenRequest,
		"subjectTokenType" | "actorToken" | "actorTokenType" | "requestedTokenType"
	>,
):
	| {
			readonly subjectValidator: ExchangeTokenValidator;
			readonly actorValidator: ExchangeTokenValidator | null | undefined;
	  }
	| GrantHandlerResult {
	if (requestedTokenType !== null && requestedTokenType !== ACCESS_TOKEN_TYPE) {
		return invalidRequest(`requested_token_type '${requestedTokenType}' is not supported`);
	}

	const subjectValidator = tokenExchangeValidatorResolver.get(subjectTokenType);
	if (!subjectValidator) {
		return invalidRequest(`subject_token_type '${subjectTokenType}' is not supported`);
	}

	// Reject actor_token_type without actor_token: a policy gating delegation on
	// `actorTokenType` must not be satisfied by the type alone.
	if (actorToken === null && actorTokenType !== null) {
		return invalidRequest("actor_token is required when actor_token_type is provided");
	}

	if (actorToken !== null && actorTokenType === null) {
		return invalidRequest("actor_token_type is required when actor_token is provided");
	}
	const actorValidator =
		actorToken !== null && actorTokenType !== null
			? tokenExchangeValidatorResolver.get(actorTokenType)
			: null;
	if (actorToken !== null && actorValidator === undefined) {
		return invalidRequest(`actor_token_type '${actorTokenType}' is not supported`);
	}
	return { subjectValidator, actorValidator };
}

/** The subject token, validated and held to the sender constraint; and what the issued token is bound to. */
export async function validateSubject(
	deps: Pick<GrantDependencies, "logger">,
	ctx: GrantContext,
	{ subjectToken }: Pick<TokenRequest, "subjectToken">,
	subjectValidator: ExchangeTokenValidator,
): Promise<
	| {
			readonly subjectValidated: ValidatedToken;
			readonly issuedConfirmation: Confirmation | undefined;
	  }
	| GrantHandlerResult
> {
	let subjectValidated: ValidatedToken | null;
	try {
		subjectValidated = await subjectValidator.validate(subjectToken, { role: "subject" });
	} catch (err) {
		// A validator throws only when it cannot reach an answer (a keystore or
		// revocation store down; core's `ExchangeTokenValidator` contract): a logged 503,
		// never a verdict on the token.
		(deps.logger ?? consoleLogger).error(
			{ role: "subject", err: loggableError(err) },
			"token_exchange_validation_unavailable",
		);
		return {
			result: {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "subject_token validation store unavailable",
			},
		};
	}
	if (!subjectValidated) return invalidRequest("subject_token validation failed");

	// Sender constraint (RFC 9449 §5, RFC 8705 §4) through core's
	// `matchConfirmation`, as the refresh grant does. Without it a stolen DPoP- or
	// mTLS-bound subject_token could be exchanged for an unbound token.
	//
	//   subject cnf | presented binding | outcome
	//   no          | no                | plain Bearer
	//   no          | yes               | bound to the presented key
	//   yes         | no                | invalid_request
	//   yes         | yes, differs      | invalid_request
	//   yes         | yes, equal        | bound (preserved)
	//
	// The same over `cnf.jkt` (DPoP) and `cnf["x5t#S256"]` (mTLS). Checked before
	// policy, store I/O and signing so a refusal is cheap. `invalid_request`, not
	// `invalid_dpop_proof`: the proof is fine, the subject_token is unacceptable
	// (RFC 8693 §2.2.2). A request carries one binding, so a subject and an actor
	// bound to different keys cannot both be satisfied and are refused.
	const match = matchConfirmation(subjectValidated.claims.cnf, ctx.tokenBinding);

	if (match.status === "compound") {
		// This AS stamps one mechanism's confirmation per token, so a compound cnf is
		// forged or a bug: refused, as the refresh grant and introspection do.
		return invalidRequest("subject_token has compound cnf binding which is not supported");
	}
	if (match.status === "no-proof") {
		return invalidRequest(
			match.member === "jkt"
				? "subject_token requires a DPoP proof"
				: "subject_token requires a client certificate",
		);
	}
	if (match.status === "mismatch") {
		return invalidRequest(
			match.member === "jkt"
				? "DPoP proof does not match subject_token binding"
				: "client certificate does not match subject_token binding",
		);
	}

	// The issued token is bound to what this request proved. For a bound subject that
	// equals its `cnf` (matched above); an unbound subject exchanged with a proof
	// yields a bound token, which cannot help an attacker already holding a bearer
	// token.
	const issuedConfirmation = ownedConfirmation(ctx.tokenBinding);
	return { subjectValidated, issuedConfirmation };
}

/** The actor token, when one was sent, validated and held to the sender constraint; else `null`. */
export async function validateActor(
	deps: Pick<GrantDependencies, "logger">,
	ctx: GrantContext,
	{ actorToken }: Pick<TokenRequest, "actorToken">,
	actorValidator: ExchangeTokenValidator | null | undefined,
): Promise<{ readonly actorValidated: ValidatedToken | null } | GrantHandlerResult> {
	let actorValidated: ValidatedToken | null = null;
	if (actorToken !== null && actorValidator) {
		try {
			actorValidated = await actorValidator.validate(actorToken, { role: "actor" });
		} catch (err) {
			(deps.logger ?? consoleLogger).error(
				{ role: "actor", err: loggableError(err) },
				"token_exchange_validation_unavailable",
			);
			return {
				result: {
					status: 503,
					error: "temporarily_unavailable",
					errorDescription: "actor_token validation store unavailable",
				},
			};
		}
		if (!actorValidated) return invalidRequest("actor_token validation failed");
	}

	// The actor is held to the same sender-constraint rule: `buildActClaim` records
	// the actor in the issued token's `act` claim (RFC 8693 §4.1), so an unproven
	// bound actor_token would let a thief forge the delegation chain. With one
	// binding per request (an mTLS client's certificate is `ctx.tokenBinding`
	// itself), delegation between a differently bound actor and subject fails
	// closed; supporting it would need several proofs per request, for which RFC 9449
	// has no token-endpoint precedent. Runs right after actor validation (a `cnf`
	// cannot be read from an unverified token), ahead of the actor's family check,
	// `may_act`, the policy and signing.
	if (actorValidated) {
		const actorMatch = matchConfirmation(actorValidated.claims.cnf, ctx.tokenBinding);
		if (actorMatch.status === "compound") {
			return invalidRequest("actor_token has compound cnf binding which is not supported");
		}
		if (actorMatch.status === "no-proof") {
			return invalidRequest(
				actorMatch.member === "jkt"
					? "actor_token requires a DPoP proof"
					: "actor_token requires a client certificate",
			);
		}
		if (actorMatch.status === "mismatch") {
			return invalidRequest(
				actorMatch.member === "jkt"
					? "DPoP proof does not match actor_token binding"
					: "client certificate does not match actor_token binding",
			);
		}
	}
	return { actorValidated };
}

/**
 * The family a validator reports, or `undefined`. An empty `familyId` is absent
 * for the family rule and issuance alike, so no token inherits a `family_id: ""`
 * that no revocation could reach.
 */
export function reportedFamily(validated: ValidatedToken): string | undefined {
	return validated.familyId ? validated.familyId : undefined;
}
