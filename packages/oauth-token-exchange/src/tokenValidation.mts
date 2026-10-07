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
 * validator that cannot reach an answer is a `503`, never a verdict on the token;
 * one whose answer names a family or a session other than as a string is a failed
 * validation.
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
import { invalidRequest, isRefusal } from "./answers.mjs";
import type { TokenRequest } from "./tokenRequest.mjs";
import { snapshotValidated } from "./validatedSnapshot.mjs";
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
			readonly subjectBindings: ReportedBindings;
			readonly issuedConfirmation: Confirmation | undefined;
	  }
	| GrantHandlerResult
> {
	const subjectAnswer = await askValidator(deps, "subject", subjectToken, subjectValidator);
	if (isRefusal(subjectAnswer)) return subjectAnswer;
	const subjectValidated = subjectAnswer.validated;
	const subjectBindings = readBindings(subjectValidated);
	if (subjectBindings === undefined) return invalidRequest("subject_token validation failed");

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
	return { subjectValidated, subjectBindings, issuedConfirmation };
}

/** The actor token, when one was sent, validated and held to the sender constraint; else `null`. */
export async function validateActor(
	deps: Pick<GrantDependencies, "logger">,
	ctx: GrantContext,
	{ actorToken }: Pick<TokenRequest, "actorToken">,
	actorValidator: ExchangeTokenValidator | null | undefined,
): Promise<
	| {
			readonly actorValidated: ValidatedToken | null;
			/** The actor's bindings; `null` with no actor. */
			readonly actorBindings: ReportedBindings | null;
	  }
	| GrantHandlerResult
> {
	let actorValidated: ValidatedToken | null = null;
	let actorBindings: ReportedBindings | null = null;
	if (actorToken !== null && actorValidator) {
		const answer = await askValidator(deps, "actor", actorToken, actorValidator);
		if (isRefusal(answer)) return answer;
		actorValidated = answer.validated;
		const read = readBindings(actorValidated);
		if (read === undefined) return invalidRequest("actor_token validation failed");
		actorBindings = read;
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
	return { actorValidated, actorBindings };
}

/**
 * The presented token's validator asked again, answered as the first asking
 * was: `null` when it still accepts the token, else the same refusal or `503`.
 * Its answer gates only; the bindings and claims read at the first asking stay
 * the ones checked and minted.
 */
export async function revalidate(
	deps: Pick<GrantDependencies, "logger">,
	role: "subject" | "actor",
	token: string,
	validator: ExchangeTokenValidator,
): Promise<GrantHandlerResult | null> {
	const answer = await askValidator(deps, role, token, validator, gateOnly);
	return isRefusal(answer) ? answer : null;
}

/** A revalidation's reading of an answer: whether there is one, nothing of it read. */
const gateOnly = (answer: ValidatedToken): ValidatedToken | null => answer;

/**
 * The validator's answer for a presented token, as `read` takes it — by
 * default into the plain, frozen copy every later stage reads
 * (`snapshotValidated`) — or the refusal: `null`, or an answer that is no
 * answer, is a failed validation, and a throw (a keystore or revocation store
 * down; core's `ExchangeTokenValidator` contract), or a member of the answer
 * whose read throws, a logged `503`, never a verdict on the token.
 */
async function askValidator(
	deps: Pick<GrantDependencies, "logger">,
	role: "subject" | "actor",
	token: string,
	validator: ExchangeTokenValidator,
	read: (answer: ValidatedToken) => ValidatedToken | null = snapshotValidated,
): Promise<{ readonly validated: ValidatedToken } | GrantHandlerResult> {
	let validated: ValidatedToken | null;
	try {
		const answer = await validator.validate(token, { role });
		validated = answer ? read(answer) : null;
	} catch (err) {
		(deps.logger ?? consoleLogger).error(
			{ role, err: loggableError(err) },
			"token_exchange_validation_unavailable",
		);
		return {
			result: {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: `${role}_token validation store unavailable`,
			},
		};
	}
	return validated ? { validated } : invalidRequest(`${role}_token validation failed`);
}

/**
 * The family and the session a validator reports, each read once off its
 * answer: a non-empty string, or `undefined` for unset (an empty string
 * included, so no token inherits a `family_id: ""` that no revocation could
 * reach). The family rule, the session rule and issuance read these, never
 * the answer again.
 */
export interface ReportedBindings {
	readonly familyId: string | undefined;
	readonly sid: string | undefined;
}

/**
 * The answer's bindings, or `undefined` when either is present but not a
 * string. That is no answer: the stores key families and sessions by string,
 * and introspection and the session rule read any other claim as none, so the
 * check and the minted token would both miss it.
 */
function readBindings(validated: ValidatedToken): ReportedBindings | undefined {
	const { familyId, sid } = validated;
	if (familyId !== undefined && typeof familyId !== "string") return undefined;
	if (sid !== undefined && typeof sid !== "string") return undefined;
	return { familyId: familyId || undefined, sid: sid || undefined };
}
