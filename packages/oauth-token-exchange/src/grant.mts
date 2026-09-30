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
 * The RFC 8693 token-exchange grant: builds the handler, which runs the stages in
 * order and answers the first refusal. It holds what the grant asks the deployment
 * itself: the refresh-token family rule and the session rule over each validated
 * token, and the policy hook.
 */

import type {
	GrantContext,
	GrantDependencies,
	GrantHandler,
	GrantHandlerResult,
	GrantPolicyContext,
	GrantPolicyRequest,
	OAuthTokenSettings,
	ProviderDeps,
	PublicClient,
	TokenExchangeValidatorResolver,
	ValidatedToken,
} from "@o3co/auth-provider-core";
import {
	auditErrorText,
	checkOAuthTokenSettings,
	consoleLogger,
	isWellFormedErrorCode,
	logGrantPolicyUnavailable,
	loggableError,
	policyOutOfBounds,
	readGrantPolicyDecision,
	resolveAccessTokenLifetime,
} from "@o3co/auth-provider-core";
import { invalidRequest, isRefusal, tokenAnswer } from "./answers.mjs";
import { authenticateClient } from "./clientAuthentication.mjs";
import { delegationRefusal } from "./delegation.mjs";
import { GRANT_TYPE } from "./grantType.mjs";
import { issueAccessToken } from "./issuance.mjs";
import { issuedTarget, type RequestTargets, requestTargets } from "./targetCeilings.mjs";
import { readTokenRequest, type TokenRequest } from "./tokenRequest.mjs";
import {
	reportedFamily,
	resolveValidators,
	validateActor,
	validateSubject,
} from "./tokenValidation.mjs";

/**
 * What the exchange reads: the shared grant slots it uses, the client repository,
 * and core's validator resolver. The module's `ProviderDeps<R, O>` satisfies
 * every slot.
 */
export interface TokenExchangeDependencies
	extends Pick<
			GrantDependencies,
			| "config"
			| "keyStore"
			| "logger"
			| "grantPolicy"
			| "refreshTokenFamilyRevocation"
			| "userSessionStore"
		>,
		ProviderDeps<"clientRepository"> {
	readonly tokenExchangeValidatorResolver: Pick<TokenExchangeValidatorResolver, "get">;
	/** What the oauth module provides of `oauth {}`; the configuration is read when absent. */
	readonly oauthTokenSettings?: OAuthTokenSettings;
	/**
	 * The module's own section, `oauth-token-exchange {}`: the deepest actor
	 * chain accepted before the current actor is added, 3 when unset. Without
	 * it, a configuration still setting `oauth.tokenExchange` is refused.
	 */
	readonly section?: { readonly maxActorChainDepth?: number };
}

export function createTokenExchangeGrant(deps: TokenExchangeDependencies): GrantHandler {
	const { tokenExchangeValidatorResolver, clientRepository } = deps;
	// Fail closed: a bound written at the old path, read as unset, would widen
	// the actor chain to the default.
	if (
		deps.section === undefined &&
		(deps.config as { oauth?: { tokenExchange?: unknown } }).oauth?.tokenExchange !== undefined
	) {
		throw new RangeError(
			"createTokenExchangeGrant: oauth.tokenExchange has moved to oauth-token-exchange; " +
				"hand maxActorChainDepth as section.maxActorChainDepth " +
				"(oauth-token-exchange.maxActorChainDepth), and remove oauth.tokenExchange.",
		);
	}
	// The lifetimes are read once, when the grant is built, so a hand-built
	// configuration the resolver refuses fails the composition instead of every
	// request after client authentication. The oauth module's settings when present
	// (checked whole), else the configuration through core's reader.
	const { defaultExpiresIn, maxExpiresIn } =
		deps.oauthTokenSettings === undefined
			? resolveAccessTokenLifetime(deps.config)
			: checkOAuthTokenSettings(deps.oauthTokenSettings, deps.config).accessTokenLifetime;

	return {
		// Deny by absence: token exchange mints a fresh credential from one the client
		// already holds, a standing capability of a registration, so a registration
		// without `allowedGrantTypes` must not acquire it while
		// `oauth.requireGrantTypeAllowlist` defaults off. Dispatch enforces this; client
		// authentication's in-handler check covers standalone wiring, where no dispatch
		// rule runs.
		requiresExplicitGrantAllowlist: true,
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const request = readTokenRequest(ctx);
			if (isRefusal(request)) return request;
			const { body, requestedExpiresIn } = request;

			const authenticated = await authenticateClient(deps, clientRepository, ctx, request);
			if (isRefusal(authenticated)) return authenticated;
			const { client } = authenticated;

			const validators = resolveValidators(tokenExchangeValidatorResolver, request);
			if (isRefusal(validators)) return validators;
			const subject = await validateSubject(deps, ctx, request, validators.subjectValidator);
			if (isRefusal(subject)) return subject;
			const { subjectValidated, issuedConfirmation } = subject;

			// The refresh-token family rule — this grant's, not the validator's;
			// see `familyRefusal`. After the sender-constraint matrices, so a cheap
			// refusal still short-circuits ahead of the store read.
			const subjectFamilyRefusal = await familyRefusal(deps, "subject", subjectValidated);
			if (subjectFamilyRefusal) return subjectFamilyRefusal;
			// The session rule, beside it: see `sessionRefusal`.
			const subjectSessionRefusal = await sessionRefusal(deps, "subject", subjectValidated);
			if (subjectSessionRefusal) return subjectSessionRefusal;

			const actor = await validateActor(deps, ctx, request, validators.actorValidator);
			if (isRefusal(actor)) return actor;
			const { actorValidated } = actor;
			if (actorValidated) {
				// The subject's family rule, applied to the actor: a revoked actor credential
				// must not be recorded in `act` as a live delegation.
				const actorFamilyRefusal = await familyRefusal(deps, "actor", actorValidated);
				if (actorFamilyRefusal) return actorFamilyRefusal;
				// And the session rule: an actor whose session a logout ended is
				// not a live delegation either.
				const actorSessionRefusal = await sessionRefusal(deps, "actor", actorValidated);
				if (actorSessionRefusal) return actorSessionRefusal;
			}
			const delegationRefused = delegationRefusal(deps, client, subjectValidated, actorValidated);
			if (delegationRefused) return delegationRefused;

			const targets = requestTargets(deps, body, client, subjectValidated);
			if (isRefusal(targets)) return targets;

			const granted = await applyGrantPolicy(
				deps,
				ctx,
				client,
				request,
				subjectValidated,
				actorValidated,
				targets,
			);
			if (isRefusal(granted)) return granted;
			const { grantedScope, grantedAudience } = granted;

			const issued = issuedTarget(deps, client, subjectValidated, targets, grantedAudience);
			if (isRefusal(issued)) return issued;
			const { audienceForToken } = issued;

			const issuedToken = await issueAccessToken(
				deps,
				ctx,
				{ defaultExpiresIn, maxExpiresIn },
				{
					client,
					subjectValidated,
					actorValidated,
					grantedScope,
					audienceForToken,
					requestedExpiresIn,
					issuedConfirmation,
				},
			);
			if (isRefusal(issuedToken)) return issuedToken;

			return tokenAnswer(issuedToken.accessToken);
		},
	};
}

/**
 * The policy hook: the deployment's grant policy, asked with the request as narrowed
 * so far, may deny it or narrow its scope and audience, never widen them past the
 * subject token's and the client's ceilings.
 */
async function applyGrantPolicy(
	deps: TokenExchangeDependencies,
	ctx: GrantContext,
	client: PublicClient,
	{ subjectTokenType, actorTokenType }: Pick<TokenRequest, "subjectTokenType" | "actorTokenType">,
	subjectValidated: ValidatedToken,
	actorValidated: ValidatedToken | null,
	{
		subjectScope,
		subjectScopeSet,
		clientScopeSet,
		requestedScope,
		clientAudienceSet,
		subjectAudienceSet,
		requestedAudience,
		requestedResource,
	}: RequestTargets,
): Promise<
	| {
			readonly grantedScope: readonly string[] | undefined;
			readonly grantedAudience: readonly string[] | undefined;
	  }
	| GrantHandlerResult
> {
	// Policy hook: `grantedScope`/`grantedAudience` start as the request's narrowed
	// values and the policy may narrow them further. An omitted `scope` inherits the
	// subject token's scope clamped to `allowedScopes` (RFC 8693 §2.1). The sibling
	// grants instead use `defaultScopes` and refuse when none are declared, so that
	// "no scope" cannot mean "the whole allowlist"; here the subject token is already
	// an authorized upper bound, so inheritance cannot over-grant, and narrowing
	// rather than refusing keeps a subject token wider than the client exchangeable
	// for less.
	let grantedScope: readonly string[] | undefined =
		requestedScope ?? subjectScope.filter((s) => clientScopeSet.has(s));
	let grantedAudience: readonly string[] | undefined = requestedAudience ?? undefined;
	if (deps.grantPolicy) {
		const policyRequest: GrantPolicyRequest = {
			grantType: GRANT_TYPE,
			clientId: client.clientId,
			subject: subjectValidated.sub,
			requestedScope: requestedScope ?? undefined,
			requestedAudience: requestedAudience ?? undefined,
			originalScope: subjectScope.length > 0 ? subjectScope : undefined,
			subjectTokenType,
			// Only when an actor_token was validated, so a type header alone cannot satisfy
			// a policy gating on it.
			actorTokenType:
				actorValidated !== null && actorTokenType !== null ? actorTokenType : undefined,
			resource: requestedResource ?? undefined,
		};
		const policyContext: GrantPolicyContext = {
			ip: ctx.ip,
			userAgent: ctx.userAgent,
			issuer: ctx.issuer ?? "",
		};
		let answer: unknown;
		try {
			answer = await deps.grantPolicy.evaluate(policyRequest, policyContext);
		} catch (err) {
			logGrantPolicyUnavailable(
				deps.logger ?? consoleLogger,
				{ grantType: GRANT_TYPE, policy: deps.grantPolicy.kind },
				err,
			);
			return {
				result: {
					status: 503,
					error: "temporarily_unavailable",
					errorDescription: "grant policy evaluation failed",
				},
			};
		}
		// Core's reading: a decision that is neither allow nor deny is its 500.
		const reading = readGrantPolicyDecision(answer, deps.logger ?? consoleLogger, {
			grantType: GRANT_TYPE,
			policy: deps.grantPolicy.kind,
		});
		if (reading.verdict === "invalid") return { result: reading.result };
		if (reading.verdict === "deny") {
			// RFC 6749 §5.2 makes `error` 1*NQSCHAR: a malformed policy code is logged
			// (sanitised) and replaced by `invalid_request`, RFC 8693 §2.2.2's code for a
			// request refused by policy. `/oauth/token` checks too; this covers a
			// composition dispatching the handler from its own route.
			let error = reading.decision.error;
			if (!isWellFormedErrorCode(error)) {
				deps.logger?.warn(
					{ error: auditErrorText(String(error)) },
					"token_exchange_policy_deny_error_malformed",
				);
				error = "invalid_request";
			}
			// A JavaScript policy can return anything as its description; one
			// that is empty or not a string is not sent — RFC 6749 A.8 makes
			// the field 1*NQSCHAR — and the default is.
			const description = reading.decision.errorDescription;
			// `400` whatever the code (RFC 6749 §5.2), as core's
			// `evaluateGrantPolicy` answers the other grants' deny.
			return {
				result: {
					status: 400,
					error,
					errorDescription: (typeof description === "string" && description) || "denied by policy",
				},
			};
		}
		const { decision } = reading;
		// Presence, not truthiness, and it must be an array (a JS policy returning a
		// string would throw at `.filter`). The policy may narrow, never widen: its scope
		// must lie within the subject's scope AND the client's `allowedScopes`, else
		// core's `policyOutOfBounds` (500: the deployment's policy exceeded its
		// authority, not the caller). An empty `grantedScope` strips every scope.
		if (decision.grantedScope !== undefined) {
			if (!Array.isArray(decision.grantedScope)) {
				return { result: policyOutOfBounds("policy returned a non-array grantedScope") };
			}
			const widenedScopes = decision.grantedScope.filter(
				(scope) => !subjectScopeSet.has(scope) || !clientScopeSet.has(scope),
			);
			if (widenedScopes.length > 0) {
				deps.logger?.warn(
					{ subject: subjectValidated.sub, clientId: client.clientId, widenedScopes },
					"token_exchange_policy_scope_refused",
				);
				return {
					result: policyOutOfBounds(
						`policy returned scopes exceeding the subject_token scope or client allowedScopes: ${widenedScopes.join(" ")}`,
					),
				};
			}
			grantedScope = decision.grantedScope;
		}
		// The audience likewise, as core's `boundPolicyAudience` does for other grants,
		// with the subject token's audience as a second bound. An empty
		// `grantedAudience` is no decision: the request's audience stands.
		if (decision.grantedAudience !== undefined) {
			if (!Array.isArray(decision.grantedAudience)) {
				return { result: policyOutOfBounds("policy returned a non-array grantedAudience") };
			}
			const widenedAudiences = decision.grantedAudience.filter(
				(audience) => !subjectAudienceSet.has(audience) || !clientAudienceSet.has(audience),
			);
			if (widenedAudiences.length > 0) {
				deps.logger?.warn(
					{ subject: subjectValidated.sub, clientId: client.clientId, widenedAudiences },
					"token_exchange_policy_audience_refused",
				);
				return {
					result: policyOutOfBounds(
						`policy returned audiences outside the subject_token audience or client allowedAudiences: ${widenedAudiences.join(" ")}`,
					),
				};
			}
			if (decision.grantedAudience.length > 0) grantedAudience = decision.grantedAudience;
		}
	}
	return { grantedScope, grantedAudience };
}

/**
 * The refresh-token family rule for a `subject_token` or `actor_token`: the
 * refusal, or `null` when the token passes. This grant owns it (the built-in
 * validator does not read `refreshTokenFamilyRevocation`), so a revoked family
 * gets its own description, `family_revoked`, telling the client to
 * re-authenticate rather than retry. It keys on the `familyId` a validator
 * reports, whatever token type the validator is registered for.
 *
 * - A family with no `refreshTokenFamilyRevocation` wired: refused (fail
 *   closed), since its revocation could never be observed.
 * - The store throws: `503 temporarily_unavailable`, logged as
 *   `token_exchange_family_store_unavailable`; an outage is never reported as a
 *   revoked token.
 * - Revoked: `family_revoked`.
 *
 * Refusals are `invalid_request` (RFC 8693 §2.2.2); the actor's carry the
 * `actor_token ` prefix.
 */
async function familyRefusal(
	deps: Pick<TokenExchangeDependencies, "refreshTokenFamilyRevocation" | "logger">,
	role: "subject" | "actor",
	validated: ValidatedToken,
): Promise<GrantHandlerResult | null> {
	const familyId = reportedFamily(validated);
	if (familyId === undefined) return null;
	const revocation = deps.refreshTokenFamilyRevocation;
	if (!revocation) {
		return invalidRequest(
			forRole(
				role,
				"refresh token family revocation not configured (revocation cannot be verified)",
			),
		);
	}
	let revoked: boolean;
	try {
		revoked = await revocation.isFamilyRevoked(familyId);
	} catch (err) {
		// Log the projection only: an ioredis reply error carries the command, the
		// family's key included.
		(deps.logger ?? consoleLogger).error(
			{ store: "refresh_token_family", role, err: loggableError(err) },
			"token_exchange_family_store_unavailable",
		);
		return {
			result: {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: forRole(role, "refresh token store unavailable"),
			},
		};
	}
	if (!revoked) return null;
	return invalidRequest(forRole(role, "family_revoked"));
}

/**
 * The session rule for a `subject_token` or `actor_token`: the refusal, or `null`
 * when the token passes. A token minted from a browser session carries its `sid`
 * and dies with the session at introspection, userinfo and refresh; this applies
 * the same rule, keyed on the validator's `ValidatedToken.sid` (never
 * `claims.sid`, which a foreign issuer's token may carry).
 *
 * - No `sid`, or no `userSessionStore`: nothing to check (introspection passes
 *   the token too).
 * - No session under the `sid`, or one for another subject: `session_invalid`
 *   (`actor_token session_invalid` for the actor), as `invalid_request`.
 * - The store throws: `503 temporarily_unavailable`, logged once as
 *   `token_exchange_session_store_unavailable`; an outage is never read as an
 *   ended or a live session.
 */
async function sessionRefusal(
	deps: Pick<TokenExchangeDependencies, "userSessionStore" | "logger">,
	role: "subject" | "actor",
	validated: ValidatedToken,
): Promise<GrantHandlerResult | null> {
	const sid = validated.sid ? validated.sid : undefined;
	const store = deps.userSessionStore;
	if (sid === undefined || store === undefined) return null;
	let live: boolean;
	try {
		// The session grant's rule: the record must be this token's
		// subject's. A token naming another subject's session is not tied to
		// it, and that session's liveness says nothing about this subject.
		live = (await store.get(sid))?.sub === validated.sub;
	} catch (err) {
		(deps.logger ?? consoleLogger).error(
			{ store: "user_session", step: "get", role, err: loggableError(err) },
			"token_exchange_session_store_unavailable",
		);
		return {
			result: {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: forRole(role, "session store unavailable"),
			},
		};
	}
	if (live) return null;
	return invalidRequest(forRole(role, "session_invalid"));
}

/** A refusal's description for the token it refuses: the actor's carry the `actor_token ` prefix. */
function forRole(role: "subject" | "actor", description: string): string {
	return role === "actor" ? `actor_token ${description}` : description;
}

export { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";
export { GRANT_TYPE as TOKEN_EXCHANGE_GRANT_TYPE };
