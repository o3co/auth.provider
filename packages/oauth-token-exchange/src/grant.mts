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
 * token, the email gate over the subject under `oauth.requireEmailVerified`
 * (`emailVerification.mts`), and the policy hook.
 */

import type {
	ExchangeTokenValidator,
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
	checkOAuthTokenSettings,
	consoleLogger,
	logGrantPolicyUnavailable,
	loggableError,
	policyDenied,
	policyOutOfBounds,
	policyUnavailable,
	readGrantPolicyDecision,
} from "@o3co/auth-provider-core";
import { invalidRequest, isRefusal, tokenAnswer } from "./answers.mjs";
import { callerBindingRefusal } from "./callerBinding.mjs";
import { authenticateClient } from "./clientAuthentication.mjs";
import { delegationRefusal } from "./delegation.mjs";
import { emailGate } from "./emailVerification.mjs";
import { GRANT_TYPE } from "./grantType.mjs";
import { issueAccessToken } from "./issuance.mjs";
import { liveSessionSubject } from "./sessionLiveness.mjs";
import { issuedTarget, type RequestTargets, requestTargets } from "./targetCeilings.mjs";
import { readTokenRequest, type TokenRequest } from "./tokenRequest.mjs";
import {
	type ReportedBindings,
	resolveValidators,
	revalidate,
	validateActor,
	validateSubject,
} from "./tokenValidation.mjs";

/**
 * What the exchange reads: the shared grant slots it uses, the client repository,
 * core's validator resolver, and `userRepository` (read under
 * `oauth.requireEmailVerified` alone). The module's `ProviderDeps<R, O>` satisfies
 * every slot. Nothing is read of the whole configuration.
 */
export interface TokenExchangeDependencies
	extends Pick<
			GrantDependencies,
			"keyStore" | "logger" | "grantPolicy" | "refreshTokenFamilyRevocation" | "userSessionStore"
		>,
		ProviderDeps<"clientRepository", "sessionLifecycle" | "userRepository"> {
	readonly tokenExchangeValidatorResolver: Pick<TokenExchangeValidatorResolver, "get">;
	/**
	 * What the oauth module provides of `oauth {}`: the access-token lifetimes
	 * the grant mints within, and `requireEmailVerified`. Held to its contract
	 * here; that its lifetimes are within the ones core resolves from the
	 * configuration is the caller's to hold. Within `createApp`, boot holds every slot to them before any
	 * reader runs. A caller building the grant by hand, outside `createApp`,
	 * passes the value `checkOAuthTokenSettings(value, config)` answers.
	 */
	readonly oauthTokenSettings: OAuthTokenSettings;
	/**
	 * The module's own section, `oauth-token-exchange {}`: the deepest actor
	 * chain accepted before the current actor is added, 3 when unset.
	 */
	readonly section?: { readonly maxActorChainDepth?: number };
}

export function createTokenExchangeGrant(deps: TokenExchangeDependencies): GrantHandler {
	const { tokenExchangeValidatorResolver, clientRepository } = deps;
	if (deps.userSessionStore !== undefined && deps.sessionLifecycle === undefined) {
		throw new Error(
			"The token_exchange grant: userSessionStore is wired, but sessionLifecycle is not. " +
				"Where a user-session store is wired, core's session lifecycle is required: the " +
				"grant reads the liveness of a presented token's session through it. Install " +
				"sessionLifecycleModule from @o3co/auth-provider-core beside the session stores.",
		);
	}
	// The lifetimes are read once, when the grant is built, so a hand-built value
	// that breaks the contract fails the composition instead of every request after
	// client authentication. Checked whole, never member by member.
	const tokenSettings = checkOAuthTokenSettings(deps.oauthTokenSettings);
	const { defaultExpiresIn, maxExpiresIn } = tokenSettings.accessTokenLifetime;
	// Under `requireEmailVerified` the user behind the subject is read; a composition
	// that cannot read one fails here, before any request.
	const emailRefusal = emailGate(deps, tokenSettings.requireEmailVerified);

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
			// The issued token's `iat`, fixed before the presented tokens are validated,
			// so a subject revocation recorded after any watermark read here covers it.
			const issuedAt = Math.floor(Date.now() / 1000);
			const subject = await validateSubject(deps, ctx, request, validators.subjectValidator);
			if (isRefusal(subject)) return subject;
			const { subjectValidated, subjectBindings, issuedConfirmation } = subject;

			// The subject token must name the caller, unless its registration says
			// otherwise; a check of the claims alone, ahead of the store reads.
			const notForClient = callerBindingRefusal(deps, client, subjectValidated);
			if (notForClient) return notForClient;

			// After the sender-constraint matrices, so a cheap refusal still
			// short-circuits ahead of the store reads.
			const subjectStanding = await standingRefusal(
				deps,
				"subject",
				subjectValidated,
				subjectBindings,
			);
			if (subjectStanding) return subjectStanding;

			const actor = await validateActor(deps, ctx, request, validators.actorValidator);
			if (isRefusal(actor)) return actor;
			const { actorValidated, actorBindings } = actor;
			if (actorValidated && actorBindings) {
				// A revoked or logged-out actor credential must not be recorded in
				// `act` as a live delegation.
				const actorStanding = await standingRefusal(deps, "actor", actorValidated, actorBindings);
				if (actorStanding) return actorStanding;
			}
			const delegationRefused = delegationRefusal(deps, client, subjectValidated, actorValidated);
			if (delegationRefused) return delegationRefused;

			// The user the issued token names, once the presented tokens have passed
			// and before the policy is asked; the actor is not read.
			const unverified = await emailRefusal(subjectValidated.sub, client.clientId);
			if (unverified) return unverified;

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

			// The last check before minting: the token is minted only from presented
			// tokens that still pass after the policy.
			const presentedAgain = await presentedTokensRefusal(
				deps,
				request,
				validators,
				{ subjectValidated, subjectBindings },
				{ actorValidated, actorBindings },
			);
			if (presentedAgain) return presentedAgain;

			const issuedToken = await issueAccessToken(
				deps,
				ctx,
				{ defaultExpiresIn, maxExpiresIn },
				{
					issuedAt,
					client,
					subjectValidated,
					subjectBindings,
					actorValidated,
					grantedScope,
					audienceForToken,
					requestedExpiresIn,
					issuedConfirmation,
				},
			);
			if (isRefusal(issuedToken)) return issuedToken;

			return tokenAnswer(issuedToken.accessToken, issuedToken.expiresIn);
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
			// A copy: the subject token's audience is the ceiling the answer is held to.
			originalAudience: [...subjectAudienceSet],
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
				deps.logger,
				{ grantType: GRANT_TYPE, policy: deps.grantPolicy.kind },
				err,
			);
			return { result: policyUnavailable() };
		}
		// Core's reading: a decision that is neither allow nor deny is its 500.
		const reading = readGrantPolicyDecision(answer, deps.logger, {
			grantType: GRANT_TYPE,
			policy: deps.grantPolicy.kind,
		});
		if (reading.verdict === "invalid") return { result: reading.result };
		if (reading.verdict === "deny") {
			// Core's answer to a deny, as on every grant: a code that is not a
			// token-endpoint code is `invalid_request`, also RFC 8693 §2.2.2's code for
			// a request refused by policy.
			return {
				result: policyDenied(reading, deps.logger, {
					grantType: GRANT_TYPE,
					hook: deps.grantPolicy,
				}),
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
 * The presented tokens held again, at the end of the exchange, to what can change
 * while it runs: each token's validator (its denylist and watermark, when it
 * reads them), then its family and session rules over the bindings the first
 * validation read, which are the ones minted. In the first check's order, with
 * its refusals and outages; `null` when both tokens still pass.
 */
async function presentedTokensRefusal(
	deps: TokenExchangeDependencies,
	{ subjectToken, actorToken }: Pick<TokenRequest, "subjectToken" | "actorToken">,
	{
		subjectValidator,
		actorValidator,
	}: {
		readonly subjectValidator: ExchangeTokenValidator;
		readonly actorValidator: ExchangeTokenValidator | null | undefined;
	},
	subject: {
		readonly subjectValidated: ValidatedToken;
		readonly subjectBindings: ReportedBindings;
	},
	actor: {
		readonly actorValidated: ValidatedToken | null;
		readonly actorBindings: ReportedBindings | null;
	},
): Promise<GrantHandlerResult | null> {
	const subjectRefused =
		(await revalidate(deps, "subject", subjectToken, subjectValidator)) ??
		(await standingRefusal(deps, "subject", subject.subjectValidated, subject.subjectBindings));
	if (subjectRefused) return subjectRefused;
	const { actorValidated, actorBindings } = actor;
	if (actorToken === null || !actorValidator || !actorValidated || !actorBindings) return null;
	return (
		(await revalidate(deps, "actor", actorToken, actorValidator)) ??
		(await standingRefusal(deps, "actor", actorValidated, actorBindings))
	);
}

/**
 * A validated token's standing with this grant: the family rule, then the
 * session rule. The refusal, or `null` when the token passes both.
 */
async function standingRefusal(
	deps: Pick<
		TokenExchangeDependencies,
		"refreshTokenFamilyRevocation" | "sessionLifecycle" | "logger"
	>,
	role: "subject" | "actor",
	validated: ValidatedToken,
	bindings: ReportedBindings,
): Promise<GrantHandlerResult | null> {
	return (
		(await familyRefusal(deps, role, bindings)) ??
		(await sessionRefusal(deps, role, validated, bindings))
	);
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
	{ familyId }: ReportedBindings,
): Promise<GrantHandlerResult | null> {
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
 * - No `sid`, or no `sessionLifecycle` (a sessionless composition, which the
 *   grant's construction holds to wiring no `userSessionStore` either):
 *   nothing to check (introspection passes the token too).
 * - Otherwise the lifecycle's `liveness` decides, so a session closing or
 *   closed is refused from the closing commit on.
 * - No live session under the `sid`, or one for another subject:
 *   `session_invalid` (`actor_token session_invalid` for the actor), as
 *   `invalid_request`.
 * - A `liveness` that rejects, or an answer that is neither `live` nor
 *   `not_live`: `503 temporarily_unavailable`, logged once as
 *   `token_exchange_session_store_unavailable`; an outage is never read as an
 *   ended or a live session.
 */
async function sessionRefusal(
	deps: Pick<TokenExchangeDependencies, "sessionLifecycle" | "logger">,
	role: "subject" | "actor",
	validated: ValidatedToken,
	{ sid }: ReportedBindings,
): Promise<GrantHandlerResult | null> {
	const lifecycle = deps.sessionLifecycle;
	if (sid === undefined || lifecycle === undefined) return null;
	const outage = (where: Readonly<Record<string, unknown>>, err?: unknown): GrantHandlerResult => {
		const logger = deps.logger ?? consoleLogger;
		if (err === undefined) {
			logger.error({ ...where, role }, "token_exchange_session_store_unavailable");
		} else {
			logger.error(
				{ ...where, role, err: loggableError(err) },
				"token_exchange_session_store_unavailable",
			);
		}
		return {
			result: {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: forRole(role, "session store unavailable"),
			},
		};
	};
	// The session grant's rule: the session must be this token's subject's. A
	// token naming another subject's session is not tied to it, and that
	// session's liveness says nothing about this subject.
	const where = { store: "session_lifecycle", step: "liveness" };
	let session: Awaited<ReturnType<typeof liveSessionSubject>>;
	try {
		session = await liveSessionSubject(lifecycle, sid);
	} catch (err) {
		return outage(where, err);
	}
	if (session === "no_answer") return outage(where);
	if (session !== "not_live" && session.subject === validated.sub) return null;
	return invalidRequest(forRole(role, "session_invalid"));
}

/** A refusal's description for the token it refuses: the actor's carry the `actor_token ` prefix. */
function forRole(role: "subject" | "actor", description: string): string {
	return role === "actor" ? `actor_token ${description}` : description;
}

export { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";
export { GRANT_TYPE as TOKEN_EXCHANGE_GRANT_TYPE };
