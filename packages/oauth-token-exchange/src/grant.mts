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
 * The RFC 8693 token-exchange grant: client authentication, the subject and
 * actor token rules (sender constraint, refresh-token family, session,
 * `may_act`), the scope, audience and resource ceilings, the policy hook, and
 * issuance.
 */

import type {
	GrantContext,
	GrantDependencies,
	GrantHandler,
	GrantHandlerResult,
	GrantPolicyContext,
	GrantPolicyDecision,
	GrantPolicyRequest,
	OAuthTokenSettings,
	ProviderDeps,
	TokenExchangeValidatorResolver,
	ValidatedToken,
} from "@o3co/auth-provider-core";
import {
	auditErrorList,
	auditErrorText,
	checkOAuthTokenSettings,
	consoleLogger,
	formatObject,
	generateToken,
	isWellFormedErrorCode,
	LIVENESS_SID_CLAIM,
	logGrantPolicyUnavailable,
	loggableError,
	matchConfirmation,
	ownedConfirmation,
	policyOutOfBounds,
	readIssuedScope,
	readSpaceDelimitedParameter,
	readTargetParameter,
	resolveAccessTokenLifetime,
} from "@o3co/auth-provider-core";
import { buildActClaim, countActorChainDepth, matchesMayAct, matchesMayActClient } from "./act.mjs";
import { invalidRequest, isRefusal, tokenAnswer } from "./answers.mjs";
import { authenticateClient } from "./clientAuthentication.mjs";
import { GRANT_TYPE } from "./grantType.mjs";
import { readTokenRequest } from "./tokenRequest.mjs";
import { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";

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
			const {
				body,
				subjectToken,
				subjectTokenType,
				requestedExpiresIn,
				actorToken,
				actorTokenType,
				requestedTokenType,
			} = request;

			const authenticated = await authenticateClient(deps, clientRepository, ctx, request);
			if (isRefusal(authenticated)) return authenticated;
			const { client } = authenticated;

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
				return invalidRequest(
					"subject_token has compound cnf binding which is not supported (Stage 1)",
				);
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

			// The refresh-token family rule — this grant's, not the validator's;
			// see `familyRefusal`. After the matrices above, so a cheap refusal
			// still short-circuits ahead of the store read.
			const subjectFamilyRefusal = await familyRefusal(deps, "subject", subjectValidated);
			if (subjectFamilyRefusal) return subjectFamilyRefusal;
			// The session rule, beside it: see `sessionRefusal`.
			const subjectSessionRefusal = await sessionRefusal(deps, "subject", subjectValidated);
			if (subjectSessionRefusal) return subjectSessionRefusal;

			let actorValidated: typeof subjectValidated | null = null;
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
					return invalidRequest(
						"actor_token has compound cnf binding which is not supported (Stage 1)",
					);
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

				// The subject's family rule, applied to the actor: a revoked actor credential
				// must not be recorded in `act` as a live delegation.
				const actorFamilyRefusal = await familyRefusal(deps, "actor", actorValidated);
				if (actorFamilyRefusal) return actorFamilyRefusal;
				// And the session rule: an actor whose session a logout ended is
				// not a live delegation either.
				const actorSessionRefusal = await sessionRefusal(deps, "actor", actorValidated);
				if (actorSessionRefusal) return actorSessionRefusal;

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

			// Scope: requested ⊆ subject scope ∩ client.allowedScopes. The registration is a
			// ceiling on every grant, so a client registered for `read` holding a subject
			// token with `admin` must not receive `admin`. Absent or empty `allowedScopes`
			// means no scope at all (deny by absence); a scope-less deployment still mints,
			// without a `scope` claim. Unlike the sibling grants, an omitted `scope`
			// inherits the subject's scope instead of reading `defaultScopes` (see
			// `grantedScope` below).
			//
			// RFC 6749 §3.3, two readings: the subject's scope never widens
			// (`readIssuedScope`: a legacy `read<TAB>write` names no scope), and the
			// request's is strict (malformed is refused; a repeated parameter is refused
			// rather than read as omitted, which would inherit the subject's whole scope).
			const subjectScope = readIssuedScope(subjectValidated.scope);
			const subjectScopeSet = new Set(subjectScope);
			const clientScopeSet = new Set(client.allowedScopes ?? []);
			if (body.scope !== undefined && body.scope !== null && typeof body.scope !== "string") {
				return invalidRequest("scope must be a space-delimited string");
			}
			const requestedScopeRaw =
				typeof body.scope === "string" ? readSpaceDelimitedParameter(body.scope) : [];
			if (requestedScopeRaw === null) {
				return {
					result: {
						status: 400,
						error: "invalid_scope",
						errorDescription: "scope is not a space-delimited list of scope-tokens",
					},
				};
			}
			// Normalize empty to null — `scope=""` and `scope=" "` behave the same
			// as scope omitted (inherit subject scope), as a target parameter
			// that names nothing does below (RFC 6749 §3.2).
			const requestedScope = requestedScopeRaw.length === 0 ? null : requestedScopeRaw;
			if (requestedScope) {
				for (const s of requestedScope) {
					if (!subjectScopeSet.has(s)) {
						return {
							result: {
								status: 400,
								error: "invalid_scope",
								errorDescription: `scope '${s}' is not in subject_token scope`,
							},
						};
					}
					// Named explicitly, so refused rather than dropped: a narrower token would
					// answer a different request than the one submitted.
					if (!clientScopeSet.has(s)) {
						return {
							result: {
								status: 400,
								error: "invalid_scope",
								errorDescription: `scope '${s}' is not allowed for this client`,
							},
						};
					}
				}
			}

			// The audience ceilings: the client's registration (`allowedAudiences` plus its
			// own id) and the subject token's audience (its client id when it names none).
			// The request is held to both before the policy runs, so its refusal is its own;
			// a policy's `grantedAudience` is held to the same two below.
			const clientAudienceSet = new Set([...(client.allowedAudiences ?? []), client.clientId]);
			const subjectAudienceSet = new Set(
				subjectAudienceBoundary(subjectValidated.aud, client.clientId),
			);
			// Targets are read by core's `readTargetParameter`. A value that is neither a
			// string nor an array of strings is refused, never converted
			// (`String([["billing"]])` is `"billing"`): `invalid_target` for `resource` (RFC
			// 8707 §2) and, by symmetry, `audience`. A target naming nothing is omitted (RFC
			// 6749 §3.2).
			const audienceValues = readTargetParameter(body.audience);
			if (audienceValues === null) {
				return {
					result: {
						status: 400,
						error: "invalid_target",
						errorDescription: "audience must be a string or an array of strings",
					},
				};
			}
			const resourceValues = readTargetParameter(body.resource);
			if (resourceValues === null) {
				return {
					result: {
						status: 400,
						error: "invalid_target",
						errorDescription: "resource must be a string or an array of strings",
					},
				};
			}
			const requestedAudience = audienceValues.length > 0 ? audienceValues : null;
			const requestedResource = resourceValues.length > 0 ? resourceValues : null;
			if (requestedAudience) {
				for (const aud of requestedAudience) {
					if (!clientAudienceSet.has(aud)) {
						return {
							result: {
								status: 400,
								error: "invalid_target",
								errorDescription: `audience '${aud}' is not allowed for this client`,
							},
						};
					}
				}
				// An audience the client is registered for but the subject token does not carry:
				// `invalid_target` (RFC 8693 §2.2.2). De-duplicated, since `audience` may repeat.
				const widenedAudiences = [
					...new Set(requestedAudience.filter((audience) => !subjectAudienceSet.has(audience))),
				];
				if (widenedAudiences.length > 0) {
					deps.logger?.warn(
						{
							subject: subjectValidated.sub,
							clientId: client.clientId,
							widenedAudiences,
						},
						"token_exchange_audience_widening_rejected",
					);
					return {
						result: {
							status: 400,
							error: "invalid_target",
							errorDescription: `audience_widening_not_allowed: ${widenedAudiences.join(" ")}`,
						},
					};
				}
			}
			// A requested `resource` must equal the issued audience (RFC 8707, checked again
			// after the policy), which is the client id or an audience both the registration
			// and the subject token carry. A resource outside that set can never be
			// represented, so it is the request's own `invalid_target`, answered before a
			// policy could turn it into a policy-ceiling 500. Absent a policy, this names the
			// same resources the later check would.
			if (requestedResource) {
				const unrepresentable = requestedResource.some(
					(resource) =>
						resource !== client.clientId &&
						!(clientAudienceSet.has(resource) && subjectAudienceSet.has(resource)),
				);
				if (unrepresentable) {
					const requestAudience = issuedAudience(
						requestedAudience ?? undefined,
						subjectValidated.aud,
						clientAudienceSet,
						client.clientId,
					);
					const missingResources = requestedResource.filter(
						(resource) => resource !== requestAudience,
					);
					deps.logger?.warn(
						{
							subject: subjectValidated.sub,
							clientId: client.clientId,
							audienceForToken: requestAudience,
							...loggedResources(missingResources),
						},
						"token_exchange_resource_not_in_audience",
					);
					return {
						result: {
							status: 400,
							error: "invalid_target",
							errorDescription: `requested_resources_not_in_audience: ${missingResources.join(" ")}`,
						},
					};
				}
			}

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
				let decision: GrantPolicyDecision;
				try {
					decision = await deps.grantPolicy.evaluate(policyRequest, policyContext);
				} catch (err) {
					logGrantPolicyUnavailable(
						deps.logger,
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
				if (decision.outcome === "deny") {
					// RFC 6749 §5.2 makes `error` 1*NQSCHAR: a malformed policy code is logged
					// (sanitised) and replaced by `invalid_request`, RFC 8693 §2.2.2's code for a
					// request refused by policy. `/oauth/token` checks too; this covers a
					// composition dispatching the handler from its own route.
					let error = decision.error;
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
					const description = decision.errorDescription;
					return {
						result: {
							status: error === "access_denied" ? 403 : 400,
							error,
							errorDescription:
								(typeof description === "string" && description) || "denied by policy",
						},
					};
				}
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

			const audienceForToken = issuedAudience(
				grantedAudience,
				subjectValidated.aud,
				clientAudienceSet,
				client.clientId,
			);

			if (requestedResource && requestedResource.length > 0) {
				const missingResources = requestedResource.filter(
					(resource) => resource !== audienceForToken,
				);
				if (missingResources.length > 0) {
					deps.logger?.warn(
						{
							subject: subjectValidated.sub,
							clientId: client.clientId,
							audienceForToken,
							...loggedResources(missingResources),
						},
						"token_exchange_resource_not_in_audience",
					);
					return {
						result: {
							status: 400,
							error: "invalid_target",
							errorDescription: `requested_resources_not_in_audience: ${missingResources.join(" ")}`,
						},
					};
				}
			}

			const act = buildActClaim({
				subject: subjectValidated,
				actor: actorValidated ?? undefined,
			});
			const scopeClaim = grantedScope && grantedScope.length > 0 ? grantedScope.join(" ") : null;

			// The issued lifetime: the requested `expires_in` or
			// `oauth.accessToken.defaultExpiresIn`, clamped (not refused) to `maxExpiresIn`,
			// then capped at the subject token's remaining lifetime below. An unset max
			// equals the default. The max also bounds how long a resource server validating
			// offline keeps accepting this token after its family is revoked.
			let expiresIn = Math.min(requestedExpiresIn ?? defaultExpiresIn, maxExpiresIn);

			// RFC 8693 §2.2.1: the issued token SHOULD NOT outlive the subject token, or a
			// chain of exchanges outlives its origin indefinitely. The built-in validator
			// already rejects an expired subject, so this is the fail-closed backstop for
			// contributed validators, placed here so the refusal order of a doubly invalid
			// request is unchanged. The issuance instant is read once for both the cap and
			// the minted `iat`/`exp`, so they cannot straddle a second and exceed the
			// subject's `exp`.
			const issuedAt = Math.floor(Date.now() / 1000);
			const subjectExpiry = subjectValidated.claims.exp;
			if (typeof subjectExpiry === "number" && Number.isFinite(subjectExpiry)) {
				const remaining = Math.floor(subjectExpiry - issuedAt);
				// `<= 0` includes a token expiring within this second: capping would mint a dead
				// token, so refuse instead.
				if (remaining <= 0) return invalidRequest("subject_token has expired");
				expiresIn = Math.min(expiresIn, remaining);
			}
			// A subject token without `exp` leaves the lifetime above standing: `exp` is a
			// property of the presented credential, and a validator returning none asserts a
			// credential with no expiry. The built-in validator never takes this path.

			const accessToken = await generateToken(
				formatObject({
					family_id: reportedFamily(subjectValidated),
					// The subject's session as a liveness link only (core's
					// `grants/sessionClaims.mts`): the logout that ends the subject token ends this
					// one at introspection and userinfo, and nothing a `sid` authorises is reachable
					// with it. The actor's session is not carried.
					[LIVENESS_SID_CLAIM]: subjectValidated.sid ? subjectValidated.sid : undefined,
					act,
				}),
				{
					expiresIn,
					issuedAt,
					keyStore: deps.keyStore,
					issuer: ctx.issuer,
					audience: audienceForToken,
					subject: subjectValidated.sub,
					authorizedParty: client.clientId,
					scope: scopeClaim,
					tokenType: "at+jwt",
					...(issuedConfirmation ? { confirmation: issuedConfirmation } : {}),
				},
			);

			return tokenAnswer(accessToken);
		},
	};
}

function getMaxActorChainDepth(deps: TokenExchangeDependencies): number {
	const maxActorChainDepth: unknown = deps.section?.maxActorChainDepth;
	return typeof maxActorChainDepth === "number" &&
		Number.isInteger(maxActorChainDepth) &&
		maxActorChainDepth > 0
		? maxActorChainDepth
		: 3;
}

/**
 * The family a validator reports, or `undefined`. An empty `familyId` is absent
 * for the family rule and issuance alike, so no token inherits a `family_id: ""`
 * that no revocation could reach.
 */
function reportedFamily(validated: ValidatedToken): string | undefined {
	return validated.familyId ? validated.familyId : undefined;
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
	const forRole = (description: string) =>
		role === "actor" ? `actor_token ${description}` : description;
	const revocation = deps.refreshTokenFamilyRevocation;
	if (!revocation) {
		return invalidRequest(
			forRole("refresh token family revocation not configured (revocation cannot be verified)"),
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
				errorDescription: forRole("refresh token store unavailable"),
			},
		};
	}
	if (!revoked) return null;
	return invalidRequest(forRole("family_revoked"));
}

/**
 * The requested resources a refusal logs: the first ten through core's
 * `auditErrorList` (sanitised, 200 characters each), plus `missingResourceCount`
 * when it had to cut. They are caller-controlled, so neither their content nor
 * their count may reach the log unbounded.
 */
const loggedResources = (
	resources: readonly string[],
): { readonly missingResources: string[]; readonly missingResourceCount?: number } => {
	const missingResources = auditErrorList(resources);
	return missingResources.length < resources.length
		? { missingResources, missingResourceCount: resources.length }
		: { missingResources };
};

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
	const forRole = (description: string) =>
		role === "actor" ? `actor_token ${description}` : description;
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
				errorDescription: forRole("session store unavailable"),
			},
		};
	}
	if (live) return null;
	return invalidRequest(forRole("session_invalid"));
}

/**
 * The single audience an exchanged token is minted for:
 * - an explicit audience (request or policy, already bounded): its first entry;
 * - omitted, with a single subject audience the client is registered for: that;
 * - otherwise the client's own id, so omitting `audience` cannot mint for an
 *   audience outside the client's allowlist.
 *
 * `generateToken` carries one audience, so only the first `grantedAudience` entry
 * is used; several audiences would need introspection by every party.
 */
function issuedAudience(
	grantedAudience: readonly string[] | undefined,
	subjectAud: ValidatedToken["aud"],
	clientAudienceSet: ReadonlySet<string>,
	clientId: string,
): string {
	if (grantedAudience && grantedAudience.length > 0) return grantedAudience[0] ?? clientId; // `?? clientId` is forward-compat for noUncheckedIndexedAccess
	const single =
		typeof subjectAud === "string"
			? subjectAud
			: Array.isArray(subjectAud) && subjectAud.length === 1
				? subjectAud[0]
				: undefined;
	if (typeof single === "string" && clientAudienceSet.has(single)) return single;
	return clientId;
}

function subjectAudienceBoundary(
	audience: ValidatedToken["aud"],
	clientId: string,
): readonly string[] {
	if (typeof audience === "string" && audience.length > 0) return [audience];
	if (Array.isArray(audience)) {
		const values = audience.filter(
			(value): value is string => typeof value === "string" && value.length > 0,
		);
		return values.length > 0 ? values : [clientId];
	}
	return [clientId];
}

export { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";
export { GRANT_TYPE as TOKEN_EXCHANGE_GRANT_TYPE };
