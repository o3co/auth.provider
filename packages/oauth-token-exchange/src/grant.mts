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

import type {
	GrantContext,
	GrantDependencies,
	GrantHandler,
	GrantHandlerResult,
	GrantPolicyContext,
	GrantPolicyDecision,
	GrantPolicyRequest,
	ProviderDeps,
	PublicClient,
	TokenExchangeValidatorResolver,
	ValidatedToken,
} from "@o3co/auth-provider-core";
import {
	auditErrorText,
	formatObject,
	generateToken,
	generateTokenResponse,
	isGrantTypeAllowed,
	isWellFormedClientId,
	isWellFormedErrorCode,
	logClientRepositoryUnavailable,
	logGrantPolicyUnavailable,
	loggableError,
	matchConfirmation,
	ownedConfirmation,
	policyOutOfBounds,
	readIssuedScope,
	readSpaceDelimitedParameter,
	resolveAccessTokenLifetime,
} from "@o3co/auth-provider-core";
import { buildActClaim, countActorChainDepth, matchesMayAct, matchesMayActClient } from "./act.mjs";
import { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";

const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

/**
 * What the exchange reads (#626 P2): the shared grant slots it uses, the
 * client repository, and the validator resolver core hands back — whose
 * `get` answers with the contract this grant consumes, since #626 P1 moved
 * that contract into core. The module's `ProviderDeps<R, O>` satisfies every
 * slot, with no cast left between them.
 */
export interface TokenExchangeDependencies
	extends Pick<
			GrantDependencies,
			"config" | "keyStore" | "logger" | "grantPolicy" | "refreshTokenFamilyRevocation"
		>,
		ProviderDeps<"clientRepository"> {
	readonly tokenExchangeValidatorResolver: Pick<TokenExchangeValidatorResolver, "get">;
}

export function createTokenExchangeGrant(deps: TokenExchangeDependencies): GrantHandler {
	const { tokenExchangeValidatorResolver, clientRepository } = deps;
	// The lifetimes it mints with, read once, when the grant is built: a
	// configuration built by hand that the resolver refuses is a composition
	// fault, refused before any request — read per request, it answered every
	// exchange with a 500, after client authentication had spent whatever it
	// spends.
	const { defaultExpiresIn, maxExpiresIn } = resolveAccessTokenLifetime(deps.config);

	return {
		// #326 deny-by-absence, the shape `client_credentials` and the WebAuthn
		// grant already declare. Token exchange mints a fresh credential out of
		// one a client already holds — a standing capability of a registration,
		// never a per-user ceremony — so a registration that predates this
		// grant, or simply omits `allowedGrantTypes`, must not acquire it by
		// omission while `oauth.requireGrantTypeAllowlist` defaults off.
		// Dispatch enforces this before `handle` runs; the in-handler copy
		// below covers the standalone wiring this package documents, where no
		// dispatch rule runs at all.
		requiresExplicitGrantAllowlist: true,
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const body = ctx.body as Record<string, unknown>;
			const subjectToken = typeof body.subject_token === "string" ? body.subject_token : null;
			const subjectTokenType =
				typeof body.subject_token_type === "string" ? body.subject_token_type : null;
			// D-6 Codex post-review: when this grant runs through `/oauth/token`,
			// Basic-authenticated callers don't repeat `client_id` in the body —
			// the authenticated identity is the canonical source. We resolve the
			// effective client id from the body first (matching standalone-wiring
			// callers) and fall back to `ctx.authenticatedClient.clientId`.
			//
			// Treat "present but not a single string" (e.g. `string[]` produced
			// by a repeated query parameter) as malformed instead of silently
			// falling back — otherwise an attacker could include a bogus
			// `client_id` array to bypass the cross-client equality check below.
			const bodyClientIdRaw = body.client_id;
			let bodyClientId: string | null;
			if (bodyClientIdRaw === undefined || bodyClientIdRaw === null) {
				bodyClientId = null;
			} else if (typeof bodyClientIdRaw === "string") {
				bodyClientId = bodyClientIdRaw;
			} else {
				return invalidRequest("client_id must be a single string value");
			}
			const clientId = bodyClientId ?? ctx.authenticatedClient?.clientId ?? null;
			const clientSecretRaw = body.client_secret;
			let clientSecret: string | null;
			if (clientSecretRaw === undefined || clientSecretRaw === null) {
				// Token Exchange currently supports confidential clients only — the
				// core ClientRepository contract requires `clientSecret` (see
				// packages/core/src/repositories/types.mts) and PublicClient is
				// `Omit<Client, "clientSecret">`, so findById alone cannot
				// distinguish "no secret configured" from "secret omitted by
				// caller". Accepting an unauthenticated client_id here would let an
				// attacker exchange a stolen subject_token under any client's
				// allowlist. Refuse outright; revisit when a Client.public flag
				// lands.
				clientSecret = null;
			} else if (typeof clientSecretRaw === "string") {
				clientSecret = clientSecretRaw;
			} else {
				// Present but not a string (e.g., repeated param producing string[]).
				// Refuse to treat this as "omitted" — that path would bypass the
				// confidential-client auth check.
				return invalidRequest("client_secret must be a single string value");
			}
			// The lifetime the client asks for, in seconds. RFC 8693 defines no
			// such parameter and RFC 6749 §3.2 has a server ignore one it does
			// not know, so this is additive: a client that never sends it — or
			// sends it without a value (§3.2) — gets the configured default,
			// exactly as before. It is refused, not
			// ignored, when present and malformed, for the reason `client_id`
			// above is — a value the caller sent and this grant silently
			// reinterpreted would answer a different request than the one made.
			// Honoured below as `min(requested ?? default, max, subject
			// remaining)`.
			const requestedExpiresIn = parseRequestedExpiresIn(body.expires_in);
			if (requestedExpiresIn === MALFORMED) {
				return invalidRequest(
					"expires_in must be sent once, as a positive whole number of seconds in ASCII digits",
				);
			}
			const actorToken = typeof body.actor_token === "string" ? body.actor_token : null;
			const actorTokenType =
				typeof body.actor_token_type === "string" ? body.actor_token_type : null;
			const requestedTokenType =
				typeof body.requested_token_type === "string" ? body.requested_token_type : null;

			if (!subjectToken || !subjectTokenType || !clientId) {
				return invalidRequest("subject_token, subject_token_type, client_id are required");
			}

			// Client authentication. Token Exchange supports confidential clients
			// only — public (`"none"`) clients are refused regardless of route.
			//
			// D-6 (v0.5.1): when this grant is dispatched from the standard
			// `/token` route, `clientAuthMw` has already authenticated the client
			// (via Basic header OR body credentials) and populated
			// `ctx.authenticatedClient`. We trust that identity over the body —
			// without this branch, Basic-authenticated callers would fail here
			// because `body.client_secret` is empty when credentials travel in
			// the `Authorization` header. For consumers wiring this grant onto a
			// custom route that bypasses `clientAuthMw`, the `else` branch keeps
			// the original body-credential gate as the sole authenticity check.
			let client: PublicClient | null;
			if (ctx.authenticatedClient) {
				if (ctx.authenticatedClient.tokenEndpointAuthMethod === "none") {
					return {
						result: {
							status: 401,
							error: "invalid_client",
							errorDescription: "Token Exchange does not support public clients",
						},
					};
				}
				// Body-supplied client_id MUST match the authenticated identity —
				// otherwise an attacker could authenticate as A and request a
				// token exchange under B's allowlist. Standard Basic-authenticated
				// callers omit body `client_id` entirely; only verify equality
				// when the body explicitly supplied one (`bodyClientId !== null`).
				if (bodyClientId !== null && bodyClientId !== ctx.authenticatedClient.clientId) {
					return invalidRequest("client_id does not match authenticated client");
				}
				try {
					client = await clientRepository.findById(ctx.authenticatedClient.clientId);
				} catch (err) {
					logClientRepositoryUnavailable(
						deps.logger,
						{ site: "token_exchange", step: "find", clientId: ctx.authenticatedClient.clientId },
						err,
					);
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "client repository unavailable",
						},
					};
				}
			} else {
				// Standalone wiring: no `clientAuthMw` ahead of us, so verify
				// the body-supplied secret directly. Repository failures are
				// surfaced as a controlled 503 to match the authenticated-client
				// branch — without this guard, a transient repository outage
				// would propagate as an unhandled 500.
				if (clientSecret === null) {
					return {
						result: {
							status: 401,
							error: "invalid_client",
							errorDescription: "client_secret is required",
						},
					};
				}
				// A client_id no client can have is refused as the client's, and
				// never handed to the repository: a repository that throws is an
				// outage (503), and one may throw on it — a SQL driver refusing a
				// NUL byte (core's `isWellFormedClientId`).
				if (!isWellFormedClientId(clientId)) {
					return {
						result: {
							status: 401,
							error: "invalid_client",
							errorDescription: "client authentication failed",
						},
					};
				}
				try {
					client = await clientRepository.authenticate(clientId, clientSecret);
				} catch (err) {
					logClientRepositoryUnavailable(
						deps.logger,
						{ site: "token_exchange", step: "authenticate", clientId },
						err,
					);
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "client repository unavailable",
						},
					};
				}
			}
			if (!client) {
				return {
					result: {
						status: 401,
						error: "invalid_client",
						errorDescription: "client authentication failed",
					},
				};
			}

			// #326, the in-handler half of `requiresExplicitGrantAllowlist`
			// declared above. Not a redundant second copy of the rule: the
			// dispatch check reads `ctx.authenticatedClient` and skips when it
			// is null, and this grant documents a standalone wiring (no
			// `clientAuthMw`) where it IS null and the client was authenticated
			// from body credentials a few lines up. Without this the strict
			// declaration would be decorative on exactly the path that has no
			// route-level gate at all.
			//
			// The rule itself is core's — `isGrantTypeAllowed` with
			// `requireAllowlist`, the same call dispatch makes — rather than a
			// hand-rolled comparison, and the wire shape is dispatch's, byte for
			// byte: both of dispatch's allowlist checks answer `client is not
			// authorized for grant_type '<type>'`, so a caller cannot tell which
			// gate refused it (the README's note 15).
			if (!isGrantTypeAllowed(client.allowedGrantTypes, GRANT_TYPE, { requireAllowlist: true })) {
				deps.logger?.warn(
					{ clientId: client.clientId, grantType: GRANT_TYPE },
					"token_exchange_grant_type_not_allowed",
				);
				return {
					result: {
						status: 400,
						error: "unauthorized_client",
						errorDescription: `client is not authorized for grant_type '${GRANT_TYPE}'`,
					},
				};
			}

			if (requestedTokenType !== null && requestedTokenType !== ACCESS_TOKEN_TYPE) {
				return invalidRequest(`requested_token_type '${requestedTokenType}' is not supported`);
			}

			const subjectValidator = tokenExchangeValidatorResolver.get(subjectTokenType);
			if (!subjectValidator) {
				return invalidRequest(`subject_token_type '${subjectTokenType}' is not supported`);
			}

			// Actor token type lookup — kept here so the validator reference is
			// available for validation below without a second registry call.

			// Reject actor_token_type without actor_token — prevents policies that
			// gate on req.actorTokenType for delegation from being bypassed by a
			// caller who only sets the type header.
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
				// A validator throws only when it cannot reach an answer — a
				// keystore or a revocation store down (core's
				// `ExchangeTokenValidator` contract). The server's fault, so a
				// logged 503, never a verdict on the token.
				deps.logger?.error(
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

			// RFC 9449 §5 / RFC 8705 §4 sender-constraint matrices — core's
			// `matchConfirmation` (#324), the same implementation the refresh
			// grant consumes; this grant keeps only the row → refusal mapping
			// below. Without the matrices the exchange grant was a de-binding
			// laundry: a stolen DPoP- or mTLS-bound
			// `subject_token` was accepted with no proof-of-possession and the
			// issued token dropped the binding, so an attacker converted a
			// token that was useless without the key into an ordinary bearer
			// token for their own client (#265).
			//
			// DPoP matrix:
			//   subject cnf.jkt | proof JKT       | Outcome
			//   no              | no              | issue plain Bearer (legacy)
			//   no              | yes             | issue DPoP-bound AT (opt-in upgrade)
			//   yes             | no              | reject invalid_request
			//   yes             | yes, differs    | reject invalid_request (multi-key attack)
			//   yes             | yes, equal      | issue DPoP-bound AT (binding preserved)
			//
			// mTLS matrix: identical over `cnf["x5t#S256"]` and the presented
			// client certificate.
			//
			// Evaluated here — after subject validation, before policy
			// evaluation, store I/O and the keystore signature — so a rejection
			// short-circuits ahead of the expensive work, the same ordering
			// rationale the refresh grant states.
			//
			// `invalid_request` rather than `invalid_dpop_proof`: the proof or
			// certificate is well-formed; it is the subject_token that is
			// unacceptable, which RFC 8693 §2.2.2 answers `invalid_request` (see
			// `invalidRequest`). The refresh path answers the same rows
			// `invalid_grant`, RFC 6749 §5.2's code for a refresh token.
			//
			// `actor_token` is held to this same matrix further down (#309). A
			// request carries exactly one `ctx.tokenBinding` — one DPoP proof,
			// one client certificate — so a subject and an actor bound to
			// *different* keys cannot both be satisfied; that shape is refused
			// rather than waved through, and the multi-proof extension it would
			// need has no RFC 9449 token-endpoint precedent.
			// Each cnf member is compared only against a binding whose `kind`
			// owns it — see `core/grants/confirmationMatch.mts` for the
			// kind-boundary and thumbprint-timing rationale.
			const match = matchConfirmation(subjectValidated.claims.cnf, ctx.tokenBinding);

			if (match.status === "compound") {
				// This AS emits exactly one mechanism's confirmation per token, so
				// a compound cnf is a forged token or an AS bug. Refuse rather
				// than pick a winner — the stance the refresh grant and the
				// introspection handler already take.
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

			// The confirmation stamped onto the issued token. When the subject was
			// bound this is the same value it carried — the matrices above have
			// already established that the presented material matches — so
			// "preserve" and "rebind to what was proven" are the same claim, and
			// taking it from the presented binding keeps the token bound to
			// material this request actually proved possession of.
			//
			// Row 2 of each matrix rides on the same expression: an unbound
			// subject exchanged with a proof yields a bound token. That cannot
			// help an attacker — a stolen *unbound* subject token was already a
			// usable bearer credential — and it takes the issued token out of
			// bearer replay for everyone else.
			const issuedConfirmation = ownedConfirmation(ctx.tokenBinding);

			// The refresh-token family rule — this grant's, not the validator's;
			// see `familyRefusal`. After the matrices above, so a cheap refusal
			// still short-circuits ahead of the store read.
			const subjectFamilyRefusal = await familyRefusal(deps, "subject", subjectValidated);
			if (subjectFamilyRefusal) return subjectFamilyRefusal;

			let actorValidated: typeof subjectValidated | null = null;
			if (actorToken !== null && actorValidator) {
				try {
					actorValidated = await actorValidator.validate(actorToken, { role: "actor" });
				} catch (err) {
					deps.logger?.error(
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

			// #309: the actor half of the matrices above, and the residual #265
			// named. `buildActClaim` folds the actor's identity into the issued
			// token's `act` claim (RFC 8693 §4.1), so an `actor_token` accepted
			// with no proof-of-possession let a stolen bound token forge the
			// delegation chain the issued token records — the same laundering
			// #265 closed for the subject, one parameter over.
			//
			// The rule is the subject's, applied to the actor: match the
			// presented binding or be refused. It is the strictest rule that is
			// physically expressible here. `AuthenticatedClient` carries no
			// certificate thumbprint of its own — for an mTLS-authenticated
			// client the certificate IS `ctx.tokenBinding` — so there is no
			// second credential an actor's `cnf` could be checked against, and
			// a request carries exactly one binding.
			//
			// The cost is stated rather than worked around: delegation where the
			// actor and the subject are bound to **different** keys can no longer
			// be exchanged. It never could be satisfied — one proof cannot answer
			// two keys — so what changes is that it now fails closed instead of
			// silently skipping the actor's binding. Supporting it needs more
			// than one proof per request, which RFC 9449 has no token-endpoint
			// precedent for; #309 keeps that as the future path rather than
			// approximating it with a rule that enforces nothing.
			//
			// Placed as early as the check can be: it needs the actor's claims,
			// so it runs immediately after actor validation and ahead of the
			// actor's family check, `may_act`, the policy hook and the keystore
			// signature. It is not ahead of *all* store I/O — validating the
			// subject and the actor already consulted the revocation stores, and
			// the subject's family was checked above — because a `cnf` cannot be
			// read out of a token that has not been verified yet.
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

				// The subject's family rule, applied to the actor: the actor's
				// identity is folded into the issued token's `act` claim, so a
				// revoked actor credential must not be recorded as a live
				// delegation any more than a revoked subject may be exchanged.
				const actorFamilyRefusal = await familyRefusal(deps, "actor", actorValidated);
				if (actorFamilyRefusal) return actorFamilyRefusal;

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
				// Impersonation — no `actor_token`, so the party acting on the
				// subject's behalf is the authenticated calling client itself,
				// and `may_act` (RFC 8693 §4.4) is exactly a statement about who
				// that party may be.
				//
				// Consulting the claim only when an `actor_token` happened to be
				// supplied made a subject-declared constraint opt-out: a client
				// that simply omitted the parameter was never held to it, so a
				// token naming `{"sub":"svc-a"}` as its only permitted actor was
				// exchangeable by any exchange-enabled client that got hold of
				// it. The claim says who may act; it does not say "only when
				// they bring a token to prove it".
				//
				// `matchesMayActClient` rather than `matchesMayAct`: the latter
				// takes a `ValidatedToken` and compares `iss` against that
				// token's issuer, and there is no actor token here to have one.
				// Rather than fabricate a `ValidatedToken` that lies about its
				// claims, the narrower matcher compares `sub` against the client
				// id and refuses any entry that pins `iss` — see its doc comment
				// for why an inferred issuer would be the permissive guess.
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

			// Scope narrowing: requested scope ⊆ subject scope ∩ client.allowedScopes.
			//
			// Two ceilings, not one. The subject token's scope bounds what this
			// exchange may carry forward; the calling client's registration
			// bounds what that client may ever hold, on any grant. Only the
			// first was enforced here, so a client registered for `read` that
			// got hold of a subject token carrying `admin` exchanged it and
			// received `admin` — its own registration was not a boundary at all,
			// while `client_credentials`, jwt-bearer and `/authorize` all treat
			// `allowedScopes` as exactly that.
			//
			// Absent and empty `allowedScopes` mean the same thing here, and
			// they mean deny: a registration that names no scope may receive
			// none. That is the #363/#396 shape — reading absence as
			// "unrestricted" is precisely the over-grant #396 removed from the
			// scope-omitting path in the sibling grants, and it would leave the
			// hole above open for every registration that never filled the
			// field in. A scope-less deployment is unaffected: there is nothing
			// to over-grant, the exchange still mints a token, it simply carries
			// no `scope` claim.
			//
			// Note the axis: this is the `allowedScopes` CEILING, where the
			// sibling grants do agree with this one. The omitted-`scope`
			// DEFAULT is where they part company — they read `defaultScopes`,
			// this grant inherits the subject token's scope. See the note at
			// the `grantedScope` assignment below.
			//
			// RFC 6749 §3.3, two readings. The subject's scope is a validated
			// token's record, read so it never widens (`readIssuedScope`): a legacy
			// `read<TAB>write` entry named no scope and must not supply `write`
			// to a request or to an inheriting exchange now. The request's
			// is the client's, read strictly: a value that is not a space-delimited
			// list of scope-tokens is refused as malformed, and a repeated
			// parameter (an array) is refused rather than read as omitted, which
			// would inherit the subject's whole scope.
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
			// as scope omitted (inherit subject scope), per the same rationale that
			// drives normalizeArrayParam for audience/resource.
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
					// Named explicitly, so refuse rather than silently drop it:
					// the caller asked for a scope its registration does not
					// carry, and answering with a narrower token would answer a
					// different request than the one submitted. Same
					// `invalid_scope` + offending-value shape as the check above
					// and as the audience allowlist below.
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

			// The audience ceilings: what the client is registered for
			// (`allowedAudiences` plus its own id) and what the subject token
			// carries (its client id when it names none). The request's audience
			// is held to both here, before the policy runs, so its answer is the
			// request's alone — no policy decision can turn it into anything
			// else. A policy's `grantedAudience` is held to the same two below.
			const clientAudienceSet = new Set([...(client.allowedAudiences ?? []), client.clientId]);
			const subjectAudienceSet = new Set(
				subjectAudienceBoundary(subjectValidated.aud, client.clientId),
			);
			const requestedAudience = normalizeArrayParam(body.audience);
			const requestedResource = normalizeArrayParam(body.resource);
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
				// An audience the client is registered for but the subject token
				// does not carry. RFC 8693 §2.2.2: "If the authorization server is
				// unwilling or unable to issue a token for any target service
				// indicated by the resource or audience parameters, the
				// invalid_target error code SHOULD be used".
				const widenedAudiences = requestedAudience.filter(
					(audience) => !subjectAudienceSet.has(audience),
				);
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
			// A requested `resource` must equal the issued audience (RFC 8707,
			// checked after the policy below), and that audience is the client id
			// or one the registration and the subject token both carry. A resource
			// outside that set can never be represented, so it is the request's
			// own `invalid_target`, answered here before the policy runs — the
			// same reason the audience is: a policy that turned it into its
			// granted audience would otherwise meet the policy ceiling first and
			// convert the caller's 400 into a 500.
			//
			// The refusal names what the check after the policy names: every
			// requested resource the issued audience would not equal. That
			// audience is taken as the request's own, which is what the later
			// check uses unless a policy replaces it — so without such a policy
			// the two list the same resources.
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
							missingResources,
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

			// Policy hook — existing GrantPolicyHook contract.
			// grantedScope/grantedAudience start as the narrowed values from the
			// request validation phase above; the policy hook may further override them.
			// An omitted `scope` inherits the SUBJECT TOKEN's scope, clamped to
			// the client's registration.
			//
			// This is deliberately not what the sibling grants do, and an earlier
			// version of this comment claimed a symmetry with them that does not
			// exist. `/authorize` (`routes/authorize.mts`), `client_credentials`
			// (`grants/clientCredentials.mts` `resolveScope`), jwt-bearer and the
			// device grant all resolve an omitted `scope` from the client's
			// declared `defaultScopes`, and all refuse with `invalid_scope` when
			// the client declares none against a non-empty allowlist — #396's
			// deny-by-absence, which exists because "forgot to send `scope`" used
			// to mean "grant the entire allowlist". This grant reads
			// `defaultScopes` nowhere and refuses nothing on that axis.
			//
			// Inheritance is the right default HERE because the request already
			// carries a ceiling. RFC 8693 §2.1 gives an omitted `scope` the same
			// scope as the subject token, and unlike the sibling grants this one
			// is handed a token whose scope is an explicit, already-authorized
			// upper bound — there is no unbounded "maximum grant" to fall into,
			// so the failure #396 closed cannot arise. Narrowing rather than
			// refusing for the same reason: the caller named nothing to be
			// refused, and refusing would make a subject token merely wider than
			// this client unexchangeable rather than exchangeable for less. The
			// clamp to `allowedScopes` is what keeps the client's own
			// registration a boundary.
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
					// actorTokenType is populated only when an actor_token was actually
					// validated — prevents policies that gate on actorTokenType from being
					// deceived by a request that supplied only the type header.
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
					// RFC 6749 §5.2 makes `error` 1*NQSCHAR. The policy's code goes
					// out as given when it is one; otherwise the refusal is
					// `invalid_request` — §2.2.2's code for a request refused by
					// policy — and the code is logged, sanitised, for the operator
					// who wrote the policy. `/oauth/token` checks every grant's code
					// too; this covers a composition that dispatches the handler
					// from its own route.
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
				// #521: presence, not truthiness, and an array — a JS policy returning
				// a string would reach `.filter` below and throw out of the handler.
				//
				// The policy may narrow, never widen, and its decision is held to
				// the exchange's ceilings before it replaces the request's value, so
				// a refusal here is the policy's alone: the deployment's policy
				// exceeding its authority, which every other grant answers with
				// core's `policyOutOfBounds` (`500 server_error`, #520) — the caller
				// did nothing wrong. Its scope ceiling is the subject token's scope
				// AND the client's `allowedScopes`; a scope the subject carries but
				// the registration does not would hand this client something its
				// registration never permitted. An empty `grantedScope` strips every
				// scope (CP-15).
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
				// The audience the same way, and the same as core's
				// `boundPolicyAudience` holds it for every other grant — within
				// what the client is registered for — with the subject token's
				// audience as a second bound, the one the request's audience met
				// above. An empty `grantedAudience` is no decision, as
				// `boundPolicyAudience` reads it: the request's audience stands.
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
							missingResources,
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

			// The issued lifetime, narrowed in three steps.
			//
			// 1. What the client asked for with `expires_in`, or the configured
			//    `oauth.accessToken.defaultExpiresIn` when it asked for nothing.
			// 2. Clamped to `oauth.accessToken.maxExpiresIn`. Clamped, not
			//    refused: the request is for "at most this long", and a shorter
			//    token answers it — the same reading step 3 gives the subject's
			//    expiry. An unset max equals the default, so no request extends
			//    past the default unless the operator opted in. The max is also
			//    the longest a resource server validating this token offline
			//    can keep accepting it after its family is revoked.
			// 3. Capped at the subject token's remaining lifetime, below.
			let expiresIn = Math.min(requestedExpiresIn ?? defaultExpiresIn, maxExpiresIn);

			// RFC 8693 §2.2.1: the issued token's lifetime SHOULD NOT exceed the
			// subject token's. A fresh `exp` was stamped from config with no
			// reference to the subject at all, so every exchange reset the
			// clock: a chain of exchanges outlived the credential it descends
			// from indefinitely, and the subject's expiry stopped being an
			// expiry — the one bound that does not depend on any store staying
			// wired was the one bound not enforced.
			//
			// Evaluated here rather than beside the other subject checks so the
			// order in which a doubly-invalid request is refused does not move;
			// the subject validator already rejects an expired self-issued token
			// before this point, which makes this the fail-closed backstop for
			// consumer-contributed validators rather than the common path.
			//
			// The issuance instant is decided once, here, and both the cap and
			// the minted `iat` / `exp` are measured from it. Reading the clock
			// again inside `generateToken` let the two land in different
			// seconds, and `exp = mint second + (subject exp − cap second)`
			// then passed the subject's `exp` by the seconds in between.
			const issuedAt = Math.floor(Date.now() / 1000);
			const subjectExpiry = subjectValidated.claims.exp;
			if (typeof subjectExpiry === "number" && Number.isFinite(subjectExpiry)) {
				const remaining = Math.floor(subjectExpiry - issuedAt);
				// `<= 0` is both the already-expired token and the one expiring
				// inside this second. Capping either mints a token with a zero
				// or negative lifetime — dead on arrival, and indistinguishable
				// at the resource server from a bug here — so it is a refusal
				// the caller can read instead.
				if (remaining <= 0) return invalidRequest("subject_token has expired");
				expiresIn = Math.min(expiresIn, remaining);
			}
			// A subject token carrying no `exp` leaves the lifetime from steps 1
			// and 2 standing. That is not absence read permissively: `exp` is a
			// property of the presented credential, not a policy this
			// deployment declined to write, and a validator that returns a
			// token without one is asserting a credential with no expiry for
			// the cap to descend from. The built-in validator never takes this
			// path — jose rejects an expired token before the handler sees it.

			const accessToken = await generateToken(
				formatObject({
					family_id: reportedFamily(subjectValidated),
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

			// RFC 9449 §5: a DPoP-bound access token is advertised as
			// `token_type: "DPoP"`. The envelope defaulted to Bearer while the
			// token itself carried `cnf.jkt`, so a DPoP-aware client believed
			// the response and presented the token as a Bearer token — which
			// this provider's own protected-resource middleware refuses (RFC
			// 9449 §7.1). mTLS keeps "Bearer": RFC 8705 §3 does not redefine
			// the wire-level type. Read off the confirmation actually stamped
			// into the token, so the envelope cannot disagree with the claim.
			const responseTokenType =
				issuedConfirmation && "jkt" in issuedConfirmation ? "DPoP" : "Bearer";
			const tokens = generateTokenResponse({ accessToken }, { tokenType: responseTokenType });
			const tokensWithIssuedType: typeof tokens & { issued_token_type: string } = {
				...tokens,
				issued_token_type: ACCESS_TOKEN_TYPE,
			};

			return {
				result: {
					status: 200,
					tokens: tokensWithIssuedType,
				},
			};
		},
	};
}

/**
 * `400 invalid_request`, the one code RFC 8693 §2.2.2 gives a token-exchange
 * request that is refused for what it presented: "If the request itself is
 * not valid or if either the `subject_token` or `actor_token` are invalid for
 * any reason, or are unacceptable based on policy, [...] the value of the
 * `error` parameter MUST be the `invalid_request` error code."
 *
 * - **The request itself:** a missing or repeated parameter, `actor_token`
 *   without `actor_token_type` or the reverse, a body `client_id` that is not
 *   the authenticated client, a malformed `expires_in`, and a token type this
 *   deployment has no validator for or cannot issue — RFC 6749 §5.2's "an
 *   unsupported parameter value". Not `unsupported_token_type`: RFC 7009
 *   registers that code for the revocation endpoint, and RFC 8693 defines no
 *   token-type error.
 * - **A presented token:** the validator's `null`, a sender-constraint row,
 *   the refresh-token family rule, `may_act`, the actor-chain bound or the
 *   subject's expiry. The §2.2.2 sentence is a MUST and covers every one of
 *   them, so no other code is open to this grant for a refused token —
 *   `invalid_grant` included. (The refresh grant, which §2.2.2 does not
 *   govern, answers the same sender-constraint and family rows with RFC
 *   6749's `invalid_grant` for its refresh token.)
 *
 * One code covers all of these, so the `error_description` is what tells a
 * client which check refused it; each call site's description is part of the
 * wire contract and the README names it. A description quotes a value with
 * `'`: RFC 6749 §5.2 allows neither `"` nor `\` in one, and `/oauth/token`
 * replaces any character outside its set with `?`.
 *
 * The request's other answers keep the codes the RFCs give them —
 * `invalid_target` for an audience or resource (§2.2.2), `invalid_scope`,
 * `invalid_client`, `unauthorized_client` — a policy decision past a ceiling
 * is core's `policyOutOfBounds`, and a store that cannot answer is
 * `503 temporarily_unavailable`, never a verdict on the request.
 */
function invalidRequest(errorDescription: string): GrantHandlerResult {
	return { result: { status: 400, error: "invalid_request", errorDescription } };
}

/** What {@link parseRequestedExpiresIn} answers for a present, unusable value. */
const MALFORMED = Symbol("malformed");

/**
 * The longest `expires_in` digit string read as a lifetime. Ten digits is over
 * three centuries — far past the one-year ceiling any `maxExpiresIn` can carry,
 * so every value it admits that is too large is clamped rather than refused —
 * and well inside the range `Number` represents exactly.
 */
const MAX_REQUESTED_EXPIRES_IN_DIGITS = 10;

const REQUESTED_EXPIRES_IN_SHAPE = new RegExp(`^[0-9]{1,${MAX_REQUESTED_EXPIRES_IN_DIGITS}}$`);

/**
 * Reads the `expires_in` form parameter: `undefined` when absent or sent
 * without a value, the number of seconds when it is one string of ASCII decimal
 * digits denoting a positive integer, and `MALFORMED` otherwise.
 *
 * Deliberately narrower than `Number(value)`, which accepts whitespace, a sign,
 * a decimal point, an exponent, hexadecimal, and reads the empty string as `0`.
 * A repeated parameter arrives as an array and is refused rather than having
 * one of its values picked: the grant cannot tell which one the client meant.
 * Absent, `null` and `""` all mean omitted: RFC 6749 §3.2 has a parameter sent
 * without a value treated as if it were not sent, which is also how this grant
 * reads `scope=""`.
 */
function parseRequestedExpiresIn(value: unknown): number | undefined | typeof MALFORMED {
	if (value === undefined || value === null || value === "") return undefined;
	if (typeof value !== "string" || !REQUESTED_EXPIRES_IN_SHAPE.test(value)) return MALFORMED;
	const seconds = Number(value);
	return seconds > 0 ? seconds : MALFORMED;
}

function getMaxActorChainDepth(deps: TokenExchangeDependencies): number {
	const tokenExchange = deps.config.oauth.tokenExchange as
		| { maxActorChainDepth?: unknown }
		| undefined;
	const maxActorChainDepth = tokenExchange?.maxActorChainDepth;
	return typeof maxActorChainDepth === "number" &&
		Number.isInteger(maxActorChainDepth) &&
		maxActorChainDepth > 0
		? maxActorChainDepth
		: 3;
}

/**
 * The family a validator reports, or `undefined` when it reports none. An
 * empty `familyId` names no family, so it is read as absent — by the family
 * rule and by issuance alike: nothing to check, and no `family_id: ""` for the
 * issued token to inherit that no revocation could ever reach.
 */
function reportedFamily(validated: ValidatedToken): string | undefined {
	return validated.familyId ? validated.familyId : undefined;
}

/**
 * The refresh-token family rule for a token presented as `subject_token` or
 * `actor_token`: the refusal to return, or `null` when the token passes.
 *
 * This grant owns the rule, for both tokens; the built-in validator does not
 * read `refreshTokenFamilyRevocation`. A validator can only answer `null`,
 * which the handler reports as `… validation failed`, whereas a revoked family
 * has a description of its own on `/oauth/token` — the refresh grant already
 * gives `family_revoked` there — and it tells the client that
 * re-authenticating, not retrying, is what helps.
 *
 * The rule keys on the family a validator asserts (`familyId`), not on the
 * token type the validator was registered for: the built-in validator can be
 * registered under any type, and whichever produced the subject, the issued
 * token inherits its `family_id`. Its outcomes, checked once per token:
 *
 * - A family but no `refreshTokenFamilyRevocation` wired: refused
 *   (fail-closed). A subject's family would pass to the issued token with
 *   nothing able to observe its revocation; an actor would be recorded in the
 *   issued token's `act` claim on a credential whose revocation cannot be
 *   checked.
 * - The store throws: `503 temporarily_unavailable`, logged as
 *   `token_exchange_family_store_unavailable` with the role and core's
 *   `loggableError` projection of the store's error, so an outage is never
 *   reported as a revoked token.
 * - The family is revoked: `family_revoked`.
 *
 * Both refusals are {@link invalidRequest}s: an unverifiable or revoked family
 * makes the token unacceptable, which RFC 8693 §2.2.2 answers
 * `invalid_request`.
 *
 * The actor's descriptions carry the `actor_token ` prefix the handler's other
 * actor answers carry.
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
		// The projection: a store error carries what it sent — an ioredis
		// reply error the command, the family's key included.
		deps.logger?.error(
			{ err: loggableError(err), role },
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
 * The single audience an exchanged token is minted for (spec §8.1 rule 2):
 *
 * - an explicit audience → its first element. It is either the request
 *   parameter or a policy hook override, each already held to the client's
 *   registration and the subject token's audience;
 * - omitted, and the subject names one audience → that audience, if the
 *   client is registered for it, else the client's own id. This prevents
 *   cross-client audience confusion: a client cannot use a stolen
 *   subject_token to mint a token for an audience outside its own allowlist
 *   just by omitting the audience parameter;
 * - omitted, and the subject names several or none → the client's own id.
 *
 * RFC 7519 §4.1.3 lets `aud` be a string or an array; a one-element array is
 * the same as the bare string. `generateToken` carries one audience, so a
 * multi-element `grantedAudience` contributes only its first entry — a known
 * limitation (spec §8.1.1: multi-audience needs introspection by every party).
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

function normalizeArrayParam(value: unknown): string[] | null {
	if (value === undefined || value === null || value === "") return null;
	if (Array.isArray(value)) {
		const filtered = value.map(String).filter((s) => s.length > 0);
		return filtered.length === 0 ? null : filtered;
	}
	return [String(value)];
}

export { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";
export { GRANT_TYPE as TOKEN_EXCHANGE_GRANT_TYPE };
