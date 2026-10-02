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
	AssertionVerifier,
	GrantContext,
	GrantDependencies,
	GrantHandler,
	GrantHandlerResult,
	ProviderDeps,
	UserRepository,
} from "@o3co/auth-provider-core";
import {
	auditErrorText,
	boundPolicyAudience,
	deriveAudienceFromResources,
	evaluateGrantPolicy,
	extractResourceParam,
	generateToken,
	generateTokenResponse,
	isEmailVerified,
	loggableError,
	ownedConfirmation,
	readSpaceDelimitedParameter,
	resolveAccessTokenLifetime,
	unrepresentedResources,
} from "@o3co/auth-provider-core";
import { resolveOAuthOptions } from "../resolveOAuthOptions.mjs";

/** RFC 7523 §2.1. */
export const JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/**
 * RFC 7523 JWT-bearer authorization grant: a pluggable
 * {@link AssertionVerifier} turns the presented assertion into a subject
 * handle, and `UserRepository.authenticateByToken` resolves the user.
 *
 * RFC 7523 rather than token exchange: client authentication is optional here
 * (§3) — a device holding an assertion is typically a public client, which
 * token exchange refuses — and the RFC leaves assertion key validation out of
 * scope, so a pluggable verifier conforms.
 *
 * Verification proves possession; the Store decides identity. This grant
 * never creates, links or writes anything. The token never outlives the
 * assertion, and no refresh token is issued.
 *
 * Failures:
 * - missing `assertion` → `invalid_request` (RFC 6749 §5.2);
 * - verifier `null`, unresolved handle, unverified email, or an assertion with
 *   no whole second left → one identical `invalid_grant`, so a caller cannot
 *   probe which device identifiers exist or are linked to accounts;
 * - verifier or Store throws → `503 temporarily_unavailable` (an outage is not
 *   a bad credential);
 * - a policy that exceeds its authority (widened scope, audience outside the
 *   ceiling) → `500 server_error`;
 * - a `resource` the final `aud` cannot represent → `invalid_target`;
 * - client and assertion issuer admit no common audience → `invalid_grant`.
 */
/**
 * What the jwt-bearer grant reads. The verifier and repository are required
 * here; the module checks both before building the grant, so a missing one is
 * refused at composition, not at the first request.
 */
export type JwtBearerGrantDeps = Pick<
	GrantDependencies,
	"config" | "keyStore" | "grantPolicy" | "logger"
> &
	ProviderDeps<"assertionVerifier" | "userRepository">;

export const createJwtBearerGrant = (deps: JwtBearerGrantDeps): GrantHandler => {
	const { config, keyStore, assertionVerifier, userRepository } = deps;
	// Resolved once at construction; `resolveOAuthOptions` owns the defensive read.
	const { requireEmailVerified } = resolveOAuthOptions(config);
	// Read once at construction, so an invalid hand-built configuration is
	// refused before any request rather than after the verifier has recorded
	// an ID-JAG's `jti`.
	const { defaultExpiresIn } = resolveAccessTokenLifetime(config);

	return {
		// A device credential is a standing capability of a registration: an
		// authenticated client must list this grant in `allowedGrantTypes`
		// (enforced at dispatch). A caller with no client (RFC 7523 §3) has no
		// allowlist to consult.
		requiresExplicitGrantAllowlist: true,
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const rawAssertion = ctx.body.assertion;
			if (typeof rawAssertion !== "string" || rawAssertion.length === 0) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "assertion is required",
					},
				};
			}

			// Possession first, always. Nothing below runs on an unverified
			// assertion, and the verifier is the only thing that can turn the
			// caller's string into a handle — the request never supplies one.
			let verified: Awaited<ReturnType<AssertionVerifier["verify"]>>;
			try {
				// The verifier learns who is presenting, so an issuer's terms can
				// admit some clients and not others.
				verified = await assertionVerifier.verify(rawAssertion, {
					clientId: ctx.authenticatedClient?.clientId,
				});
			} catch (err) {
				deps.logger?.error(
					{ err: loggableError(err) },
					"jwt_bearer_assertion_verifier_unavailable",
				);
				return {
					result: {
						status: 503,
						error: "temporarily_unavailable",
						errorDescription: "assertion verification unavailable",
					},
				};
			}
			if (verified === null) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "assertion did not verify",
					},
				};
			}

			let user: Awaited<ReturnType<UserRepository["authenticateByToken"]>>;
			try {
				user = await userRepository.authenticateByToken(verified.subjectHandle);
			} catch (err) {
				deps.logger?.error({ err: loggableError(err) }, "jwt_bearer_user_repository_unavailable");
				return {
					result: {
						status: 503,
						error: "temporarily_unavailable",
						errorDescription: "identity resolution unavailable",
					},
				};
			}
			if (user === null) {
				// Same answer as a failed verification, on purpose: telling the
				// two apart is a probe for which device identifiers exist.
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "assertion did not verify",
					},
				};
			}

			const subject = user.id;
			if (typeof subject !== "string" || subject.length === 0) {
				// The Store resolved the handle to something with no subject to
				// bind. Issuing a token with an empty `sub` would produce a
				// credential naming nobody, so this fails closed.
				deps.logger?.error({ kind: assertionVerifier.kind }, "jwt_bearer_resolved_user_has_no_id");
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "assertion did not verify",
					},
				};
			}

			// The email gate covers every path that mints for a user. Same answer
			// as an unknown handle: a distinct one would reveal that the handle
			// resolves to a real, unverified account.
			if (requireEmailVerified && !isEmailVerified(user)) {
				deps.logger?.info({ kind: assertionVerifier.kind }, "jwt_bearer_email_not_verified");
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "assertion did not verify",
					},
				};
			}

			const scopes = resolveScope(ctx, verified.scope);
			if ("error" in scopes) return { result: scopes };
			let effectiveScopes = scopes.scopes;
			const client = ctx.authenticatedClient;
			const clientId = client?.clientId;

			// RFC 8707: read under the flag alone, whether or not a policy is
			// wired. Flag off, the parameter is ignored (RFC 6749 §3.2).
			const resourceIndicatorEnabled = config.oauth.resourceIndicator?.enabled === true;
			const requestedResource = resourceIndicatorEnabled
				? extractResourceParam(ctx.body as Record<string, unknown>)
				: null;

			// The assertion issuer's registered audiences, when it has any, bound
			// the issued `aud` from every source.
			const issuerAudiences = verified.audience;
			const withinIssuer = (a: string): boolean =>
				issuerAudiences === undefined || issuerAudiences.includes(a);
			// What this request may mint for: the registration's audiences that
			// the issuer also admits, or — with no client — the issuer's own list.
			// `undefined` only when neither side says anything.
			const clientAudiences = client
				? (client.allowedAudiences ?? []).filter(withinIssuer)
				: undefined;
			const audienceCeiling = clientAudiences ?? issuerAudiences;

			// The grant policy runs after the identity gates and scope ceilings, so
			// it sees a resolved subject and an already-narrowed request.
			let policyGrantedAudience: string | null = null;
			if (deps.grantPolicy) {
				const policy = await evaluateGrantPolicy(
					deps.grantPolicy,
					{
						grantType: JWT_BEARER_GRANT_TYPE,
						clientId,
						subject,
						requestedScope: effectiveScopes.length > 0 ? [...effectiveScopes] : undefined,
						// Forwarded as the siblings do, so a policy can narrow to it.
						resource: requestedResource ?? undefined,
					},
					{ ip: ctx.ip, userAgent: ctx.userAgent, issuer: ctx.issuer ?? "" },
					effectiveScopes,
					{ logger: deps.logger },
				);
				if (!policy.ok) return { result: policy.result };
				effectiveScopes = policy.scopes;
				// A policy audience is held to `audienceCeiling`; with no ceiling at
				// all it is refused rather than dropped, so a policy never believes
				// it narrowed a token that carries no `aud`.
				const policyAudience = boundPolicyAudience(policy.decision, audienceCeiling);
				if (!policyAudience.ok) {
					// Logged for the operator who wired the policy. The description may
					// quote the caller's `resource`, so it is sanitised and capped.
					deps.logger?.warn(
						{
							kind: assertionVerifier.kind,
							reason: auditErrorText(policyAudience.result.errorDescription),
						},
						"jwt_bearer_policy_audience_refused",
					);
					return { result: policyAudience.result };
				}
				policyGrantedAudience = policyAudience.audience;
			}

			// Audience, first match wins: a policy-narrowed audience; one derived
			// from `resource` (RFC 8707 §2) within `allowedAudiences ∪ {clientId}`;
			// the client's `allowedAudiences[0]`, else its client id — the rule
			// the session and device grants use, so a client gets one `aud` across
			// grants; with no client, the issuer's first audience, else this
			// server's issuer (RFC 9068 §2.2 requires the claim). Without a client
			// nothing derives from `resource`, and the check below refuses.
			const audience =
				policyGrantedAudience ??
				deriveAudienceFromResources(
					requestedResource,
					new Set([
						...(audienceCeiling ?? []),
						...(clientId !== undefined && withinIssuer(clientId) ? [clientId] : []),
					]),
				) ??
				(client
					? (clientAudiences?.[0] ?? (withinIssuer(client.clientId) ? client.clientId : null))
					: (issuerAudiences?.[0] ?? ctx.issuer ?? null));

			if (
				issuerAudiences !== undefined &&
				(audience === null || !issuerAudiences.includes(audience))
			) {
				// The client and issuer registrations admit no common audience; the
				// description says which two registrations to compare.
				deps.logger?.warn(
					{ kind: assertionVerifier.kind, issuer: verified.issuer, clientId },
					"jwt_bearer_issuer_audience_mismatch",
				);
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription:
							"assertion issuer is not trusted for any audience this client mints for",
					},
				};
			}

			// RFC 8707 §2: the audience must represent the requested resource.
			// Checked once the audience is final, covering every source.
			const unrepresented = unrepresentedResources(requestedResource, audience);
			if (unrepresented.length > 0) {
				return {
					result: {
						status: 400,
						error: "invalid_target",
						errorDescription: `requested_resources_not_in_audience: ${unrepresented.join(" ")}`,
					},
				};
			}

			const scopeClaim = effectiveScopes.length > 0 ? effectiveScopes.join(" ") : null;
			// The member the binding's mechanism kind owns (core's
			// `ownedConfirmation`), so a contributed mechanism cannot have a
			// binding minted that no owning mechanism validated. The response's
			// `token_type` is read off it by `generateTokenResponse`.
			const confirmation = ownedConfirmation(ctx.tokenBinding);

			// The token never outlives the assertion (as RFC 8693 §2.2.1 holds a
			// subject token). Capped at minting, not at verification: the Store
			// and the policy run in between.
			let expiresIn = defaultExpiresIn;
			// One issuance instant for both the cap and the token. Read twice,
			// a second boundary between the reads would stamp `exp` a second
			// past the assertion's; `iat` is this instant's whole second, so
			// `iat + floor(expiresAt − now)` can never exceed `expiresAt`.
			const nowSeconds = Date.now() / 1000;
			const issuedAt = Math.floor(nowSeconds);
			const { expiresAt } = verified;
			if (expiresAt !== undefined) {
				// Present means a finite number. The port is typed, not checked:
				// arithmetic would coerce a custom verifier's numeric string into
				// an expiry and read Infinity as none, so anything else is refused
				// below — a malformed expiry is neither an expiry nor its absence.
				const remaining =
					typeof expiresAt === "number" && Number.isFinite(expiresAt)
						? Math.floor(expiresAt - nowSeconds)
						: Number.NaN;
				// `<= 0`: already past `exp` (within a verifier's clock tolerance,
				// or lapsed while the Store answered) or expiring this second — a
				// token dead on arrival. `!(> 0)` also catches NaN. The uniform
				// description, not "has expired": a distinct answer this far in
				// would reveal that the handle resolves to a real account.
				if (!(remaining > 0)) {
					deps.logger?.info(
						{ kind: assertionVerifier.kind, issuer: verified.issuer },
						"jwt_bearer_assertion_expired",
					);
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "assertion did not verify",
						},
					};
				}
				expiresIn = Math.min(expiresIn, remaining);
			}
			// No `expiresAt` leaves the configured lifetime standing: the
			// verifier is asserting a credential with no expiry, not declining
			// to say (see `AssertionVerificationResult.expiresAt`).

			const accessToken = await generateToken(
				{ ...(clientId ? { client_id: clientId } : {}) },
				{
					expiresIn,
					issuedAt,
					keyStore,
					issuer: ctx.issuer,
					audience,
					subject,
					...(clientId ? { authorizedParty: clientId } : {}),
					scope: scopeClaim,
					tokenType: "at+jwt",
					...(confirmation ? { confirmation } : {}),
				},
			);

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({ accessToken }),
				},
			};
		},
	};
};

/**
 * Intersect what the request asks for, what the assertion authorizes, and what
 * the client is allowed. An absent ceiling constrains nothing; a requested
 * scope outside a present ceiling is `invalid_scope`, not silently dropped.
 *
 * An omitted scope gets an authenticated client's declared `defaultScopes`
 * (never its whole allowlist), or `invalid_scope` when it declares none and
 * has a non-empty allowlist. Without a client it gets the assertion's `scope`
 * claim, or nothing.
 */
function resolveScope(
	ctx: GrantContext,
	assertionScope: readonly string[] | undefined,
):
	| { scopes: readonly string[] }
	| { status: 400; error: "invalid_scope" | "invalid_request"; errorDescription: string } {
	// RFC 6749 §3.2: a parameter sent without a value is treated as omitted —
	// `scope=""` in a form body, `"scope": null` in a JSON one.
	const raw = ctx.body.scope ?? undefined;
	if (raw !== undefined && typeof raw !== "string") {
		return {
			status: 400,
			error: "invalid_request",
			errorDescription: "scope must be a space-delimited string",
		};
	}
	// RFC 6749 §3.3, read strictly: a client's request, so a value that is not
	// a space-delimited list of scope-tokens is malformed, not a scope with a
	// tab in its name that no ceiling holds. Spaces alone name nothing, which
	// is an omitted scope.
	const requested = raw === undefined ? [] : readSpaceDelimitedParameter(raw);
	if (requested === null) {
		return {
			status: 400,
			error: "invalid_scope",
			errorDescription: "scope is not a space-delimited list of scope-tokens",
		};
	}
	const client = ctx.authenticatedClient;
	const ceilings = [assertionScope, client?.allowedScopes].filter(
		(c): c is readonly string[] => c !== undefined,
	);
	const within = (s: string): boolean => ceilings.every((c) => c.includes(s));

	if (requested.length === 0) {
		if (client) {
			// The DECLARED default, never the whole allowlist: "forgot to send
			// scope" must not be the maximum grant. Filtered by the allowlist
			// even so: a grant handler is reachable through
			// `grantHandlerResolver`, so its caller may hand it an
			// `authenticatedClient` that did not come through core's
			// client-record boundary, which holds defaultScopes ⊆ allowedScopes.
			// The assertion's `scope` is a ceiling on it too (`within`).
			const allowed = client.allowedScopes ?? [];
			if (client.defaultScopes !== undefined) {
				return { scopes: client.defaultScopes.filter((s) => allowed.includes(s) && within(s)) };
			}
			if (allowed.length === 0) return { scopes: [] };
			return {
				status: 400,
				error: "invalid_scope",
				errorDescription: "scope is required: this client declares no defaultScopes",
			};
		}
		// No client: the assertion's `scope` claim is the only declared default;
		// with none, the token gets nothing.
		return { scopes: assertionScope ?? [] };
	}

	// With no ceiling, `within` is vacuously true (`[].every`) and would grant
	// whatever was asked: refuse instead.
	if (ceilings.length === 0) {
		return {
			status: 400,
			error: "invalid_scope",
			errorDescription:
				"scope was requested but nothing bounds it: the assertion names no scope and " +
				"no authenticated client supplies an allowlist",
		};
	}

	const refused = requested.filter((s) => !within(s));
	if (refused.length > 0) {
		return {
			status: 400,
			error: "invalid_scope",
			errorDescription: `scope not permitted: ${refused.join(" ")}`,
		};
	}
	return { scopes: requested };
}
