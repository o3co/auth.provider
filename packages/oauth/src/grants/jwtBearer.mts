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
	UserRepository,
} from "@o3co/auth-provider-core";
import { generateToken, generateTokenResponse, isEmailVerified } from "@o3co/auth-provider-core";
import { resolveOAuthOptions } from "../resolveOAuthOptions.mjs";

/** RFC 7523 §2.1. */
export const JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/**
 * RFC 7523 JWT-bearer authorization grant, wired to the Store's
 * `authenticateByToken` seam (#301).
 *
 * ## The gap this closes
 *
 * `UserRepository.authenticateByToken(handle)` — "authenticate by an opaque
 * handle and resolve to a subject" — already existed and is service-pluggable,
 * but the only caller was the federation callback. There was no public entry
 * point for *present a device credential → authenticate → get tokens*, so the
 * device-login and anonymous→registered shapes had nowhere to land.
 *
 * ## Why RFC 7523 and not token exchange
 *
 * The issue's option (A) was a custom token-exchange validator, on the reading
 * that it "works today". It does not for this case: the exchange grant answers
 * `401 invalid_client` for `tokenEndpointAuthMethod === "none"` — *"Token
 * Exchange does not support public clients"* — and a device holding a signed
 * assertion is the archetypal public client. RFC 7523 §3 is the standard
 * written for this shape, and says client authentication is **optional**
 * ("JWT authorization grants may be used with or without client authentication
 * or identification"), which is the property token exchange refuses.
 *
 * RFC 7523 also leaves *how* the assertion is validated — "the key used to
 * apply and verify the digital signature" — explicitly out of scope, which is
 * what makes resolving it through a pluggable {@link AssertionVerifier} a
 * conforming choice rather than a deviation.
 *
 * ## The boundary this does not cross
 *
 * Verification proves **possession**; the Store decides **identity**. This
 * grant never inspects who the handle belongs to, never creates or links
 * anything, and never writes. A device that is not linked to a user is the
 * Store's business: it returns whatever subject it wants for that handle,
 * including a stable anonymous one, and continuity across a later signup is a
 * Store data-modelling choice. `UserRepository` stays `authenticate` /
 * `authenticateByToken` (#305's verify-only boundary).
 *
 * ## Failure vocabulary
 *
 * - Missing/blank `assertion` → `invalid_request` (RFC 6749 §5.2: a missing
 *   parameter is not a bad grant).
 * - Verifier returns `null`, the Store does not resolve the handle, or the
 *   resolved user fails `oauth.requireEmailVerified` (#297) → `invalid_grant`,
 *   identically. Distinguishing them would let a caller probe for live device
 *   identifiers, or for which of them are linked to a real account.
 * - Verifier or Store **throws** → `503 temporarily_unavailable`. An
 *   attestation service or a Store being unreachable is an outage, not a bad
 *   credential, and answering `invalid_grant` would send an operator to
 *   re-enrol a device that was fine — the distinction #408 drew for revocation.
 */
export const createJwtBearerGrant = (
	deps: GrantDependencies & {
		readonly assertionVerifier: AssertionVerifier;
		readonly userRepository: UserRepository;
	},
): GrantHandler => {
	const { config, keyStore, assertionVerifier, userRepository } = deps;
	// #297: deployment config, resolved once at construction like the session
	// grant does — `resolveOAuthOptions` owns the defensive read.
	const { requireEmailVerified } = resolveOAuthOptions(config);

	return {
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
				verified = await assertionVerifier.verify(rawAssertion);
			} catch (err) {
				deps.logger?.error({ err }, "jwt_bearer_assertion_verifier_unavailable");
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
				deps.logger?.error({ err }, "jwt_bearer_user_repository_unavailable");
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

			// #297: this grant resolves a user and mints for them, which makes it
			// the third point (after `/authorize` and the `session` grant) that
			// holds the user at issuance and therefore the third the gate has to
			// cover. Without it a deployment requiring a verified email would
			// find the browser paths gated and the device path wide open.
			//
			// Same answer as an unknown handle, on purpose: a distinct
			// description would tell a caller that this handle resolves to a
			// real, merely unverified, account. The log line is for the
			// operator who turned the gate on and now sees devices refused.
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

			const scopeClaim = scopes.scopes.length > 0 ? scopes.scopes.join(" ") : null;
			const clientId = ctx.authenticatedClient?.clientId;
			const confirmation = ctx.tokenBinding?.confirmation;
			const tokenType = ctx.tokenBinding?.kind === "dpop" ? "DPoP" : "Bearer";

			const accessToken = await generateToken(
				{ ...(clientId ? { client_id: clientId } : {}) },
				{
					expiresIn: config.oauth.accessToken.expiresIn,
					keyStore,
					issuer: ctx.issuer,
					audience: clientId ?? null,
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
					tokens: generateTokenResponse({ accessToken }, { tokenType }),
				},
			};
		},
	};
};

/**
 * Intersect what the request asks for, what the assertion authorizes, and what
 * the client is allowed.
 *
 * Each is a ceiling, and an absent one constrains nothing rather than granting
 * everything — the distinction #396 drew for `defaultScopes`. A requested scope
 * outside any present ceiling is `invalid_scope` rather than silently dropped,
 * so a caller learns their token is narrower than they asked for.
 *
 * An **omitted** scope is the case #396 is about, and it is answered the way
 * `client_credentials` answers it: an authenticated client's *declared*
 * `defaultScopes` — never its whole allowlist — filtered by that allowlist and
 * by the assertion. A client with an allowlist and no declared default gets
 * `invalid_scope`; one with an empty allowlist keeps the empty grant, since
 * there is nothing to over-grant. Without an authenticated client there is no
 * registration to declare a default, so the assertion's own `scope` claim —
 * the issuing authority's statement — is what an omitted request receives,
 * and nothing at all when it names none.
 */
function resolveScope(
	ctx: GrantContext,
	assertionScope: readonly string[] | undefined,
):
	| { scopes: readonly string[] }
	| { status: 400; error: "invalid_scope" | "invalid_request"; errorDescription: string } {
	const raw = ctx.body.scope;
	if (raw !== undefined && typeof raw !== "string") {
		return {
			status: 400,
			error: "invalid_request",
			errorDescription: "scope must be a string",
		};
	}
	const client = ctx.authenticatedClient;
	const ceilings = [assertionScope, client?.allowedScopes].filter(
		(c): c is readonly string[] => c !== undefined,
	);
	const within = (s: string): boolean => ceilings.every((c) => c.includes(s));

	if (raw === undefined || raw.trim().length === 0) {
		if (client) {
			// #396, mirrored from `client_credentials`: an omitted scope draws
			// on the client's DECLARED default, never on the whole allowlist —
			// "forgot to send scope" must not be the maximum grant. The
			// assertion stays a ceiling on that default (`within`), and the
			// allowlist filter is applied even so: schema-validated
			// registrations are ⊆ by boot, custom repositories are under no
			// such obligation.
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
		// No client: the assertion's issuer is the only authority present, and
		// its `scope` claim is the declared default. With none, the token gets
		// nothing — there is no allowlist to draw on and inventing one would be
		// the over-grant #396 removed.
		return { scopes: assertionScope ?? [] };
	}

	// A request with NO ceiling to bound it is refused, not granted.
	//
	// `within` is `ceilings.every(...)`, and `[].every(...)` is `true` — so
	// without this branch a caller with an assertion that names no scope and no
	// authenticated client would receive whatever scope they asked for, which
	// is the over-grant #396 removed elsewhere and which the paragraph above
	// claims not to do. Vacuous truth, in the one place it is most expensive.
	if (ceilings.length === 0) {
		return {
			status: 400,
			error: "invalid_scope",
			errorDescription:
				"scope was requested but nothing bounds it: the assertion names no scope and " +
				"no authenticated client supplies an allowlist",
		};
	}

	const requested = raw.split(" ").filter((s) => s.length > 0);
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
