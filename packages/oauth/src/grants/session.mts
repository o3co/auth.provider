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
import {
	type Admission,
	type AdmissionDeps,
	admitSession,
	checkResolver,
	cookieClaim,
	describeAdmissionOutage,
	type GrantContext,
	type GrantDependencies,
	type GrantError,
	type GrantHandler,
	type GrantHandlerResult,
	generateToken,
	generateTokenResponse,
	isEmailVerified,
	ownedConfirmation,
	type ProviderDeps,
	readSpaceDelimitedParameter,
	resolveAccessTokenLifetime,
	vouchedAmr,
	wellFormedAmr,
} from "@o3co/auth-provider-core";
import { stepUpRefusal } from "../admission.mjs";
import type { SESSION_GRANT_ADMISSION_ACTIONS } from "../admissionActions.mjs";
import { resolveOAuthOptions } from "../resolveOAuthOptions.mjs";

/**
 * `session` grant: mints an access token for the user of an already
 * authenticated browser session (first-party / BFF topologies).
 *
 * The client is `ctx.authenticatedClient` (RFC 6749 §2.3 authentication via
 * `clientAuthMw`), never a body `client_id`: no identity decision reads the
 * raw body. Its `allowedScopes` bound the request; `aud` is its first
 * `allowedAudiences` entry, else its client id; `azp` is its client id.
 */
/**
 * What the session grant reads. The requirement resolver, `subjectRevocation`
 * and `auditSink` feed session admission; the resolver is required, and a
 * factory built without one is refused.
 */
export type SessionGrantDeps = Pick<
	GrantDependencies,
	"config" | "keyStore" | "userSessionStore" | "subjectRevocation" | "logger"
> &
	ProviderDeps<"sessionRequirementResolver", "auditSink">;

/**
 * The token endpoint's answer to an admission that does not mint, or
 * `undefined` when admitted. `step_up` stays in RFC 6749's vocabulary
 * (`invalid_grant` plus a `step_up` member), so existing clients keep their
 * error mapping.
 */
const refusalFor = (admission: Admission): GrantError | undefined => {
	switch (admission.outcome) {
		case "admitted":
			return undefined;
		case "unauthenticated":
			return {
				status: 401,
				error: "unauthorized",
				errorDescription: "session is not authenticated",
			};
		case "not_live":
			return {
				status: 400,
				error: "invalid_grant",
				errorDescription:
					admission.reason === "no_sid"
						? "session identifier (sid) is required"
						: "session_invalid",
			};
		case "revoked":
			return { status: 400, error: "invalid_grant", errorDescription: "session_invalid" };
		case "unmet":
		case "reauthenticate":
			return {
				status: 400,
				error: "invalid_grant",
				errorDescription: `the session does not meet the ${admission.requirement} requirement`,
			};
		case "step_up":
			return stepUpRefusal(admission.requirement);
		case "unavailable":
			return {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: describeAdmissionOutage(admission.store),
			};
	}
};

export const createSessionGrant = (deps: SessionGrantDeps): GrantHandler => {
	const { config, keyStore } = deps;
	// What admission reads for this grant: the module's own slots as wired,
	// and no acr table, since the grant asks for no acr.
	const admissionDeps: AdmissionDeps = {
		userSessionStore: deps.userSessionStore,
		subjectRevocation: deps.subjectRevocation,
		requirements: checkResolver(deps.sessionRequirementResolver, "createSessionGrant"),
		acrTable: {},
		logger: deps.logger,
		auditSink: deps.auditSink,
	};
	// Deployment config, resolved once at construction; `resolveOAuthOptions`
	// owns the defensive read for hand-built configs.
	const { requireEmailVerified } = resolveOAuthOptions(config);
	// Read once at construction, so an invalid hand-built configuration is
	// refused before any request.
	const accessTokenExpiresIn = resolveAccessTokenLifetime(config).defaultExpiresIn;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, session, issuer } = ctx;
			const { scope: requestedScope } = body as { scope?: unknown };

			// Identity is the authenticated client only (clientAuthMw): a body
			// `client_id` is absent under HTTP Basic and spoofable otherwise.
			const client = ctx.authenticatedClient;
			if (!client) {
				return {
					result: {
						status: 401,
						error: "invalid_client",
						errorDescription: "Client authentication is required",
					},
				};
			}

			// express-session and UserSession are separate stores: a retained
			// cookie must not mint after the tracked session is revoked, expired,
			// or predates a subject-wide revocation. Admission decides (flag, live
			// record by `sid`, subject, revocation boundary, requirements).
			const claim = cookieClaim({ session });
			const admission = await admitSession(admissionDeps, {
				claim,
				action: "oauth.session_grant" satisfies keyof typeof SESSION_GRANT_ADMISSION_ACTIONS,
			});
			const refusal = refusalFor(admission);
			if (refusal !== undefined) return { result: refusal };
			// `admitted`: the tracked identity is authoritative — the record's
			// `sub`, which admission held equal to the cookie's — else, with no
			// store, the cookie's own, which a cookie claim always names by now.
			const tracked = (admission as Extract<Admission, { outcome: "admitted" }>).session;
			const userId = tracked === null ? claim.subject : tracked.sub;
			const sid = claim.sid;
			// The access token's `amr` is what the tracked session vouches for
			// (as in the authorization_code grant), never the record's raw `amr`;
			// an untracked browser session is not a source.
			const trackedAmr = tracked === null ? undefined : wellFormedAmr(vouchedAmr(tracked));

			// The email gate covers every path that mints for a user.
			// `invalid_grant`, not `access_denied`: RFC 6749 §5.2 does not define
			// the latter for the token endpoint.
			if (requireEmailVerified && !isEmailVerified(session.user)) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "email address is not verified",
					},
				};
			}

			// RFC 6749 §3.3, read strictly: a malformed value is refused rather
			// than checked against the allowlist. Empty or `null` is omitted; a
			// repeated parameter arrives as an array.
			if (
				requestedScope !== undefined &&
				requestedScope !== null &&
				typeof requestedScope !== "string"
			) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "scope must be a space-delimited string",
					},
				};
			}
			const named =
				typeof requestedScope === "string" ? readSpaceDelimitedParameter(requestedScope) : [];
			if (named === null) {
				return {
					result: {
						status: 400,
						error: "invalid_scope",
						errorDescription: "scope is not a space-delimited list of scope-tokens",
					},
				};
			}
			const scopes = named.length > 0 ? named : undefined;

			// An omitted scope stays omitted rather than widening to the client's
			// full allowlist: this grant runs on a live user session, so the
			// narrower reading is the safe one.
			if (scopes) {
				const allowed = client.allowedScopes ?? [];
				const invalid = scopes.filter((s) => !allowed.includes(s));
				if (invalid.length > 0) {
					return {
						result: {
							status: 400,
							error: "invalid_scope",
							errorDescription: `requested scope exceeds allowed: ${invalid.join(" ")}`,
						},
					};
				}
			}

			// `sid` binds the token to the browser session, so either logout
			// endpoint (both delete the `UserSession` record) revokes it wherever
			// liveness is checked (`/userinfo`, `/introspect`). No refresh token
			// and no `family_id`: `sid` is the whole binding. A resource server
			// that checks only signature and `exp` cannot see a logout; the lever
			// there is a short `accessToken.defaultExpiresIn`.
			//
			// `aud` defaults to `allowedAudiences[0]`, the client's configured
			// resource (the AuthenticatedClient contract), falling back to the
			// client id as `authorization_code` does — never the issuer, since the
			// token is for a resource, and never null.
			const audience = client.allowedAudiences?.[0] ?? client.clientId;
			// The member the binding's mechanism kind owns (core's
			// `ownedConfirmation`): a contributed mechanism cannot have a binding
			// minted that no owning mechanism validated. The response's
			// `token_type` is read off it by `generateTokenResponse`.
			const confirmation = ownedConfirmation(ctx.tokenBinding);

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: await generateToken(
							{ ...(sid ? { sid } : {}), ...(trackedAmr ? { amr: trackedAmr } : {}) },
							{
								keyStore,
								expiresIn: accessTokenExpiresIn,
								issuer,
								audience,
								subject: userId ?? null,
								authorizedParty: client.clientId,
								scope: scopes?.join(" ") ?? null,
								tokenType: "at+jwt",
								...(confirmation ? { confirmation } : {}),
							},
						),
					}),
				},
			};
		},
	};
};
