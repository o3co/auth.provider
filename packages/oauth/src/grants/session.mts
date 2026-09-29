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
	ADMISSION_ACTIONS,
	type Admission,
	type AdmissionDeps,
	admitSession,
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
import { requireRequirements, stepUpRefusal } from "../admission.mjs";
import { resolveOAuthOptions } from "../resolveOAuthOptions.mjs";

/**
 * `session` grant — mints an access token for the user of an already
 * authenticated browser session (first-party / BFF topologies).
 *
 * Authorization binds to `ctx.authenticatedClient`, which `clientAuthMw`
 * populates from RFC 6749 §2.3 token-endpoint authentication. The client's
 * `allowedScopes` are the ceiling for the request; `aud` is the client's first
 * `allowedAudiences` entry, falling back to its client id, and `azp` is the
 * client id.
 *
 * The grant deliberately takes no `clientRepository`: `clientAuthMw` already
 * resolved the client record, so re-reading it would be a second lookup of the
 * same row — and looking it up by a body `client_id` would reintroduce a
 * body-spoofable identity (the D-6 / Codex M2 invariant that no identity
 * decision reads the raw body). #295 kept the parameter for compatibility
 * after removing the read; #331 removed it.
 */
/**
 * What the session grant reads (#626 P2); see `AuthorizationGrantDeps`.
 * `sessionRequirementResolver`, `subjectRevocation` and `auditSink` are what
 * it hands admission beside the store and the logger (the session-admission
 * ADR's D1, D8): the resolver — the synthetic key, by its slot's name, so
 * `oauthSessionModule` hands its deps over whole — is required, and a
 * factory built by hand without one is refused.
 */
export type SessionGrantDeps = Pick<
	GrantDependencies,
	"config" | "keyStore" | "userSessionStore" | "subjectRevocation" | "logger"
> &
	ProviderDeps<"sessionRequirementResolver", "auditSink">;

/**
 * The token endpoint's answer to an admission that does not mint (the
 * session-admission ADR's D8), or `undefined` for `admitted`:
 *
 * - `unauthenticated` → `401 unauthorized`, as the flag's refusal always was;
 * - `not_live` → `400 invalid_grant`: `session identifier (sid) is required`
 *   for a cookie that names no record while a store is wired, else
 *   `session_invalid` — a record gone or past its expiry, a subject that is
 *   not the cookie's, a cookie that names no user;
 * - `revoked` → `400 invalid_grant` `session_invalid`: established before the
 *   subject's sessions were revoked (change 4);
 * - `unmet`, `reauthenticate` → `400 invalid_grant` naming the requirement;
 *   `step_up` → the same, with `step_up: "<requirement>"` beside it (the MFA
 *   ADR's D16 row: RFC 6749's vocabulary, so an existing client keeps its
 *   mapping and an updated one can offer the step-up);
 * - `unavailable` → `503 temporarily_unavailable`, logged once by admission.
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
	// What admission reads for this grant (D1): the module's own slots as
	// wired, and no acr table — the grant asks for no acr.
	const admissionDeps: AdmissionDeps = {
		userSessionStore: deps.userSessionStore,
		subjectRevocation: deps.subjectRevocation,
		requirements: requireRequirements("createSessionGrant", deps.sessionRequirementResolver),
		acrTable: {},
		logger: deps.logger,
		auditSink: deps.auditSink,
	};
	// #328: deployment config, not request state — resolved once at grant
	// construction, matching the altitude the router resolves its knobs at.
	// `resolveOAuthOptions` owns the defensive read for hand-built configs
	// that never passed the schema (the cast that used to sit in `handle`).
	const { requireEmailVerified } = resolveOAuthOptions(config);
	// The lifetime it mints with, read once, when the grant is built: a
	// configuration built by hand that the resolver refuses is a composition
	// fault, refused before any request — read per request, it was refused
	// only after client authentication had spent whatever it spends, with
	// a 500.
	const accessTokenExpiresIn = resolveAccessTokenLifetime(config).defaultExpiresIn;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, session, issuer } = ctx;
			const { scope: requestedScope } = body as { scope?: unknown };

			// Previously this grant read `body.client_id` and, when it was absent,
			// accepted the requested scopes as-is with `aud` / `azp` left null. A
			// confidential client authenticating with HTTP Basic sends its
			// client_id in the Authorization header and not in the body, so that
			// branch was the *normal* path for the canonical transport: any client
			// reaching this grant could mint an audience-less token carrying scopes
			// it was never registered for. Authorization now reads the
			// authenticated identity, which cannot be absent behind clientAuthMw.
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

			// express-session and UserSession are separate stores. A retained
			// browser cookie must not mint fresh tokens after the tracked session
			// is revoked, expired, or established before the subject's sessions
			// were revoked. The cookie handed to the grant is read through
			// admission (the session-admission ADR's D8): the flag, the live
			// record its `sid` names when a store is wired, the subject, the
			// boundary and the registered requirements, decided in core.
			const claim = cookieClaim({ session });
			const admission = await admitSession(admissionDeps, {
				claim,
				action: ADMISSION_ACTIONS["oauth.session_grant"],
			});
			const refusal = refusalFor(admission);
			if (refusal !== undefined) return { result: refusal };
			// `admitted`: the tracked identity is authoritative — the record's
			// `sub`, which admission held equal to the cookie's — else, with no
			// store, the cookie's own, which a cookie claim always names by now.
			const tracked = (admission as Extract<Admission, { outcome: "admitted" }>).session;
			const userId = tracked === null ? claim.subject : tracked.sub;
			const sid = claim.sid;
			// #481 audit: how the tracked session authenticated, mirrored onto the
			// access token as the authorization_code grant does — what the session
			// vouches for (the MFA ADR's D9, D13), never the record's own `amr`.
			// Only a tracked session has one; the browser's own session is not a
			// source for it.
			const trackedAmr = tracked === null ? undefined : wellFormedAmr(vouchedAmr(tracked));

			// #297: this grant mints a token straight from the browser session, so
			// it is the second point (with `/authorize`) that holds the user at
			// issuance and therefore the second the gate has to cover. Without it
			// a deployment requiring a verified email would find `/authorize`
			// gated and this path wide open.
			//
			// `invalid_grant` rather than `access_denied`: RFC 6749 §5.2 does not
			// define the latter for the token endpoint, and the session is
			// precisely the grant that cannot be honoured.
			if (requireEmailVerified && !isEmailVerified(session.user)) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "email address is not verified",
					},
				};
			}

			// RFC 6749 §3.3, read strictly and without repeats: a client's request,
			// so a value that is not a space-delimited list of scope-tokens is
			// refused as malformed rather than checked against the allowlist as if
			// a scope could be named with a tab. One that names nothing stays
			// omitted, as one sent without a value (`null`) is. A repeated
			// parameter arrives as an array.
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

			// R3: bind the token to the browser session that produced it. Without
			// `sid` nothing linked the two, so no logout could reach this token at
			// all — it stayed valid for its full lifetime (an hour by default) in
			// precisely the BFF / proxy topology this grant exists for. Stamping
			// `sid` puts it under the session-liveness machinery `/userinfo` and
			// `/introspect` run: both resolve the `UserSession` record, and both
			// logout endpoints delete it.
			//
			// They delete different amounts around it. `/oauth/logout` runs the
			// full cascade — refresh-token families, RP registry, federation
			// stores. `/session/logout` invalidates the session record, the
			// subject index and the federation pair, but revokes no families;
			// `packages/session` may not reach `cascadeLogout` across the package
			// boundary, and the scope it draws is documented on the handler.
			// Neither difference reaches THIS token: it is bound by `sid` alone
			// and issues no refresh token, so deleting the record is the whole of
			// its revocation, from either endpoint.
			//
			// What `sid` does not buy is offline validation. Liveness is a
			// property of asking: a resource server that only verifies the
			// signature and `exp` never reads the record, so it cannot see a
			// logout at any point and keeps accepting the token until it expires.
			// That is inherent to a self-contained token, not a gap these checks
			// left open — the lever for such a deployment is a short
			// `accessToken.defaultExpiresIn`, not a longer one.
			//
			// No `family_id` is stamped alongside it: this grant issues no refresh
			// token, so a family id would name a family nothing ever opens or
			// revokes. `sid` is the whole binding.
			// `allowedAudiences[0]` is the client's configured resource audience, and
			// per the AuthenticatedClient contract a grant issuing tokens straight
			// from the client record takes it as the default `aud`. Forcing the
			// client id here instead would mint tokens that the very API the
			// operator configured would reject, since `aud` would never name it.
			//
			// The fallback is the client id rather than the issuer (the shape
			// `client_credentials` uses): this token is bound to an end user and
			// meant for a resource, so naming the authorization server would be
			// wrong, and `authorization_code` already falls back the same way. What
			// matters either way is that `aud` is never null — an audience-less
			// token was half of what made the old path a self-elevation.
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
