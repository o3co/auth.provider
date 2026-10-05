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
 * The `/authorize` handler: runs the stages of RFC 6749 §4.1.1 to §4.1.2 in a
 * fixed order and stops at the first that answers. It holds the grant policy
 * hook, evaluated once here so the code exchange never evaluates it again.
 */

import {
	type AdmissionDeps,
	admitSession,
	auditErrorText,
	boundPolicyAudience,
	checkResolver,
	extractResourceParam,
	isWellFormedErrorCode,
	logGrantPolicyUnavailable,
	policyUnavailable,
	readGrantPolicyDecision,
	sanitizeErrorText,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import type { OAUTH_ROUTER_ADMISSION_ACTIONS } from "../admissionActions.mjs";
import { auditFailure, redirectError } from "./authorizeAnswers.mjs";
import { parseAcrValues, parseMaxAge, resolvePrompt, spendAskAtMint } from "./authorizeAsk.mjs";
import {
	checkAuthorizationCodeGrantAllowed,
	checkFirstPartyOrConsentable,
	resolveClientAndRedirectUri,
} from "./authorizeClient.mjs";
import { checkConsent } from "./authorizeConsent.mjs";
import {
	type AuthorizeContext,
	type AuthorizeHandlerOptions,
	authorizeParams,
	toStr,
} from "./authorizeContext.mjs";
import { mintCode, redirectWithCode, resolveAudienceForPersist } from "./authorizeIssuance.mjs";
import {
	checkClaimsParameter,
	checkNonce,
	checkPkce,
	checkRequestObjectUnsupported,
	checkResponseMode,
	checkResponseTypeIsCode,
	checkSingleValuedParams,
	resolveScopes,
} from "./authorizeRequest.mjs";
import {
	checkEmailVerified,
	checkLogin,
	checkPromptNoneHasSession,
	decideOnAdmission,
} from "./authorizeSession.mjs";
import { reauthAskStoreFor } from "./reauthAsk.mjs";

export { REDIRECT_TO_PARAM } from "./authorizeAsk.mjs";
export type { AuthorizeHandlerOptions } from "./authorizeContext.mjs";
export { authorizeParams } from "./authorizeContext.mjs";

/** The action /authorize admits, as `oauthEndpointsModule` registers it. */
const AUTHORIZE_ACTION = "oauth.authorize" satisfies keyof typeof OAUTH_ROUTER_ADMISSION_ACTIONS;

/** What `authorize.rejected` carries for a policy decision past the client's ceiling. */
const POLICY_OUT_OF_BOUNDS = { reason: "policy_out_of_bounds" } as const;

// Policy is evaluated once, here, and its narrowed scope and audience persist
// on the code; the code exchange must not re-evaluate, so a crafted `/token`
// request cannot escalate.
const applyGrantPolicy = async (
	ctx: AuthorizeContext,
	inputs: {
		requestedScopes: string[];
		allowedFilteredScopes: readonly string[];
		/** The client's full allowlist — the policy's `originalScope`. */
		originalScope: readonly string[];
		/**
		 * The audiences this grant may mint for: the client's `allowedAudiences`,
		 * or empty. Policy may narrow within it, never originate outside it.
		 */
		audienceCeiling: readonly string[];
		authorizeResource: readonly string[] | null;
	},
): Promise<{
	grantedScopes: readonly string[];
	grantedAudience: readonly string[] | undefined;
} | null> => {
	const {
		requestedScopes,
		allowedFilteredScopes,
		originalScope,
		audienceCeiling,
		authorizeResource,
	} = inputs;
	let grantedScopes: readonly string[] = allowedFilteredScopes;
	let grantedAudience: readonly string[] | undefined;
	const sessionUser = ctx.req.session.user as Record<string, unknown> | undefined;
	const subjectForPolicy =
		typeof sessionUser?.id === "string" ? (sessionUser.id as string) : undefined;
	const { grantPolicy } = ctx.opts;
	if (grantPolicy) {
		// `opts.issuer` is config-only, never request-derived, so decisions
		// match the minted tokens' `iss`. A throw fails closed.
		let answer: unknown;
		try {
			answer = await grantPolicy.evaluate(
				{
					grantType: "authorization_code",
					clientId: ctx.clientId,
					subject: subjectForPolicy,
					requestedScope: requestedScopes.length > 0 ? requestedScopes : undefined,
					originalScope,
					// RFC 8707: `resource` is accepted here and forwarded so the
					// policy can narrow `grantedAudience` before it is persisted;
					// the audience is decided once, keeping `/token` free of policy.
					...(ctx.opts.oauth.resourceIndicatorEnabled && authorizeResource
						? { resource: authorizeResource }
						: {}),
				},
				{
					ip: ctx.req.ip,
					userAgent: ctx.req.get("user-agent"),
					issuer: ctx.opts.issuer,
				},
			);
		} catch (err) {
			// The redirect is the outage's answer at this endpoint; the line is
			// its log, as every grant that consults the policy writes it.
			logGrantPolicyUnavailable(
				ctx.opts.logger,
				{ site: "authorize", grantType: "authorization_code", policy: grantPolicy.kind },
				err,
			);
			const { error, errorDescription } = policyUnavailable();
			redirectError(ctx, error, errorDescription);
			return null;
		}
		const reading = readGrantPolicyDecision(answer, ctx.opts.logger, {
			site: "authorize",
			grantType: "authorization_code",
			policy: grantPolicy.kind,
		});
		if (reading.verdict === "invalid") {
			// Core's answer on the redirect, audited as a failure, not a denial.
			const { error, errorDescription } = reading.result;
			await auditFailure(ctx, { reason: errorDescription });
			redirectError(ctx, error, errorDescription);
			return null;
		}
		if (reading.verdict === "deny") {
			// RFC 6749 §4.1.2.1 makes `error` 1*NQSCHAR. The policy's code goes
			// out as given when it is one; otherwise the redirect says
			// `access_denied` — the authorization server refused — and the code
			// is logged, sanitised, for the operator who wrote the policy; one
			// that is not a string, by its type, as core's `policyDenied` does.
			let error = reading.decision.error;
			if (!isWellFormedErrorCode(error)) {
				const code: unknown = error;
				ctx.opts.logger.warn(
					{ error: auditErrorText(code) ?? `(${typeof code})` },
					"authorize_policy_deny_error_malformed",
				);
				error = "access_denied";
			}
			await auditFailure(ctx, { reason: "policy_denied", error });
			// A description that is empty or not a string is not sent (RFC 6749
			// A.8 makes the field 1*NQSCHAR); the default is.
			redirectError(
				ctx,
				error,
				sanitizeErrorText(reading.decision.errorDescription) || "policy denied",
			);
			return null;
		}
		const { decision } = reading;
		// Presence, not truthiness: `""` and `null` are malformed answers; only
		// `undefined` is "no opinion".
		if (decision.grantedScope !== undefined) {
			if (!Array.isArray(decision.grantedScope)) {
				// A non-array from a JS policy would throw in `.filter`.
				await auditFailure(ctx, POLICY_OUT_OF_BOUNDS);
				redirectError(ctx, "server_error", "policy returned a non-array grantedScope");
				return null;
			}
			// Policy may narrow, never widen, the client's scope ceiling. A scope
			// outside it means a buggy or compromised policy: `server_error`, as
			// every grant answers a policy that exceeds its authority.
			const invalidFromPolicy = decision.grantedScope.filter(
				(s) => !allowedFilteredScopes.includes(s),
			);
			if (invalidFromPolicy.length > 0) {
				await auditFailure(ctx, POLICY_OUT_OF_BOUNDS);
				redirectError(
					ctx,
					"server_error",
					`policy returned scopes outside client allowance: ${invalidFromPolicy.join(" ")}`,
				);
				return null;
			}
			grantedScopes = decision.grantedScope;
		}
		if (decision.grantedAudience !== undefined) {
			// Policy may narrow the audience within the client's ceiling, never
			// originate one: the value is persisted and read back at `/token`
			// without re-checking, so an invented audience would reach a resource
			// server the client was never registered for. `server_error`, as above.
			const bounded = boundPolicyAudience(decision, audienceCeiling);
			if (!bounded.ok) {
				await auditFailure(ctx, POLICY_OUT_OF_BOUNDS);
				redirectError(
					ctx,
					bounded.result.error,
					bounded.result.errorDescription ?? "policy exceeded its audience ceiling",
				);
				return null;
			}
			// The whole list is persisted, as before — every entry has now met
			// the ceiling, and `/token` reads the first.
			grantedAudience = decision.grantedAudience;
		}
	}
	return { grantedScopes, grantedAudience };
};

/**
 * Creates the `GET /authorize` handler: the RFC 6749 §4.1.1 → §4.1.2
 * authorization-code sequence.
 *
 * 1. an unauthenticated browser is sent to log in before any lookup;
 * 2. identify the client and validate `redirect_uri`: the registered list,
 *    then core's `checkRedirectUri` (400 JSON — no trusted redirect target
 *    yet; after step 1, so an unauthenticated browser meets it after login);
 * 3. read the request's shape: request objects and any `response_mode` but
 *    `query` refused, then `prompt`, the single-valued parameters, `claims`,
 *    `max_age` and `acr_values`;
 * 4. admit the session once (`admitSession`): freshness first, then the
 *    verdict — a new login, a step-up trip, a refusal, or on;
 * 5. validate `response_type`, registered grant types, first-party or
 *    consentable, verified email, PKCE (mandatory, S256) and `nonce`;
 * 6. narrow scope (allowlist, openid), ask for consent when not first-party,
 *    apply the grant policy, check RFC 8707 resources;
 * 7. spend the re-authentication ask the request presents, issue the code
 *    and redirect with `code` and `state` (§4.1.2).
 */
export const createAuthorizeHandler = (opts: AuthorizeHandlerOptions): RequestHandler => {
	// The login round-trip target is built from the configured origin, never
	// `req.protocol` + `Host`, which follow forwarded headers under
	// `trust proxy` and would make `redirect_to` an open redirect. Resolved
	// once so an issuer that names no origin fails at composition.
	const issuerOrigin = new URL(opts.issuer).origin;
	// What admission reads for this endpoint: the handler's slots as wired, the
	// resolver, and the vouchable acr table the router computed once.
	const admissionDeps: AdmissionDeps = {
		userSessionStore: opts.userSessionStore,
		sessionLifecycleStore: opts.sessionLifecycleStore,
		subjectRevocation: opts.subjectRevocation,
		requirements: checkResolver(opts.requirements, "createAuthorizeHandler", [AUTHORIZE_ACTION]),
		acrTable: opts.oauth.acrValues,
		logger: opts.logger,
		auditSink: opts.auditSink,
	};
	return async (req: Request, res: Response) => {
		const askStore = reauthAskStoreFor(req);
		const claim = await checkLogin(req, res, opts, issuerOrigin, askStore);
		if (claim === null) return;

		// No early `response_type` gate: once the redirect target is validated,
		// errors redirect so the user lands back in the app (RFC 6749
		// §4.1.2.1). The cost: a bad `response_type` with a real client_id
		// spends one lookup.

		const {
			scope = null,
			state = null,
			code_challenge = null,
			code_challenge_method = null,
		} = authorizeParams(req);

		const resolved = await resolveClientAndRedirectUri(req, res, opts);
		if (!resolved) return;
		const { client } = resolved;

		// From here redirect_uri is validated — use redirect-based errors per RFC 6749 §4.1.2.1
		const ctx: AuthorizeContext = {
			req,
			res,
			opts,
			issuerOrigin,
			clientId: resolved.clientId,
			redirectUri: resolved.redirectUri,
			state: toStr(state),
			params: authorizeParams(req),
		};

		// Request objects are refused before anything interprets the query
		// parameters: those are not the parameters the RP signed.
		if (!checkRequestObjectUnsupported(ctx)) return;
		// Every later answer goes in the query, so a request for another mode
		// is refused before any of them, a re-authentication trip included.
		if (!checkResponseMode(ctx)) return;
		const prompt = resolvePrompt(ctx);
		if (prompt === null) return;
		if (!checkPromptNoneHasSession(ctx, prompt, claim)) return;
		// RFC 6749 §3.1: refuse a repeated single-valued parameter before any of
		// it is interpreted, ahead of re-authentication and every repository or
		// policy call.
		if (!checkSingleValuedParams(ctx)) return;
		// `acr` is asked for through `acr_values` alone; refused before a
		// `prompt=login` or `max_age` sends the browser to log in.
		if (!checkClaimsParameter(ctx)) return;
		const maxAge = parseMaxAge(ctx);
		if (maxAge === null) return;
		const requested = parseAcrValues(ctx);
		if (requested === null) return;
		// One admission per request, after the client and parameters are
		// validated; what each outcome is answered with is `decideOnAdmission`'s.
		const admission = await admitSession(admissionDeps, {
			claim,
			action: AUTHORIZE_ACTION,
			...(requested.length > 0 ? { asks: { acrValues: requested } } : {}),
		});
		const decided = await decideOnAdmission(
			ctx,
			admission,
			prompt,
			maxAge.value,
			requested,
			askStore,
		);
		if (decided === null) return;
		if (!checkResponseTypeIsCode(ctx)) return;
		if (!(await checkAuthorizationCodeGrantAllowed(ctx, client))) return;
		if (!(await checkFirstPartyOrConsentable(ctx, client))) return;
		if (!(await checkEmailVerified(ctx))) return;
		const pkce = checkPkce(ctx, client, code_challenge, code_challenge_method);
		if (!pkce) return;
		if (!checkNonce(ctx)) return;

		const scopes = await resolveScopes(ctx, scope, client);
		if (!scopes) return;

		// A client that is not first-party mints only with the user's recorded
		// consent, asked for on the deployment's page otherwise.
		if (!(await checkConsent(ctx, client, scopes.allowedFilteredScopes, prompt))) return;

		// RFC 8707 §2, read through `authorizeParams` so GET and POST reach the
		// same extractor as the token endpoint (a repeat arrives as an array).
		const authorizeResource = opts.oauth.resourceIndicatorEnabled
			? extractResourceParam(authorizeParams(req))
			: null;

		const policy = await applyGrantPolicy(ctx, {
			requestedScopes: scopes.requestedScopes,
			allowedFilteredScopes: scopes.allowedFilteredScopes,
			originalScope: client.allowedScopes,
			// A client that registers no audiences gives the policy nothing to
			// narrow within.
			audienceCeiling: client.allowedAudiences ?? [],
			authorizeResource,
		});
		if (!policy) return;

		// Persist `undefined` when nothing survived: an empty array would become
		// `scope: ""` in the token response.
		const scopeForPersist = policy.grantedScopes.length > 0 ? policy.grantedScopes : undefined;
		const audience = resolveAudienceForPersist(
			ctx,
			client,
			authorizeResource,
			policy.grantedAudience,
		);
		if (!audience) return;

		if (!(await spendAskAtMint(ctx, askStore, decided.freshByAsk))) return;
		const minted = await mintCode(ctx, {
			// `checkPkce` proved both are present and admissible for this client.
			codeChallenge: toStr(code_challenge),
			codeChallengeMethod: pkce.method,
			grantedScope: scopeForPersist,
			grantedAudience: audience.audienceForPersist,
			acr: decided.acr,
			session: decided.session,
		});
		if (!minted) return;

		return redirectWithCode(ctx, minted.code);
	};
};
