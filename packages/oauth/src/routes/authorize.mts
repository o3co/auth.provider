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
	type AdmissionDeps,
	admitSession,
	auditErrorText,
	boundPolicyAudience,
	type CodeRepository,
	type ConsentStore,
	checkResolver,
	consentCovers,
	deriveAudienceFromResources,
	emitAuditEvent,
	extractResourceParam,
	isWellFormedErrorCode,
	logGrantPolicyUnavailable,
	loggableError,
	type PublicClient,
	readSpaceDelimitedParameter,
	sanitizeErrorText,
	unrepresentedResources,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import type { OAUTH_ROUTER_ADMISSION_ACTIONS } from "../admissionActions.mjs";
import { auditFailure, redirectError } from "./authorizeAnswers.mjs";
import {
	type PromptDirective,
	parseAcrValues,
	parseMaxAge,
	resolvePrompt,
} from "./authorizeAsk.mjs";
import {
	checkAuthorizationCodeGrantAllowed,
	checkFirstPartyOrConsentable,
	resolveClientAndRedirectUri,
} from "./authorizeClient.mjs";
import {
	type AuthorizeContext,
	type AuthorizeHandlerOptions,
	authorizeParams,
	authorizeRequestUrl,
	toStr,
} from "./authorizeContext.mjs";
import {
	checkClaimsParameter,
	checkNonce,
	checkPkce,
	checkRequestObjectUnsupported,
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
import { newConsentChallenge, PENDING_CONSENT_TTL_MS } from "./consent.mjs";
import { reauthAskStoreFor } from "./reauthAsk.mjs";

export { REDIRECT_TO_PARAM } from "./authorizeAsk.mjs";
export type { AuthorizeHandlerOptions } from "./authorizeContext.mjs";
export { authorizeParams } from "./authorizeContext.mjs";

/** The action /authorize admits, as `oauthModule` registers it. */
const AUTHORIZE_ACTION = "oauth.authorize" satisfies keyof typeof OAUTH_ROUTER_ADMISSION_ACTIONS;

/** The end-user the session names, or `null` when it names nobody. */
const subjectOf = (req: Request): string | null => {
	const id = req.session?.user?.id;
	return typeof id === "string" && id.length > 0 ? id : null;
};

/**
 * The authorize request to resume after consent: this request less
 * `prompt=consent`, which the round trip answers — carried back, it would
 * park the request again forever. Other prompt values stay.
 */
const resumeUrl = (ctx: AuthorizeContext): string => {
	const url = authorizeRequestUrl(ctx.issuerOrigin, ctx.req);
	const prompt = url.searchParams.get("prompt");
	// Read as `resolvePrompt` read it; a malformed one was refused there, so
	// it never reaches a consent page to be carried back from.
	const prompts = prompt === null ? null : readSpaceDelimitedParameter(prompt);
	if (prompts !== null) {
		const remaining = prompts.filter((v) => v !== "consent");
		if (remaining.length === 0) {
			url.searchParams.delete("prompt");
		} else {
			url.searchParams.set("prompt", remaining.join(" "));
		}
	}
	return url.toString();
};

/**
 * Consent for a client that is not an explicit `firstParty: true`. Without
 * it, a forced navigation from an attacker's page would make a logged-in
 * victim's browser mint a code for the attacker's chosen `code_challenge`.
 * The user is asked on the deployment's own page and the answer recorded, so
 * covered requests are not asked again. Runs after every request-shape check
 * (no consent for a request that would fail anyway) and before the policy.
 */
const checkConsent = async (
	ctx: AuthorizeContext,
	client: PublicClient,
	scopes: readonly string[],
	prompt: PromptDirective,
): Promise<boolean> => {
	if (client.firstParty === true) return true;
	const store = ctx.opts.consentStore;
	const pendingStore = ctx.opts.pendingConsentStore;
	if (store === undefined || pendingStore === undefined) {
		await auditFailure(ctx, { reason: "client_not_first_party" });
		redirectError(
			ctx,
			"unauthorized_client",
			"client is not authorized for the authorization endpoint",
		);
		return false;
	}
	const sub = subjectOf(ctx.req);
	if (sub === null) {
		await auditFailure(ctx, { reason: "consent_without_subject" });
		redirectError(ctx, "access_denied", "the session names no subject to ask for consent");
		return false;
	}
	let record: Awaited<ReturnType<ConsentStore["find"]>>;
	try {
		record = await store.find(sub, ctx.clientId);
	} catch (err) {
		// An outage is not a decision either way: neither a code nor a refusal
		// the user could act on. The same rule the session-liveness read applies.
		ctx.opts.logger.error(
			{ err: loggableError(err), clientId: ctx.clientId },
			"authorize_consent_store_unavailable",
		);
		redirectError(ctx, "temporarily_unavailable", "consent store unavailable");
		return false;
	}
	if (!prompt.consent && consentCovers(record, scopes)) return true;
	if (prompt.silent) {
		// OIDC Core §3.1.2.6: no interaction was permitted, and interaction is
		// what is needed.
		await auditFailure(ctx, { reason: "consent_required" });
		redirectError(
			ctx,
			"consent_required",
			"prompt=none was requested but the end-user has not consented to this client",
		);
		return false;
	}
	// Park the request under an unguessable, session-bound challenge: the
	// consent page's answer must carry it back, which keeps a forged cross-site
	// POST from answering for the user. Parked in its own record, not on the
	// session (a per-request snapshot), so it can be consumed atomically.
	const sessionId = (ctx.req as { sessionID?: unknown }).sessionID;
	if (typeof sessionId !== "string" || sessionId.length === 0) {
		await auditFailure(ctx, { reason: "consent_without_session_id" });
		redirectError(ctx, "access_denied", "the session has no id to bind the consent request to");
		return false;
	}
	const challenge = newConsentChallenge();
	const createdAt = Date.now();
	try {
		await pendingStore.set({
			challenge,
			sessionId,
			sub,
			clientId: ctx.clientId,
			scopes: [...scopes],
			grantedScopes: record === null ? [] : [...record.scopes],
			authorizeUrl: resumeUrl(ctx),
			redirectUri: ctx.redirectUri,
			state: ctx.state,
			createdAt,
			expiresAt: createdAt + PENDING_CONSENT_TTL_MS,
		});
	} catch (err) {
		// The same rule as the consent-store read above: an outage is not a
		// decision either way.
		ctx.opts.logger.error(
			{ err: loggableError(err), clientId: ctx.clientId },
			"authorize_pending_consent_store_unavailable",
		);
		redirectError(ctx, "temporarily_unavailable", "consent store unavailable");
		return false;
	}
	// `oauth.consentPage.url` may already carry a query string, like the
	// login URL.
	const consentUrl = ctx.opts.consentUrl();
	const joiner = consentUrl.includes("?") ? "&" : "?";
	ctx.res.redirect(`${consentUrl}${joiner}challenge=${encodeURIComponent(challenge)}`);
	return false;
};

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
		let decision: Awaited<ReturnType<typeof grantPolicy.evaluate>>;
		try {
			decision = await grantPolicy.evaluate(
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
			redirectError(ctx, "temporarily_unavailable", "policy evaluation unavailable");
			return null;
		}
		if (decision.outcome === "deny") {
			// RFC 6749 §4.1.2.1 makes `error` 1*NQSCHAR. The policy's code goes
			// out as given when it is one; otherwise the redirect says
			// `access_denied` — the authorization server refused — and the code
			// is logged, sanitised, for the operator who wrote the policy.
			let error = decision.error;
			if (!isWellFormedErrorCode(error)) {
				ctx.opts.logger.warn(
					{ error: auditErrorText(String(error)) },
					"authorize_policy_deny_error_malformed",
				);
				error = "access_denied";
			}
			// A description that is empty or not a string is not sent (RFC 6749
			// A.8 makes the field 1*NQSCHAR); the default is.
			redirectError(ctx, error, sanitizeErrorText(decision.errorDescription) || "policy denied");
			return null;
		}
		// Presence, not truthiness: `""` and `null` are malformed answers; only
		// `undefined` is "no opinion".
		if (decision.grantedScope !== undefined) {
			if (!Array.isArray(decision.grantedScope)) {
				// A non-array from a JS policy would throw in `.filter`.
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
 * RFC 8707 §2 audience shaping for the code record, or `null` when the
 * requested resources cannot be represented and a response has been sent.
 */
const resolveAudienceForPersist = (
	ctx: AuthorizeContext,
	client: PublicClient,
	authorizeResource: readonly string[] | null,
	grantedAudience: readonly string[] | undefined,
): { audienceForPersist: readonly string[] | undefined } | null => {
	// RFC 8707 §2: when a `resource` was requested and no policy narrowed an
	// audience, derive it here, so the audience persisted on the code — which
	// `/token` enforces — is decided exactly once. Bounded by the client's
	// `allowedAudiences` plus its id.
	let effectiveGrantedAudience = grantedAudience;
	if (ctx.opts.oauth.resourceIndicatorEnabled && authorizeResource && !effectiveGrantedAudience) {
		const derived = deriveAudienceFromResources(
			authorizeResource,
			new Set([...(client.allowedAudiences ?? []), ctx.clientId]),
		);
		if (derived !== undefined) effectiveGrantedAudience = [derived];
	}
	const audienceForPersist =
		effectiveGrantedAudience && effectiveGrantedAudience.length > 0
			? effectiveGrantedAudience
			: undefined;

	// RFC 8707 §2: refuse now rather than issue a code `/token` would reject
	// after the user completed the redirect. Mirrors the token endpoint's
	// audience: the persisted one, else the client id.
	if (ctx.opts.oauth.resourceIndicatorEnabled && authorizeResource) {
		const effectiveAudience = audienceForPersist?.[0] ?? ctx.clientId;
		const unrepresented = unrepresentedResources(authorizeResource, effectiveAudience);
		if (unrepresented.length > 0) {
			redirectError(
				ctx,
				"invalid_target",
				`requested_resources_not_in_audience: ${unrepresented.join(" ")}`,
			);
			return null;
		}
	}
	return { audienceForPersist };
};

/**
 * RFC 6749 §4.1.2 code issuance, or `null` after a `temporarily_unavailable`
 * redirect: a code store that cannot answer is the condition §4.1.2.1 names
 * `temporarily_unavailable` for, not `server_error`. Logged once at error
 * level as `authorize_store_unavailable`.
 */
const mintCode = async (
	ctx: AuthorizeContext,
	params: {
		codeChallenge: string | undefined;
		codeChallengeMethod: string | undefined;
		grantedScope: readonly string[] | undefined;
		grantedAudience: readonly string[] | undefined;
		/** The `acr` the session met. */
		acr: string | undefined;
	},
): Promise<{ code: string } | null> => {
	let issue: Awaited<ReturnType<CodeRepository["createCode"]>>;
	try {
		issue = await ctx.opts.codeRepository.createCode({
			client_id: ctx.clientId, // the identity binding lives on the code record
			redirect_uri: ctx.redirectUri, // required: RFC 6749 §4.1.3 compares it at the token endpoint
			code_challenge: params.codeChallenge,
			code_challenge_method: params.codeChallengeMethod,
			grantedScope: params.grantedScope,
			grantedAudience: params.grantedAudience,
			// OIDC round-trip state.
			nonce: typeof ctx.params.nonce === "string" ? ctx.params.nonce : undefined,
			sid: typeof ctx.req.session?.sid === "string" ? ctx.req.session.sid : undefined,
			acr: params.acr,
		});
	} catch (err) {
		ctx.opts.logger.error(
			{
				store: "authorization_code",
				step: "create",
				clientId: ctx.clientId,
				err: loggableError(err),
			},
			"authorize_store_unavailable",
		);
		redirectError(ctx, "temporarily_unavailable", "authorization code store unavailable");
		return null;
	}
	return { code: issue.code };
};

// The code record alone carries the identity binding — no session writes, so
// concurrent requests sharing a session cannot race. `consumeByCode`'s atomic
// read-and-delete is the sole authenticity gate.
const redirectWithCode = async (ctx: AuthorizeContext, code: string): Promise<Response> => {
	const url = new URL(ctx.redirectUri);
	url.searchParams.append("code", code);
	if (typeof ctx.state === "string") {
		url.searchParams.append("state", ctx.state);
	}

	await emitAuditEvent(ctx.opts.auditSink, {
		timestamp: new Date(),
		type: "authorize.granted",
		subject: typeof ctx.req.session.user?.id === "string" ? ctx.req.session.user.id : undefined,
		clientId: ctx.clientId,
		ip: ctx.req.ip,
		userAgent: ctx.req.get("user-agent"),
		details: { response_type: "code" },
	});
	return ctx.res.redirect(url.toString()) as unknown as Response;
};

/**
 * Creates the `GET /authorize` handler: the RFC 6749 §4.1.1 → §4.1.2
 * authorization-code sequence.
 *
 * 1. an unauthenticated browser is sent to log in before any lookup;
 * 2. identify the client and validate `redirect_uri` (400 JSON — no trusted
 *    redirect target yet);
 * 3. read the request's shape: request objects refused, then `prompt`, the
 *    single-valued parameters, `claims`, `max_age` and `acr_values`;
 * 4. admit the session once (`admitSession`): freshness first, then the
 *    verdict — a new login, a step-up trip, a refusal, or on;
 * 5. validate `response_type`, registered grant types, first-party or
 *    consentable, verified email, PKCE (mandatory, S256) and `nonce`;
 * 6. narrow scope (allowlist, openid), ask for consent when not first-party,
 *    apply the grant policy, check RFC 8707 resources;
 * 7. issue the code and redirect with `code` and `state` (§4.1.2).
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
		subjectRevocation: opts.subjectRevocation,
		requirements: checkResolver(opts.requirements, "createAuthorizeHandler", [AUTHORIZE_ACTION]),
		acrTable: opts.oauth.acrValues,
		logger: opts.logger,
		auditSink: opts.auditSink,
	};
	return async (req: Request, res: Response) => {
		const claim = checkLogin(req, res, opts, issuerOrigin);
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
			reauthAskStoreFor(req),
		);
		if (decided === null) return;
		if (!checkResponseTypeIsCode(ctx)) return;
		if (!(await checkAuthorizationCodeGrantAllowed(ctx, client))) return;
		if (!(await checkFirstPartyOrConsentable(ctx, client))) return;
		if (!(await checkEmailVerified(ctx))) return;
		const pkce = checkPkce(ctx, client, code_challenge, code_challenge_method);
		if (!pkce) return;
		if (!checkNonce(ctx)) return;

		const scopes = resolveScopes(ctx, scope, client);
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

		const minted = await mintCode(ctx, {
			// `checkPkce` proved both are present and admissible for this client.
			codeChallenge: toStr(code_challenge),
			codeChallengeMethod: pkce.method,
			grantedScope: scopeForPersist,
			grantedAudience: audience.audienceForPersist,
			acr: decided.acr,
		});
		if (!minted) return;

		return redirectWithCode(ctx, minted.code);
	};
};
