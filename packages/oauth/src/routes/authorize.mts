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
	type AuditSink,
	type ClientRepository,
	type CodeRepository,
	emitAuditEvent,
	type GrantPolicyHook,
	isEmailVerified,
	isGrantTypeAllowed,
	type Logger,
	type PublicClient,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import {
	deriveAudienceFromResources,
	extractResourceParam,
	unrepresentedResources,
} from "../grants/_resourceIndicator.mjs";
import {
	PKCE_METHOD_ABSENT_DEFAULT,
	PKCE_METHOD_S256,
	pkceMethodsForClient,
} from "../grants/pkce.mjs";
import type { ResolvedOAuthOptions } from "../resolveOAuthOptions.mjs";

export interface AuthorizeHandlerOptions {
	readonly clientRepository: ClientRepository;
	readonly codeRepository: CodeRepository;
	readonly grantPolicy?: GrantPolicyHook;
	readonly auditSink?: AuditSink;
	readonly logger: Logger;
	/**
	 * CP-11: the canonical issuer, config-only — never request-derived (the
	 * Host header is attacker-controlled in many deployments).
	 */
	readonly issuer: string;
	/**
	 * Login-page URL for unauthenticated sessions. A thunk, evaluated per
	 * request exactly as the inline handler read `config.endpoints.login.url`,
	 * so a hand-built config missing the key fails at the same point (request
	 * time) it always did — `oauthModule`'s configSchema is what turns the
	 * missing key into a boot failure for schema-validated deployments.
	 */
	readonly loginUrl: () => string;
	/** The `oauth.*` knobs, resolved once at router composition (#328). */
	readonly oauth: ResolvedOAuthOptions;
}

/**
 * Per-request state threaded through the §4.1 steps below. Constructed only
 * after `resolveClientAndRedirectUri` validated `redirect_uri` against the
 * client allowlist, so holding it is itself the proof that redirect-based
 * errors (RFC 6749 §4.1.2.1) are permitted.
 */
interface AuthorizeContext {
	readonly req: Request;
	readonly res: Response;
	readonly opts: AuthorizeHandlerOptions;
	readonly clientId: string;
	readonly redirectUri: string;
	/** Verbatim `state` when it was a single string; echoed on every response. */
	readonly state: string | undefined;
}

const toStr = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

// A-1: RFC 6749 §4.1.2.1 — errors that prevent redirect (invalid client / redirect_uri)
// must return 400 JSON. Other errors redirect with error params.
const redirectError = (
	ctx: AuthorizeContext,
	error: string,
	errorDescription: string,
): Response => {
	const url = new URL(ctx.redirectUri);
	url.searchParams.append("error", error);
	url.searchParams.append("error_description", errorDescription);
	if (typeof ctx.state === "string") url.searchParams.append("state", ctx.state);
	return ctx.res.redirect(url.toString()) as unknown as Response;
};

/**
 * Emits the `authorize.rejected` audit event every rejected authorization
 * request shares — the payload shape (clientId / ip / userAgent /
 * `details.reason`) matches the token endpoint's `token.issued.failure`, but
 * the name is this endpoint's own: /authorize mints codes, not tokens, and
 * its success event is `authorize.granted` (#329).
 */
const auditFailure = (ctx: AuthorizeContext, details: Record<string, unknown>): Promise<void> =>
	emitAuditEvent(ctx.opts.auditSink, {
		timestamp: new Date(),
		type: "authorize.rejected",
		clientId: ctx.clientId,
		ip: ctx.req.ip,
		userAgent: ctx.req.get("user-agent"),
		details,
	});

/**
 * RFC 6749 §4.1.1 identification: `client_id` / `redirect_uri` presence, the
 * client lookup, and the `redirect_uri` allowlist. Everything here fails as
 * 400/500 JSON (A-1) because no trusted redirect target exists yet.
 *
 * Returns `null` when a response has been sent.
 */
const resolveClientAndRedirectUri = async (
	req: Request,
	res: Response,
	opts: AuthorizeHandlerOptions,
): Promise<{ client: PublicClient; clientId: string; redirectUri: string } | null> => {
	const { client_id = null, redirect_uri = null } = req.query;

	// A-1: invalid client_id and redirect_uri → 400 JSON (cannot redirect)
	if (typeof client_id !== "string" || !client_id) {
		res.status(400).json({ error: "invalid_request", error_description: "client_id is required" });
		return null;
	}

	if (typeof redirect_uri !== "string" || !redirect_uri) {
		res
			.status(400)
			.json({ error: "invalid_request", error_description: "redirect_uri is required" });
		return null;
	}

	let client: PublicClient | null;
	try {
		client = await opts.clientRepository.findById(client_id);
	} catch {
		res.status(500).json({ error: "server_error", error_description: "Failed to fetch client" });
		return null;
	}
	if (!client) {
		// Cannot redirect — client unknown, redirect_uri untrusted
		res.status(400).json({ error: "invalid_client", error_description: "client not found" });
		return null;
	}

	if (!client.allowedRedirectUris.includes(redirect_uri)) {
		// Cannot redirect — redirect_uri not trusted
		res
			.status(400)
			.json({ error: "invalid_request", error_description: "redirect_uri not allowed" });
		return null;
	}

	return { client, clientId: client_id, redirectUri: redirect_uri };
};

// A-1: validate response_type (the handler already dispatched on
// includes("code"), but handle unknown types such as `?response_type=code&
// response_type=token`, which Express surfaces as an array).
const checkResponseTypeIsCode = (ctx: AuthorizeContext): boolean => {
	const responseType = toStr(ctx.req.query.response_type);
	if (responseType !== "code") {
		redirectError(
			ctx,
			"unsupported_response_type",
			`response_type "${responseType}" is not supported`,
		);
		return false;
	}
	return true;
};

// #268: the code flow leads to `grant_type=authorization_code` at
// the token endpoint, so a client not registered for it must be
// turned away here rather than after the user has authenticated
// and a code has been minted. `redirect_uri` is validated above,
// so RFC 6749 §4.1.2.1 puts this error in the redirect.
const checkAuthorizationCodeGrantAllowed = async (
	ctx: AuthorizeContext,
	client: PublicClient,
): Promise<boolean> => {
	if (isGrantTypeAllowed(client.allowedGrantTypes, "authorization_code")) return true;
	await auditFailure(ctx, { reason: "grant_type_not_allowed", grant_type: "authorization_code" });
	redirectError(
		ctx,
		"unauthorized_client",
		"client is not authorized for the authorization_code grant",
	);
	return false;
};

// #267: `/authorize` mints a code as soon as the session is
// authenticated, with no consent step. A forced top-level
// navigation from an attacker's page therefore makes a logged-in
// victim's browser mint a code, bound to the victim's session and
// delivered to the named client's registered `redirect_uri` —
// and since the attacker chose the `code_challenge`, they redeem
// it. That is defensible in a pure first-party OP and only there.
//
// The assumption is now enforced instead of assumed. This does
// not make the endpoint safe against forced navigation for a
// client that *is* first-party; it stops a client that should
// never have been trusted with a silent code from being
// registered into that position. Consent (#284) is the step that
// changes the former.
const checkFirstPartyInvariant = async (
	ctx: AuthorizeContext,
	client: PublicClient,
): Promise<boolean> => {
	// Anything that is not an explicit `true` is refused — a
	// registration with no `firstParty` field and one carrying
	// `false` alike. The one-time migration flag that admitted
	// unmarked registrations (`oauth.authorize.allowUnmarkedClients`,
	// #317) was removed in #330: the config schema rejects a config
	// still setting it, and this handler no longer reads it, so
	// there is no permissive path left.
	if (client.firstParty === true) return true;
	await auditFailure(ctx, { reason: "client_not_first_party" });
	redirectError(
		ctx,
		"unauthorized_client",
		"client is not authorized for the authorization endpoint",
	);
	return false;
};

// #297: refuse before a code is minted when the deployment requires
// a verified email and the Store has not published one for this
// user. `/authorize` and the `session` grant are the two points
// that hold the user's session at issuance; `refresh_token` and
// token-exchange derive from an artifact that already passed this
// gate, so re-checking there would revoke a session mid-life on a
// Store hiccup rather than gate its creation.
//
// `access_denied` is the RFC 6749 §4.1.2.1 code for "the resource
// owner or authorization server denied the request", which is
// exactly what this is — and unlike `invalid_request` it does not
// suggest the client sent something malformed.
const checkEmailVerified = async (ctx: AuthorizeContext): Promise<boolean> => {
	if (!(ctx.opts.oauth.requireEmailVerified && !isEmailVerified(ctx.req.session.user))) return true;
	await auditFailure(ctx, { reason: "email_not_verified" });
	redirectError(ctx, "access_denied", "email address is not verified");
	return false;
};

/**
 * #273 (OAuth 2.1 §4.1.1 / RFC 9700 §2.1.1): PKCE gate + method resolution,
 * as one step.
 *
 * Pre-#273 this was two functions running either side of scope narrowing and
 * policy evaluation — a presence check here, an allowlist check after the
 * policy hook — with three different rules between them (a public-client
 * S256 mandate, an operator `pkce.required` flag, an operator
 * `supportedMethods` allowlist with a `defaultMethod` fallback). They are one
 * rule now, applied to every client:
 *
 * 1. a `code_challenge` is REQUIRED — confidential clients included, because a
 *    client secret proves who is redeeming the code, not that the redeemer is
 *    the party it was issued to;
 * 2. the method is `S256`, unless this client's registration opts into `plain`
 *    (`pkceMethodsForClient`).
 *
 * Running the allowlist check here rather than after `applyGrantPolicy` also
 * means an unsupported method is refused before the policy hook's external
 * I/O, matching the `checkNonce` placement rationale.
 */
const checkPkce = (
	ctx: AuthorizeContext,
	client: PublicClient,
	codeChallenge: unknown,
	codeChallengeMethod: unknown,
): { method: string } | null => {
	// The resolved policy object — the SAME one the authorization grant reads
	// at `/token`. `required` is `true` by construction (see
	// `ResolvedPkceOptions`); it is read rather than assumed so both endpoints
	// demonstrably consult one value.
	const policy = ctx.opts.oauth.pkce;
	if (policy.required && (typeof codeChallenge !== "string" || !codeChallenge)) {
		redirectError(ctx, "invalid_request", "code_challenge is required");
		return null;
	}
	// `toStr` yields undefined for a repeated `?code_challenge_method=` too
	// (Express surfaces it as an array), which then resolves as absent —
	// i.e. as `plain` — and is refused unless this client opted in.
	const requestedMethod = toStr(codeChallengeMethod);
	const method = requestedMethod ?? PKCE_METHOD_ABSENT_DEFAULT;
	if (!pkceMethodsForClient(policy, client).includes(method)) {
		redirectError(
			ctx,
			"invalid_request",
			requestedMethod === undefined
				? `code_challenge_method is required and must be "${PKCE_METHOD_S256}"`
				: `code_challenge_method "${requestedMethod}" is not supported`,
		);
		return null;
	}
	return { method };
};

// IH-16 (v0.5.1): bound the OIDC `nonce` query parameter BEFORE the
// scope/policy block runs. Pre-fix the value was stored on the code
// record + echoed verbatim into the id_token, letting a malicious
// RP exhaust per-request memory or amplify the token payload with a
// multi-megabyte string. The 256-char ceiling is operator-tunable
// via `oauth.nonce.maxLength` (default in core HOCON, env-var
// `OAUTH_NONCE_MAX_LENGTH`). Errors use `redirectError` because
// `redirect_uri` is already validated against the client allowlist
// at this point — RFC 6749 §4.1.2.1 requires error redirects from
// here on.
//
// Placement (Claude review fixup): the gate runs BEFORE
// `grantPolicy.evaluate()` so an oversized nonce cannot trigger
// external policy I/O (Redis lookup / HTTP call) before the cheap
// length+character-set check rejects the request. Moving the gate
// any earlier than this is unsafe — it must follow `redirect_uri`
// validation so errors can use `redirectError`.
const checkNonce = (ctx: AuthorizeContext): boolean => {
	const nonceMaxLength = ctx.opts.oauth.nonceMaxLength;
	if (ctx.req.query.nonce === undefined) return true;
	// Reject non-string `nonce` (Copilot review on PR #126):
	// Express + qs parses repeated `?nonce=a&nonce=b` as an
	// array, which silently failed the previous
	// `typeof === "string"` gate, causing the request to
	// proceed with `nonce: undefined` on the issued code. The
	// client's downstream OIDC nonce check would then fail
	// long after `/authorize` returned 302 + code, surfacing
	// as a confusing client-side error. Reject as
	// `invalid_request` immediately so the failure is at the
	// request boundary, not asynchronously at id_token
	// validation time.
	if (typeof ctx.req.query.nonce !== "string") {
		redirectError(ctx, "invalid_request", "nonce must be a single string value");
		return false;
	}
	const nonceValue = ctx.req.query.nonce;
	if (nonceValue.length > nonceMaxLength) {
		redirectError(ctx, "invalid_request", `nonce exceeds maximum length of ${nonceMaxLength}`);
		return false;
	}
	// Printable ASCII only (0x20-0x7E). Non-printable input could
	// confuse downstream JWT libraries that don't escape control
	// chars in JSON payloads. OIDC Core §3.1.2.1 leaves the
	// alphabet unconstrained; this is a defensive narrowing.
	if (!/^[\x20-\x7E]*$/.test(nonceValue)) {
		redirectError(ctx, "invalid_request", "nonce contains non-printable characters");
		return false;
	}
	return true;
};

/**
 * RFC 6749 §3.3 scope narrowing plus the IH-6 openid requirement. Returns the
 * requested scopes and the client-allowlist-filtered set the policy step takes
 * as its ceiling, or `null` when a response has been sent.
 */
const resolveScopes = (
	ctx: AuthorizeContext,
	scope: unknown,
	allowedScopes: readonly string[],
): { requestedScopes: string[]; allowedFilteredScopes: readonly string[] } | null => {
	const requestedScopes = toStr(scope)?.split(" ").filter(Boolean) ?? [];
	const allowedFilteredScopes =
		requestedScopes.length > 0
			? requestedScopes.filter((s) => allowedScopes.includes(s))
			: allowedScopes;
	// #328: the openid-scope gate used to also test issuer presence
	// (`isActingAsOidcProvider`), suggesting issuer-less operation was a
	// supported mode. It is not: router construction throws when
	// `oauth.jwt.issuer` is missing or malformed (#266/#307), so by the time
	// a request reaches this handler the server is always acting as an OIDC
	// OP and `oidcMode` alone decides.
	if (
		ctx.opts.oauth.oidcMode === "oidc-required" &&
		// Two failure modes both undermine "OIDC required":
		//   (a) the request itself omits openid;
		//   (b) the request includes openid but the client allowlist
		//       filters it out — without checking the filtered set
		//       the request would silently proceed as OAuth-only
		//       even though the server is configured oidc-required.
		(!requestedScopes.includes("openid") || !allowedFilteredScopes.includes("openid"))
	) {
		ctx.opts.logger.warn(
			{
				clientId: ctx.clientId,
				requestedScopes,
				allowedFilteredScopes,
			},
			"authorize_rejected_missing_openid_scope",
		);
		redirectError(
			ctx,
			"invalid_scope",
			"openid scope is required when server is acting as an OIDC OP",
		);
		return null;
	}
	if (allowedFilteredScopes.length === 0 && requestedScopes.length > 0) {
		redirectError(ctx, "invalid_scope", "no requested scopes are allowed for this client");
		return null;
	}
	return { requestedScopes, allowedFilteredScopes };
};

// C-2: policy evaluation at /authorize (evaluate-once, persist on Code).
// The code exchange MUST NOT re-evaluate — it reads the narrowed values off
// Code.grantedScope / Code.grantedAudience. This prevents scope escalation
// via a crafted /token request after /authorize decided the narrow.
const applyGrantPolicy = async (
	ctx: AuthorizeContext,
	inputs: {
		requestedScopes: string[];
		allowedFilteredScopes: readonly string[];
		/** The client's full allowlist — the policy's `originalScope`. */
		originalScope: readonly string[];
		authorizeResource: readonly string[] | null;
	},
): Promise<{
	grantedScopes: readonly string[];
	grantedAudience: readonly string[] | undefined;
} | null> => {
	const { requestedScopes, allowedFilteredScopes, originalScope, authorizeResource } = inputs;
	let grantedScopes: readonly string[] = allowedFilteredScopes;
	let grantedAudience: readonly string[] | undefined;
	const sessionUser = ctx.req.session.user as Record<string, unknown> | undefined;
	const subjectForPolicy =
		typeof sessionUser?.id === "string" ? (sessionUser.id as string) : undefined;
	const { grantPolicy } = ctx.opts;
	if (grantPolicy) {
		// CP-11: issuer must NOT be request-derived (Host header is
		// attacker-controlled in many deployments). `opts.issuer` is the
		// router's canonical issuer — config-only — so policy decisions match
		// the issuer claim on minted tokens.
		// CP-18 (authorize side): fail-closed on policy throw. Same
		// rationale as the refresh_token path — policy is a security
		// boundary and failing open would hand out the pre-policy
		// scope ceiling.
		let decision: Awaited<ReturnType<typeof grantPolicy.evaluate>>;
		try {
			decision = await grantPolicy.evaluate(
				{
					grantType: "authorization_code",
					clientId: ctx.clientId,
					subject: subjectForPolicy,
					requestedScope: requestedScopes.length > 0 ? requestedScopes : undefined,
					originalScope,
					// RFC 8707 Stage 2 (#173): `resource` is accepted at the
					// AUTHORIZATION endpoint for this flow and forwarded here,
					// so the policy can narrow `grantedAudience` to the
					// requested target before it is persisted on the code.
					// This is what keeps the token endpoint free of policy:
					// the audience decision happens once, here (C-2 / D-1).
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
		} catch {
			redirectError(ctx, "temporarily_unavailable", "policy evaluation unavailable");
			return null;
		}
		if (decision.outcome === "deny") {
			redirectError(ctx, decision.error, decision.errorDescription ?? "policy denied");
			return null;
		}
		if (decision.grantedScope) {
			// CP-13: policy MUST NOT expand the client's scope ceiling.
			// Enforce grantedScope ⊆ allowedFilteredScopes (the
			// pre-policy-narrowed set) — a policy returning a scope
			// outside this is a bug or a compromised policy, and we
			// fail closed with invalid_scope per RFC 6749.
			const invalidFromPolicy = decision.grantedScope.filter(
				(s) => !allowedFilteredScopes.includes(s),
			);
			if (invalidFromPolicy.length > 0) {
				redirectError(
					ctx,
					"invalid_scope",
					`policy returned scopes outside client allowance: ${invalidFromPolicy.join(" ")}`,
				);
				return null;
			}
			grantedScopes = decision.grantedScope;
		}
		if (decision.grantedAudience) grantedAudience = decision.grantedAudience;
	}
	return { grantedScopes, grantedAudience };
};

/**
 * RFC 8707 §2 audience shaping for the code record (Stage 2, #173), or `null`
 * when the requested resources cannot be represented and a response has been
 * sent.
 */
const resolveAudienceForPersist = (
	ctx: AuthorizeContext,
	client: PublicClient,
	authorizeResource: readonly string[] | null,
	grantedAudience: readonly string[] | undefined,
): { audienceForPersist: readonly string[] | undefined } | null => {
	// RFC 8707 §2 audience derivation (Stage 2, #173). When a `resource`
	// was requested and no policy narrowed an audience, derive it here so
	// the value persisted on the code — which the token endpoint reads and
	// enforces against — already reflects the request. Deriving at
	// `/authorize` rather than `/token` is what keeps the audience decided
	// exactly once (C-2 / D-1). Bounded by the client's allowedAudiences
	// plus its own id, the same ceiling a policy-returned audience meets.
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

	// RFC 8707 §2 (Stage 2, #173): reject here rather than issuing a code
	// that is already doomed. The token endpoint applies the same check
	// against the persisted audience, so a code whose audience cannot
	// represent the requested resource would fail there anyway — after the
	// user has completed the redirect. Failing at `/authorize` surfaces
	// `invalid_target` while the client can still act on it, which is where
	// RFC 8707 §2 places the error for this endpoint.
	//
	// The effective audience mirrors the token endpoint's derivation: the
	// persisted audience when the policy narrowed one, else the client id
	// (the `authorization_code` default).
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

/** RFC 6749 §4.1.2 code issuance, or `null` after a `server_error` redirect. */
const mintCode = async (
	ctx: AuthorizeContext,
	params: {
		codeChallenge: string | undefined;
		codeChallengeMethod: string | undefined;
		grantedScope: readonly string[] | undefined;
		grantedAudience: readonly string[] | undefined;
	},
): Promise<{ code: string } | null> => {
	let issue: Awaited<ReturnType<CodeRepository["createCode"]>>;
	try {
		issue = await ctx.opts.codeRepository.createCode({
			client_id: ctx.clientId, // D-1: identity binding embedded in the code record (replaces session.code_client_id)
			redirect_uri: ctx.redirectUri, // D-1: required field (closes IH-4 vacuous-pass)
			code_challenge: params.codeChallenge,
			code_challenge_method: params.codeChallengeMethod,
			grantedScope: params.grantedScope,
			grantedAudience: params.grantedAudience,
			// NEW (TODO-F-3): OIDC round-trip state on the code record.
			nonce: typeof ctx.req.query.nonce === "string" ? ctx.req.query.nonce : undefined,
			sid: typeof ctx.req.session?.sid === "string" ? ctx.req.session.sid : undefined,
		});
	} catch {
		redirectError(ctx, "server_error", "Failed to create authorization code");
		return null;
	}
	return { code: issue.code };
};

// D-1 / CR-2: identity binding lives in the code record only — no
// session writes. Concurrent /authorize requests sharing a session
// previously raced on `req.session.code` last-write-wins; the
// losing request's code became unredeemable. consumeByCode (atomic
// getDel on a single Redis node) is now the sole authenticity gate.
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
 * Creates the `GET /authorize` handler — the RFC 6749 §4.1.1 → §4.1.2
 * authorization-code sequence, one step per concern:
 *
 * 1. authenticate the resource owner (redirect to login) — the #325
 *    rate-limit guard runs before this handler, mounted as sibling
 *    middleware on the route;
 * 2. identify the client and validate `redirect_uri` (§4.1.1; 400 JSON —
 *    no trusted redirect target yet, per A-1);
 * 3. validate the request: `response_type`, the client's registered grant
 *    types (#268), the first-party invariant (#267), the email-verified
 *    gate (#297), PKCE — mandatory, S256 (#273) — `nonce` bounds (IH-16);
 * 4. narrow scope and audience: client allowlist + openid requirement
 *    (IH-6), then policy (C-2), then the RFC 8707 resource check;
 * 5. issue the code and redirect back with `code` + `state` (§4.1.2).
 *
 * Extracted from the inline `routes.mts` closure in #328 with behavior
 * intentionally identical: same checks, same order, same error responses,
 * same audit payloads.
 */
export const createAuthorizeHandler = (opts: AuthorizeHandlerOptions): RequestHandler => {
	return async (req: Request, res: Response) => {
		if (!req.session.isAuthenticated) {
			return res.redirect(
				`${opts.loginUrl()}?redirect_to=${encodeURIComponent(`${req.protocol}://${req.get("host")}${req.originalUrl}`)}`,
			);
		}

		if (![req.query.response_type].flat().includes("code")) {
			// A-1: unknown response_type without a validated redirect_uri → 400 JSON
			return res.status(400).json({
				error: "unsupported_response_type",
				error_description: `response_type "${req.query.response_type}" is not supported`,
			});
		}

		const {
			scope = null,
			state = null,
			code_challenge = null,
			code_challenge_method = null,
		} = req.query;

		const resolved = await resolveClientAndRedirectUri(req, res, opts);
		if (!resolved) return;
		const { client } = resolved;

		// From here redirect_uri is validated — use redirect-based errors per RFC 6749 §4.1.2.1
		const ctx: AuthorizeContext = {
			req,
			res,
			opts,
			clientId: resolved.clientId,
			redirectUri: resolved.redirectUri,
			state: toStr(state),
		};

		if (!checkResponseTypeIsCode(ctx)) return;
		if (!(await checkAuthorizationCodeGrantAllowed(ctx, client))) return;
		if (!(await checkFirstPartyInvariant(ctx, client))) return;
		if (!(await checkEmailVerified(ctx))) return;
		const pkce = checkPkce(ctx, client, code_challenge, code_challenge_method);
		if (!pkce) return;
		if (!checkNonce(ctx)) return;

		const scopes = resolveScopes(ctx, scope, client.allowedScopes);
		if (!scopes) return;

		// RFC 8707 §2 at the authorization endpoint (Stage 2, #173). Read
		// from the query string here — `/authorize` is a GET — using the
		// same extractor the token endpoint uses, so a repeated
		// `?resource=` (which Express surfaces as an array) is handled
		// identically on both endpoints.
		const authorizeResource = opts.oauth.resourceIndicatorEnabled
			? extractResourceParam(req.query as Record<string, unknown>)
			: null;

		const policy = await applyGrantPolicy(ctx, {
			requestedScopes: scopes.requestedScopes,
			allowedFilteredScopes: scopes.allowedFilteredScopes,
			originalScope: client.allowedScopes,
			authorizeResource,
		});
		if (!policy) return;

		// CP-14: persist `undefined` when no scopes/audiences survived —
		// an empty array would later stringify to `scope: ""` in the
		// token response, which is indistinguishable from "scope claim
		// omitted" and surprises consumers.
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
		});
		if (!minted) return;

		return redirectWithCode(ctx, minted.code);
	};
};
