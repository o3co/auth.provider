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
	boundPolicyAudience,
	buildCanonicalRequestUrl,
	type ClientRepository,
	type CodeRepository,
	type ConsentStore,
	consentCovers,
	emitAuditEvent,
	type GrantPolicyHook,
	isEmailVerified,
	isGrantTypeAllowed,
	type Logger,
	matchesRegisteredRedirectUri,
	type PendingConsentStore,
	type PublicClient,
	type UserSession,
	type UserSessionStore,
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
import { newConsentChallenge, PENDING_CONSENT_TTL_MS } from "./consent.mjs";

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
	/**
	 * Consent-page URL for a client that is not first-party (#527). A thunk
	 * like `loginUrl`, for the same reason.
	 */
	readonly consentUrl: () => string;
	/**
	 * #527: where consent records live. Optional: without it a client that is
	 * not first-party is refused, exactly as before the slot existed.
	 */
	readonly consentStore?: ConsentStore;
	/**
	 * #552: where a request is parked while the consent page asks. Wired
	 * with `consentStore` — the router refuses one without the other.
	 */
	readonly pendingConsentStore?: PendingConsentStore;
	/** The `oauth.*` knobs, resolved once at router composition (#328). */
	readonly oauth: ResolvedOAuthOptions;
	/**
	 * R1b: the durable session store, so an express-session claiming
	 * authentication can be checked against the `UserSession` record its `sid`
	 * names. Optional for the same reason it is optional on the router: a
	 * deployment without session-backed login has no record to check, and this
	 * endpoint must keep working for it exactly as before.
	 */
	readonly userSessionStore?: UserSessionStore;
}

/**
 * R1b — does the express-session's `sid` still name a live `UserSession`?
 *
 * `isAuthenticated` is a claim the browser's cookie makes; the `UserSession`
 * record is the fact. `/oauth/logout`'s cascade deletes the record, and a
 * store can also lose it to a restart or an out-of-band delete — after which
 * this endpoint went on minting codes carrying a dead `sid` that `/token`
 * refused with `invalid_grant`, leaving the browser in a login loop it was
 * never shown a login page to escape. This is the same read `/token` already
 * performs at redemption, moved to the point where "log in again" is still an
 * available answer.
 *
 * Returns `true` — authentication stands — in the two cases where there is
 * nothing to check: no store wired, or a session that recorded no `sid`
 * (a deployment whose login wiring predates it). Neither is evidence of a
 * dead session, and refusing them would revoke authentication from every such
 * deployment.
 *
 * A store that cannot answer fails CLOSED. Minting a code is an authorization
 * decision, and an outage is not a reason to make it: the caller lands on the
 * login page (or gets `login_required`), which is recoverable, rather than
 * holding a code bound to a session nobody can vouch for.
 *
 * Callers MUST short-circuit on `isAuthenticated` first, so a genuinely
 * unauthenticated request still answers without touching any repository
 * (#284) — this function is only reached once the session claims otherwise.
 */
/**
 * The live `UserSession` behind the request's `sid`, when this composition
 * wires a store (#481 widened it from a boolean: `max_age`, `prompt=login`
 * and `acr_values` all read the record, not just its presence).
 *
 * `live: true, session: null` is the no-store composition — authenticated
 * on the cookie's word alone, with no `auth_time` to reason about.
 */
const readLiveSession = async (
	req: Request,
	opts: AuthorizeHandlerOptions,
): Promise<{ readonly live: boolean; readonly session: UserSession | null }> => {
	const store = opts.userSessionStore;
	const sid = typeof req.session?.sid === "string" ? req.session.sid : undefined;
	if (!store || sid === undefined) return { live: true, session: null };
	try {
		const session = await store.get(sid);
		return { live: session != null, session };
	} catch (err) {
		opts.logger.warn({ err, sid }, "authorize_session_liveness_unavailable");
		return { live: false, session: null };
	}
};

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
	/** The configured issuer's origin — what a parked request's URL is built from. */
	readonly issuerOrigin: string;
	readonly clientId: string;
	readonly redirectUri: string;
	/** Verbatim `state` when it was a single string; echoed on every response. */
	readonly state: string | undefined;
	/**
	 * The request's parameters — query string on GET, form body on POST.
	 * Carried on the context so every check reads the same object regardless
	 * of how the request arrived (#284).
	 */
	readonly params: Record<string, unknown>;
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
	const { client_id = null, redirect_uri = null } = authorizeParams(req);

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

	// #483: exact string equality, except that a `http:` loopback IP literal on
	// both sides is compared with the port dropped — a native app's listener
	// binds an ephemeral port the registration cannot name (RFC 8252 §7.3).
	// `localhost` and `https:` get no carve-out. The PRESENTED URI is what is
	// carried forward and bound to the code record, so the token endpoint's
	// §4.1.3 equality check still compares the URI actually used.
	if (
		!client.allowedRedirectUris.some((entry) => matchesRegisteredRedirectUri(entry, redirect_uri))
	) {
		// Cannot redirect — redirect_uri not trusted
		res
			.status(400)
			.json({ error: "invalid_request", error_description: "redirect_uri not allowed" });
		return null;
	}

	return { client, clientId: client_id, redirectUri: redirect_uri };
};

// The sole owner of the response_type refusal since #397 — it runs after
// `resolveClientAndRedirectUri`, so the refusal travels via redirect per
// RFC 6749 §4.1.2.1 (A-1's rule that nothing redirects to an unvalidated
// target holds; validation has already succeeded here). Handles unknown
// types and repeats such as `?response_type=code&response_type=token`,
// which Express surfaces as an array.
const checkResponseTypeIsCode = (ctx: AuthorizeContext): boolean => {
	const raw = ctx.params.response_type;
	if (toStr(raw) !== "code") {
		// The description names what actually arrived — a missing parameter and
		// a repeated one are different client bugs, and `"undefined"` in quotes
		// (the old rendering of both) pointed at neither.
		const description =
			raw === undefined
				? "response_type is required"
				: Array.isArray(raw)
					? "response_type must not be included more than once"
					: `response_type ${JSON.stringify(String(raw))} is not supported`;
		redirectError(ctx, "unsupported_response_type", description);
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
	if (
		isGrantTypeAllowed(client.allowedGrantTypes, "authorization_code", {
			requireAllowlist: ctx.opts.oauth.requireGrantTypeAllowlist,
		})
	)
		return true;
	await auditFailure(ctx, { reason: "grant_type_not_allowed", grant_type: "authorization_code" });
	redirectError(
		ctx,
		"unauthorized_client",
		"client is not authorized for the authorization_code grant",
	);
	return false;
};

// #267 / #527: a client that is not first-party is served only through the
// consent step, so with no consent store wired it is refused here — the #267
// refusal, in the position it always had (ahead of the request-shape gates),
// so what such a deployment answers does not change.
const checkFirstPartyOrConsentable = async (
	ctx: AuthorizeContext,
	client: PublicClient,
): Promise<boolean> => {
	if (client.firstParty === true || ctx.opts.consentStore !== undefined) return true;
	await auditFailure(ctx, { reason: "client_not_first_party" });
	redirectError(
		ctx,
		"unauthorized_client",
		"client is not authorized for the authorization endpoint",
	);
	return false;
};

/** The end-user the session names, or `null` when it names nobody. */
const subjectOf = (req: Request): string | null => {
	const id = req.session?.user?.id;
	return typeof id === "string" && id.length > 0 ? id : null;
};

// #267 / #527: `/authorize` mints a code as soon as the session is
// authenticated — for a first-party client. That is the accepted model for a
// client the deployment operates, and only there: a forced top-level
// navigation from an attacker's page makes a logged-in victim's browser mint
// a code, bound to the victim's session, delivered to the named client's
// registered `redirect_uri`, and since the attacker chose the
// `code_challenge` they redeem it. Consent is the step that changes that,
// and it is what every other client goes through: the user is asked, on the
// deployment's own page, before a code is minted, and what they answered is
// recorded so they are not asked again for what they already allowed.
//
// Anything that is not an explicit `firstParty: true` goes through it — a
// registration with no field and one carrying `false` alike (the one-time
// migration flag that admitted unmarked registrations, #317, was removed in
// #330). Without a consent store there is no way to ask, and the refusal
// #267 introduced stands: an operator who wants to serve a third-party
// client wires `consentStore` rather than marking the client first-party.
//
// Runs after every request-shape check and before the policy hook: a user
// is not asked to consent to a request that would fail anyway, and the
// policy sees the request only once the user has allowed it.
/**
 * The authorize request to come back to once the consent page has an
 * answer.
 *
 * Not `req.originalUrl`, for two reasons the review found (#527). A POST
 * carries its parameters in the body — `authorizeParams` reads them from
 * there — so the URL alone names no client, no `redirect_uri`, no PKCE, and
 * the resumed request would be a different, invalid one; the parameters are
 * written back into the query of the URL the browser returns to. And
 * `prompt=consent` is answered by this very round trip: carried back, it
 * would park the request again, forever. Every other prompt value is left
 * alone — `login` has its own one-shot marker (#481).
 */
const resumeUrl = (ctx: AuthorizeContext): string => {
	const url = new URL(buildCanonicalRequestUrl(ctx.issuerOrigin, ctx.req.originalUrl));
	url.search = "";
	for (const [name, value] of Object.entries(authorizeParams(ctx.req))) {
		if (typeof value === "string") {
			url.searchParams.append(name, value);
		} else if (Array.isArray(value)) {
			for (const item of value) {
				if (typeof item === "string") url.searchParams.append(name, item);
			}
		}
	}
	const prompt = url.searchParams.get("prompt");
	if (prompt !== null) {
		const remaining = prompt.split(" ").filter((v) => v.length > 0 && v !== "consent");
		if (remaining.length === 0) {
			url.searchParams.delete("prompt");
		} else {
			url.searchParams.set("prompt", remaining.join(" "));
		}
	}
	return url.toString();
};

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
		ctx.opts.logger.error({ err, clientId: ctx.clientId }, "authorize_consent_store_unavailable");
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
	// Park the request under an unguessable challenge and hand the browser to
	// the deployment's page. The challenge is what the page's answer carries
	// back, and being session-bound and unreadable cross-site it is the
	// synchronizer token that keeps a forged POST from answering for the user.
	//
	// #552: in a record of its own, not on the session. The session is a
	// per-request snapshot, so a field on it cannot be consumed atomically
	// across two answers in flight; the record names the session that parked
	// it, which is what keeps the challenge session-bound.
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
			...(ctx.state === undefined ? {} : { state: ctx.state }),
			createdAt,
			expiresAt: createdAt + PENDING_CONSENT_TTL_MS,
		});
	} catch (err) {
		// The same rule as the consent-store read above: an outage is not a
		// decision either way.
		ctx.opts.logger.error(
			{ err, clientId: ctx.clientId },
			"authorize_pending_consent_store_unavailable",
		);
		redirectError(ctx, "temporarily_unavailable", "consent store unavailable");
		return false;
	}
	// `endpoints.consent.url` may already carry a query string, like the
	// login URL.
	const consentUrl = ctx.opts.consentUrl();
	const joiner = consentUrl.includes("?") ? "&" : "?";
	ctx.res.redirect(`${consentUrl}${joiner}challenge=${encodeURIComponent(challenge)}`);
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
	// at `/token`. The challenge requirement is unconditional for the reason
	// given there: `ResolvedPkceOptions.required` is the literal `true`, so
	// gating on it would be a branch with no reachable other path. The shared
	// runtime read is `pkceMethodsForClient(policy, client)` below.
	const policy = ctx.opts.oauth.pkce;
	if (typeof codeChallenge !== "string" || !codeChallenge) {
		redirectError(ctx, "invalid_request", "code_challenge is required");
		return null;
	}
	// `checkSingleValuedParams` already refused a repeated parameter, so
	// `toStr` yielding undefined here means genuinely absent — which RFC 7636
	// §4.3 defines as `plain`, and which is then refused unless this client
	// opted in. (Before that gate existed, a repeat also landed here and was
	// silently read as `plain`; see SINGLE_VALUED_QUERY_PARAMS.)
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

/**
 * The `/authorize` query parameters RFC 6749 §3.1 defines as single-valued
 * ("Request and response parameters MUST NOT be included more than once").
 *
 * Express + `qs` surfaces a repeated `?p=a&p=b` as an ARRAY (and `?p[k]=v` as
 * an object), while every read in this file narrows a non-string to
 * `undefined` — the same shape *absence* produces. Without this gate a
 * repeated parameter is therefore read as "not sent", which is a different
 * request from the one the client made, and in three places that difference
 * was wrong rather than merely surprising:
 *
 * - **`code_challenge_method`** fell through to RFC 7636 §4.3's `plain`
 *   default. A client the operator opted into `plain` (`allowPlainPkce`)
 *   could downgrade its own S256 request by sending the parameter twice —
 *   the AS minted a `plain` code, no S256 verifier was ever computed, and
 *   nothing about the request looked malformed. That is the instance
 *   Copilot flagged on #350.
 * - **`scope`** became "no scope requested", which does not narrow — it
 *   widens the grant to the client's entire registered allowlist.
 * - **`state`** was dropped from the response, so the client's CSRF check
 *   failed silently instead of the request failing loudly.
 *
 * Two parameters are deliberately NOT in the list:
 *
 * - `response_type` is already refused by `checkResponseTypeIsCode` with
 *   `unsupported_response_type`, the code RFC 6749 §4.1.2.1 defines for it.
 *   Sweeping it in here would replace a specific error with a generic one.
 * - `resource` is defined as **repeatable** by RFC 8707 §2, so rejecting a
 *   repeat would break a conformant client. `extractResourceParam` validates
 *   its elements instead.
 *
 * `client_id` and `redirect_uri` are absent for a different reason: they are
 * single-valued too, but they are validated in the pre-redirect phase where
 * the correct answer is `400` JSON, not a redirect — a `redirect_uri` we
 * could not read is precisely one we must not redirect to (A-1).
 *
 * `nonce` is absent for a third reason: `checkNonce` already owns it, and has
 * since IH-16 — it rejects a repeat with this exact message and then applies
 * the length and character-set bounds. Listing it here as well would give one
 * parameter two owners and make the check inside `checkNonce` unreachable,
 * which is dead code rather than defence in depth. One owner per parameter;
 * this gate is for the ones that had none.
 */
const SINGLE_VALUED_QUERY_PARAMS = [
	"scope",
	"state",
	"code_challenge",
	"code_challenge_method",
	// #481
	"max_age",
	"acr_values",
	"reauth_after",
] as const;

/**
 * Refuses a repeated single-valued parameter at the request boundary, before
 * any of it is interpreted. The message is per-parameter and matches the
 * wording IH-16 already used for `nonce`, which this gate now owns for the
 * whole class.
 */
/**
 * The authorization request's parameters, wherever this request carried them.
 *
 * OIDC Core §3.1.2.1: *"Authorization Servers MUST support the use of the HTTP
 * GET and POST methods"*. A POST carries the same parameters in a
 * form-encoded body — the parameter names, the single-valued rule and every
 * check below are identical, so the only thing that differs is which object
 * they are read from, and reading it in one place is what keeps a check from
 * silently applying to GET alone (#284).
 *
 * Express's `qs` surfaces a repeated parameter as an array from either source,
 * so `checkSingleValuedParams` covers both without knowing which it got.
 */
export const authorizeParams = (req: Request): Record<string, unknown> =>
	req.method === "POST"
		? ((req.body ?? {}) as Record<string, unknown>)
		: (req.query as Record<string, unknown>);

/**
 * OIDC Core §3.1.2.1 `prompt` (#284).
 *
 * `none` is the one that matters and the one whose absence broke standard RP
 * libraries: silent renewal asks for a token without user interaction and
 * expects `login_required` when there is no session. Answering with the login
 * page instead — which is what happened before — hands an HTML redirect to a
 * hidden iframe, where it does nothing and produces a timeout rather than an
 * error the RP can act on.
 *
 * `consent` is honoured since #527: for a client that is not first-party it
 * forces the consent page even when a record already covers the request; for
 * a first-party client it is a no-op, since the deployment operates that
 * client and there is nothing to consent to.
 *
 * Every other value is **refused**, not ignored, and each for its own reason:
 *
 * - `select_account` — there is no account picker. Ignoring it would hand
 *   back a token the RP believes was freshly account-picked.
 * - `login` — forcing re-authentication needs a way to know that it just
 *   happened, or the user returns from the login page with the same
 *   `prompt=login` and goes round again. That marker is `auth_time`, which
 *   arrives with `max_age`; until then a looping implementation would be worse
 *   than an honest refusal.
 *
 * `invalid_request` naming the value is the answer — OIDC Core defines no
 * "prompt value unsupported" code, and inventing one would put a non-standard
 * error where an RP expects a standard one.
 *
 * Returns the resolved directive, or `null` when it has already answered.
 */
type PromptDirective = {
	readonly silent: boolean;
	readonly login: boolean;
	readonly consent: boolean;
};

const NO_PROMPT: PromptDirective = { silent: false, login: false, consent: false };

const resolvePrompt = (ctx: AuthorizeContext): PromptDirective | null => {
	const raw = ctx.params.prompt;
	if (raw === undefined) return NO_PROMPT;
	if (typeof raw !== "string") {
		redirectError(ctx, "invalid_request", "prompt must be a single string value");
		return null;
	}
	// §3.1.2.1: a space-delimited list. `none` may not be combined with any
	// other value — "if this parameter contains none with any other value, an
	// error is returned".
	const values = raw.split(" ").filter((v) => v.length > 0);
	if (values.length === 0) return NO_PROMPT;
	if (values.includes("none") && values.length > 1) {
		redirectError(ctx, "invalid_request", "prompt=none cannot be combined with other values");
		return null;
	}
	// #481: `login` is honoured — see `evaluateReauthentication`.
	// #527: so is `consent` — see `checkConsent`.
	const unsupported = values.filter((v) => v !== "none" && v !== "login" && v !== "consent");
	if (unsupported.length > 0) {
		redirectError(
			ctx,
			"invalid_request",
			`prompt values not supported: ${unsupported.join(" ")} — this authorization server ` +
				"has no account picker",
		);
		return null;
	}
	return {
		silent: values.includes("none"),
		login: values.includes("login"),
		consent: values.includes("consent"),
	};
};

/**
 * #481 — `max_age` (OIDC Core §3.1.2.1): the seconds since the End-User's
 * authentication that the RP will accept. A non-negative integer, or a
 * refusal; absent means no constraint.
 */
const parseMaxAge = (ctx: AuthorizeContext): { readonly value: number | undefined } | null => {
	const raw = ctx.params.max_age;
	if (raw === undefined) return { value: undefined };
	if (typeof raw !== "string" || !/^[0-9]+$/.test(raw)) {
		redirectError(ctx, "invalid_request", "max_age must be a non-negative integer");
		return null;
	}
	return { value: Number(raw) };
};

/**
 * #481 — the marker this endpoint puts on the authorize URL it sends the
 * browser back to when it asks for a re-authentication: the epoch second
 * of the ask. On the way back, a session authenticated at or after it is
 * the re-authentication that was asked for; one authenticated before it is
 * not, and gets `login_required` instead of a second round trip. Only
 * this server ever writes it, and it decides nothing an RP relies on —
 * `auth_time` in the id_token is what the RP verifies.
 */
const REAUTH_MARKER_PARAM = "reauth_after";

const readReauthMarker = (ctx: AuthorizeContext): number | undefined => {
	const raw = ctx.params[REAUTH_MARKER_PARAM];
	return typeof raw === "string" && /^[0-9]+$/.test(raw) ? Number(raw) : undefined;
};

type ReauthOutcome = "proceed" | "login" | "answered";

/**
 * #481 — decide whether the session's authentication is fresh enough.
 *
 * `prompt=login` and a `max_age` the session's `auth_time` is older than
 * both mean "re-authenticate". The first time through, the browser is sent
 * to the login page with the request round-tripped and the marker set —
 * unless the RP asked for `prompt=none`, in which case the only honest
 * answer is `login_required`. When the marker is already on the request the
 * user has been to the login page: a session authenticated after the ask
 * satisfies both `prompt=login` and any `max_age` (it is as fresh as this
 * request), and one that was not is refused with `login_required` rather
 * than looped.
 */
const evaluateReauthentication = (
	ctx: AuthorizeContext,
	prompt: PromptDirective,
	maxAge: number | undefined,
	session: UserSession | null,
): ReauthOutcome => {
	if (!prompt.login && maxAge === undefined) return "proceed";
	if (session === null) {
		// No UserSessionStore in this composition: there is no `auth_time` to
		// measure against, and pretending would be the silent acceptance the
		// parameters exist to prevent.
		redirectError(
			ctx,
			"invalid_request",
			"max_age and prompt=login need a user session store, which this deployment does not wire",
		);
		return "answered";
	}
	const nowSeconds = Math.floor(Date.now() / 1000);
	const authTimeSeconds = Math.floor(session.authTime.getTime() / 1000);
	const marker = readReauthMarker(ctx);
	if (marker !== undefined) {
		if (authTimeSeconds >= marker) return "proceed";
		redirectError(
			ctx,
			"login_required",
			"re-authentication was requested but the session was not re-established",
		);
		return "answered";
	}
	const stale = maxAge !== undefined && nowSeconds - authTimeSeconds > maxAge;
	if (!prompt.login && !stale) return "proceed";
	if (prompt.silent) {
		redirectError(
			ctx,
			"login_required",
			"the session is older than max_age and prompt=none forbids re-authenticating",
		);
		return "answered";
	}
	return "login";
};

/**
 * #481 — `acr_values` (OIDC Core §3.1.2.1) against the configured table
 * (`oauth.authorize.acrValues`): the first requested value whose `amr`
 * requirement the session's recorded `amr` covers is the `acr` the code —
 * and so the id_token — carries. None satisfied, or a value this
 * deployment never configured, is `unmet_authentication_requirements`
 * rather than a token the RP would read as meeting its requirement.
 */
const resolveAcr = (
	ctx: AuthorizeContext,
	session: UserSession | null,
): { readonly value: string | undefined } | null => {
	const raw = ctx.params.acr_values;
	if (raw === undefined) return { value: undefined };
	const requested = typeof raw === "string" ? raw.split(" ").filter((v) => v.length > 0) : [];
	if (requested.length === 0) return { value: undefined };
	const table = ctx.opts.oauth.acrValues;
	const held = new Set(session?.amr ?? []);
	// `Object.hasOwn` rather than a bare read, and not only because
	// `resolveOAuthOptions` now builds the table without a prototype:
	// `ResolvedOAuthOptions` is exported, so a composition may hand in a
	// plain object, and the value being looked up is one an unauthenticated
	// caller writes.
	const entryFor = (acr: string): readonly string[] | undefined =>
		Object.hasOwn(table, acr) ? table[acr] : undefined;
	for (const acr of requested) {
		const required = entryFor(acr);
		if (required?.every((method) => held.has(method))) {
			return { value: acr };
		}
	}
	const unknown = requested.filter((acr) => entryFor(acr) === undefined);
	redirectError(
		ctx,
		"unmet_authentication_requirements",
		unknown.length > 0
			? `acr_values not configured on this authorization server: ${unknown.join(" ")}`
			: `the session's authentication does not satisfy any requested acr: ${requested.join(" ")}`,
	);
	return null;
};

/**
 * Refuse the request-object parameters this AS does not implement (#284).
 *
 * OIDC Core defines `request_not_supported` and `request_uri_not_supported`
 * for exactly this, and the reason to answer rather than ignore is security,
 * not tidiness. A signed request object exists to make the parameters
 * tamper-proof; an AS that ignores it and processes the query string instead
 * gives an attacker precisely what the request object was there to prevent,
 * while the RP believes its signed request was honoured. Silence is the worst
 * of the three options.
 *
 * The discovery document says the same thing in its own vocabulary —
 * `request_uri_parameter_supported: false` is emitted because OIDC Discovery
 * defaults that field to **true** when omitted, so saying nothing claimed
 * support for `request_uri`. Same shape #283 found in `grant_types_supported`.
 */
const checkRequestObjectUnsupported = (ctx: AuthorizeContext): boolean => {
	if (ctx.params.request !== undefined) {
		redirectError(
			ctx,
			"request_not_supported",
			"this authorization server does not accept request objects",
		);
		return false;
	}
	if (ctx.params.request_uri !== undefined) {
		redirectError(
			ctx,
			"request_uri_not_supported",
			"this authorization server does not accept request_uri",
		);
		return false;
	}
	return true;
};

const checkSingleValuedParams = (ctx: AuthorizeContext): boolean => {
	for (const name of SINGLE_VALUED_QUERY_PARAMS) {
		const value = ctx.params[name];
		if (value === undefined || typeof value === "string") continue;
		redirectError(ctx, "invalid_request", `${name} must be a single string value`);
		return false;
	}
	return true;
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
	if (ctx.params.nonce === undefined) return true;
	// Reject a `nonce` that is not a single string (Copilot review on
	// PR #126). This is the sole owner of the rule for this
	// parameter — `SINGLE_VALUED_QUERY_PARAMS` deliberately omits
	// `nonce` so that this check stays reachable rather than
	// becoming an unexercisable duplicate of the gate.
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
	if (typeof ctx.params.nonce !== "string") {
		redirectError(ctx, "invalid_request", "nonce must be a single string value");
		return false;
	}
	const nonceValue = ctx.params.nonce;
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
 *
 * Narrowing is kept, deliberately (#396): §3.3 sanctions ignoring scopes the
 * client is not registered for, and the honesty half — the token response's
 * `scope` member naming what WAS granted whenever it differs — is pinned by
 * test. The omitted-scope default is not kept: it granted the client's entire
 * allowlist, making "forgot to send scope" the maximum grant. An omitted
 * scope now draws on the client's declared `defaultScopes`, and a client that
 * declares none answers `invalid_scope` — deny-by-absence, the #326/#363
 * shape. The one carve-out: a client whose allowlist is EMPTY keeps the empty
 * grant, because there is nothing to over-grant and scope-less deployments
 * are a supported shape.
 */
const resolveScopes = (
	ctx: AuthorizeContext,
	scope: unknown,
	client: PublicClient,
): { requestedScopes: string[]; allowedFilteredScopes: readonly string[] } | null => {
	const allowedScopes = client.allowedScopes;
	const requestedScopes = toStr(scope)?.split(" ").filter(Boolean) ?? [];
	let allowedFilteredScopes: readonly string[];
	if (requestedScopes.length > 0) {
		allowedFilteredScopes = requestedScopes.filter((s) => allowedScopes.includes(s));
	} else if (client.defaultScopes !== undefined) {
		// Filtered through the allowlist even so: schema-validated registrations
		// are ⊆ allowedScopes by boot (#396's superRefine), but a custom
		// ClientRepository is under no such obligation.
		allowedFilteredScopes = client.defaultScopes.filter((s) => allowedScopes.includes(s));
	} else if (allowedScopes.length === 0) {
		allowedFilteredScopes = [];
	} else {
		void auditFailure(ctx, { reason: "scope_omitted_without_default" });
		redirectError(ctx, "invalid_scope", "scope is required: this client declares no defaultScopes");
		return null;
	}
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
		/**
		 * #520: the audiences this grant may mint for — the client's
		 * `allowedAudiences`, or an empty ceiling when it registers none.
		 * Policy may narrow within it, never originate outside it.
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
		// Presence, not truthiness: `""` and `null` are a policy saying
		// something malformed, not a policy saying nothing, and only
		// `undefined` is "no opinion" (#521).
		if (decision.grantedScope !== undefined) {
			if (!Array.isArray(decision.grantedScope)) {
				// #521: a non-array from a JS policy would throw in `.filter`.
				redirectError(ctx, "server_error", "policy returned a non-array grantedScope");
				return null;
			}
			// CP-13: policy MUST NOT expand the client's scope ceiling.
			// Enforce grantedScope ⊆ allowedFilteredScopes (the
			// pre-policy-narrowed set) — a policy returning a scope
			// outside this is a bug or a compromised policy. Fail closed
			// with `server_error` (RFC 6749 §4.1.2.1), the answer every
			// grant gives a policy that exceeds its authority (#520): the
			// request was fine, the deployment's policy was not.
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
			// #520: the same ceiling `client_credentials`, jwt-bearer and the
			// WebAuthn grant apply, through the same home — a policy may narrow
			// the grant's audience and may not originate one. `/authorize` used
			// to check only the shape, and nothing re-bounds the value at
			// `/token`: it is persisted on the code and read back there, so an
			// audience a buggy or compromised policy invented would reach a
			// resource server the client was never registered for. Refused as
			// `server_error` (the redirect shape of `policyOutOfBounds`): the
			// deployment's policy exceeded its authority, the caller did not.
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
	// plus its own id; a policy-returned audience met the client's
	// allowedAudiences in `applyGrantPolicy` before it got here (#520).
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
		/** #481 */
		acr?: string | undefined;
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
			nonce: typeof ctx.params.nonce === "string" ? ctx.params.nonce : undefined,
			sid: typeof ctx.req.session?.sid === "string" ? ctx.req.session.sid : undefined,
			...(params.acr !== undefined ? { acr: params.acr } : {}),
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
	// #356: the login round-trip target is built from the deployment's
	// configured origin plus `req.originalUrl` — never `req.protocol` +
	// `Host`, which follow `X-Forwarded-Proto` / the client's `Host` under
	// `trust proxy` and made `redirect_to` an open redirect the caller aims.
	// Same door #292 closed for the DPoP htu; `buildCanonicalRequestUrl`
	// (core/src/net/request-url.mts) is the shared vocabulary. Resolved once
	// here so a hand-built config whose issuer cannot name an origin fails at
	// composition, not per request (`checkCanonicalIssuer` already vouched for
	// schema-validated deployments at router creation).
	const issuerOrigin = new URL(opts.issuer).origin;
	return async (req: Request, res: Response) => {
		// #284: `prompt=none` asks for a token *without* user interaction, so
		// the login redirect below is exactly what it must not get — a hidden
		// iframe cannot act on an HTML page, and the RP sees a timeout instead
		// of an error. Such a request falls through to have its client and
		// `redirect_uri` validated, so `login_required` can be delivered where
		// the RP is listening for it.
		//
		// The gate opens for any `prompt` list that names `none`, including
		// the combinations §3.1.2.1 forbids (`prompt=none login`). That is
		// deliberate, not slack: such a request still comes from a silent
		// context, so answering it with a login page hangs the same hidden
		// iframe, and its `invalid_request` belongs at the RP's
		// `redirect_uri` — which cannot be trusted until it is validated,
		// which costs the lookup. Every other unauthenticated request still
		// answers before touching the repository, which is what keeps an
		// unauthenticated endpoint from doing a lookup per hit.
		const promptRaw = authorizeParams(req).prompt;
		const wantsSilentAuth =
			typeof promptRaw === "string" &&
			promptRaw
				.split(" ")
				.filter((v) => v.length > 0)
				.includes("none");

		// R1b: one liveness read per authenticated request, resolved here so
		// both the login redirect below and the `prompt=none` refusal further
		// down answer from the same fact. The `&&` short-circuits, which is
		// what keeps the anonymous path free of the store read.
		// The store is read only for a session that claims to be authenticated —
		// a genuinely anonymous request costs no lookup (R1b).
		const liveSession = req.session.isAuthenticated
			? await readLiveSession(req, opts)
			: { live: false, session: null };
		const authenticated = Boolean(req.session.isAuthenticated) && liveSession.live;

		if (!authenticated && !wantsSilentAuth) {
			// `endpoints.login.url` may already carry a query string (e.g.
			// `/login?tenant=x`), so `redirect_to` joins with `&` there and `?`
			// otherwise — a second `?` would corrupt both parameters.
			const loginUrl = opts.loginUrl();
			const joiner = loginUrl.includes("?") ? "&" : "?";
			return res.redirect(
				`${loginUrl}${joiner}redirect_to=${encodeURIComponent(buildCanonicalRequestUrl(issuerOrigin, req.originalUrl))}`,
			);
		}

		// #397: no early response_type gate. RFC 6749 §4.1.2.1 prefers that once
		// the client and redirect_uri ARE validated, errors travel via redirect
		// so the user lands back in the app — and the pre-validation 400-JSON
		// gate that used to sit here made that unreachable for this error class.
		// A-1's trust rule is untouched: `resolveClientAndRedirectUri` still
		// answers 400 JSON whenever the redirect target cannot be validated, and
		// nothing redirects before it succeeds. `checkResponseTypeIsCode` (after
		// validation) is now the sole owner of the response_type refusal. The
		// accepted cost: a garbage response_type with a real client_id spends one
		// repository lookup before its refusal — the price of having a validated
		// target to redirect the user back to.

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

		// #284: the request-object refusal runs before anything interprets the
		// query parameters, because the whole point is that those parameters
		// are not the ones the RP signed.
		if (!checkRequestObjectUnsupported(ctx)) return;
		const prompt = resolvePrompt(ctx);
		if (prompt === null) return;
		if (prompt.silent && !authenticated) {
			// OIDC Core §3.1.2.6. Now that `redirect_uri` is validated this
			// reaches the RP's own listener rather than a login page it cannot
			// use.
			redirectError(
				ctx,
				"login_required",
				"prompt=none was requested but no end-user session is present",
			);
			return;
		}
		// RFC 6749 §3.1: refuse a repeated single-valued parameter before any of
		// it is interpreted — a repeat read as absence is a different request
		// from the one the client sent. This runs ahead of the re-authentication
		// evaluation as well as the client-policy gates: a repeated
		// `reauth_after` read as "no marker" would send a stale session to the
		// login page, whose redirect rebuilds the URL with one server-written
		// marker, and the request would then succeed where it should have been
		// refused. A malformed request never reaches the repository or the
		// policy hook either.
		if (!checkSingleValuedParams(ctx)) return;
		// #481: is the authentication fresh enough for what the RP asked?
		const maxAge = parseMaxAge(ctx);
		if (maxAge === null) return;
		const reauth = evaluateReauthentication(ctx, prompt, maxAge.value, liveSession.session);
		if (reauth === "answered") return;
		if (reauth === "login") {
			const back = new URL(buildCanonicalRequestUrl(issuerOrigin, req.originalUrl));
			back.searchParams.set(REAUTH_MARKER_PARAM, String(Math.floor(Date.now() / 1000)));
			const loginUrl = opts.loginUrl();
			const joiner = loginUrl.includes("?") ? "&" : "?";
			return res.redirect(`${loginUrl}${joiner}redirect_to=${encodeURIComponent(back.toString())}`);
		}
		const acr = resolveAcr(ctx, liveSession.session);
		if (acr === null) return;
		if (!checkResponseTypeIsCode(ctx)) return;
		if (!(await checkAuthorizationCodeGrantAllowed(ctx, client))) return;
		if (!(await checkFirstPartyOrConsentable(ctx, client))) return;
		if (!(await checkEmailVerified(ctx))) return;
		const pkce = checkPkce(ctx, client, code_challenge, code_challenge_method);
		if (!pkce) return;
		if (!checkNonce(ctx)) return;

		const scopes = resolveScopes(ctx, scope, client);
		if (!scopes) return;

		// #527: a client that is not first-party mints only with the user's
		// recorded consent — asked for on the deployment's page otherwise.
		if (!(await checkConsent(ctx, client, scopes.allowedFilteredScopes, prompt))) return;

		// RFC 8707 §2 at the authorization endpoint (Stage 2, #173). Read
		// through `authorizeParams`, so a GET's query string and a POST's
		// form body reach the same extractor the token endpoint uses and a
		// repeated `resource` (which Express surfaces as an array) is
		// handled identically on every endpoint and method.
		const authorizeResource = opts.oauth.resourceIndicatorEnabled
			? extractResourceParam(authorizeParams(req))
			: null;

		const policy = await applyGrantPolicy(ctx, {
			requestedScopes: scopes.requestedScopes,
			allowedFilteredScopes: scopes.allowedFilteredScopes,
			originalScope: client.allowedScopes,
			// #520: the same `?? []` the sibling grants pass — a client that
			// registers no audiences gives the policy nothing to narrow within.
			audienceCeiling: client.allowedAudiences ?? [],
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
			acr: acr.value,
		});
		if (!minted) return;

		return redirectWithCode(ctx, minted.code);
	};
};
