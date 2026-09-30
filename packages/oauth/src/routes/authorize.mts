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
	type AuditSink,
	admitSession,
	auditErrorList,
	auditErrorText,
	boundPolicyAudience,
	buildCanonicalRequestUrl,
	type ClientRepository,
	type CodeRepository,
	type ConsentStore,
	checkResolver,
	consentCovers,
	cookieClaim,
	deriveAudienceFromResources,
	describeAdmissionOutage,
	emitAuditEvent,
	extractResourceParam,
	type GrantPolicyHook,
	isEmailVerified,
	isGrantTypeAllowed,
	isWellFormedClientId,
	isWellFormedErrorCode,
	LOGIN_RETURN_PARAMETER,
	type Logger,
	type LoginEntry,
	logClientRepositoryUnavailable,
	logGrantPolicyUnavailable,
	loggableError,
	matchesRegisteredRedirectUri,
	type PendingConsentStore,
	type PublicClient,
	parseScopeTokens,
	readSpaceDelimitedParameter,
	type SessionRequirementResolver,
	type SubjectRevocation,
	sanitizeErrorText,
	type UserSession,
	type UserSessionStore,
	unrepresentedResources,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import type { OAUTH_ROUTER_ADMISSION_ACTIONS } from "../admissionActions.mjs";
import {
	PKCE_METHOD_ABSENT_DEFAULT,
	PKCE_METHOD_S256,
	pkceMethodsForClient,
} from "../grants/pkce.mjs";
import type { ResolvedOAuthOptions } from "../resolveOAuthOptions.mjs";
import { newConsentChallenge, PENDING_CONSENT_TTL_MS } from "./consent.mjs";
import {
	REAUTH_ASK_PARAM,
	type ReauthAskRecord,
	type ReauthAskStore,
	reauthAskStoreFor,
} from "./reauthAsk.mjs";

/** The action /authorize admits, as `oauthModule` registers it. */
const AUTHORIZE_ACTION = "oauth.authorize" satisfies keyof typeof OAUTH_ROUTER_ADMISSION_ACTIONS;

export interface AuthorizeHandlerOptions {
	readonly clientRepository: ClientRepository;
	readonly codeRepository: CodeRepository;
	readonly grantPolicy?: GrantPolicyHook;
	readonly auditSink?: AuditSink;
	readonly logger: Logger;
	/** The canonical issuer, config-only: never request-derived (Host is attacker-controlled). */
	readonly issuer: string;
	/**
	 * The login trip for a browser that must log in: `urlFor(returnTo)` is the
	 * login page with the request to come back to — the `loginEntry` slot's.
	 */
	readonly login: Pick<LoginEntry, "urlFor">;
	/**
	 * Consent-page URL for a client that is not first-party. A thunk, evaluated
	 * per request.
	 */
	readonly consentUrl: () => string;
	/** Where consent records live. Without it a client that is not first-party is refused. */
	readonly consentStore?: ConsentStore;
	/**
	 * Where a request is parked while the consent page asks. Wired with
	 * `consentStore`; the router refuses one without the other.
	 */
	readonly pendingConsentStore?: PendingConsentStore;
	/** The `oauth.*` knobs, resolved once at router composition. */
	readonly oauth: ResolvedOAuthOptions;
	/**
	 * The durable session store admission reads the cookie's session from.
	 * Without it (no session-backed login) admission decides on the cookie alone.
	 */
	readonly userSessionStore?: UserSessionStore;
	/**
	 * The subject-revocation boundary admission applies to the live record: a
	 * session established before the subject's sessions were revoked is refused
	 * here too, not only at the token side.
	 */
	readonly subjectRevocation?: SubjectRevocation;
	/**
	 * The registered session requirements admission asks about. Required: a
	 * handler built without one is refused.
	 */
	readonly requirements: SessionRequirementResolver;
}

/**
 * The parameter this endpoint adds to a page it sends the browser to, naming
 * the request to come back to: core's `LOGIN_RETURN_PARAMETER`, which the
 * login page and a requirement's step-up page both read. The login page's own
 * URL may not carry it (core's `LoginEntry` contract).
 */
export const REDIRECT_TO_PARAM = LOGIN_RETURN_PARAMETER;

/** The login-page redirect with the request to come back to. */
const loginRedirect = (res: Response, login: Pick<LoginEntry, "urlFor">, target: string): void => {
	res.redirect(login.urlFor(target));
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
	 * The request's parameters — query string on GET, form body on POST — so
	 * every check reads the same object however the request arrived.
	 */
	readonly params: Record<string, unknown>;
}

const toStr = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

// RFC 6749 §4.1.2.1: errors that prevent redirect (invalid client or
// redirect_uri) are 400 JSON; the rest redirect with error params. The same
// section limits `error_description`'s characters, and several descriptions
// echo client input, so it is sanitised here once.
const redirectError = (
	ctx: AuthorizeContext,
	error: string,
	errorDescription: string,
): Response => {
	const url = new URL(ctx.redirectUri);
	url.searchParams.append("error", error);
	url.searchParams.append("error_description", sanitizeErrorText(errorDescription));
	if (typeof ctx.state === "string") url.searchParams.append("state", ctx.state);
	return ctx.res.redirect(url.toString()) as unknown as Response;
};

/**
 * Emits `authorize.rejected`, with the payload shape of the token endpoint's
 * `token.issued.failure`; the success event is `authorize.granted`.
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
 * RFC 6749 §4.1.1 identification: `client_id`/`redirect_uri` presence, client
 * lookup and the `redirect_uri` allowlist. Everything here answers 400/503
 * JSON because no trusted redirect target exists yet. A malformed `client_id`
 * is answered as unknown and never reaches the repository (which may throw on
 * it); a repository that throws is `503 temporarily_unavailable`.
 *
 * Returns `null` when a response has been sent.
 */
const resolveClientAndRedirectUri = async (
	req: Request,
	res: Response,
	opts: AuthorizeHandlerOptions,
): Promise<{ client: PublicClient; clientId: string; redirectUri: string } | null> => {
	const { client_id = null, redirect_uri = null } = authorizeParams(req);

	// Invalid client_id or redirect_uri → 400 JSON (cannot redirect).
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

	if (!isWellFormedClientId(client_id)) {
		res.status(400).json({ error: "invalid_client", error_description: "client not found" });
		return null;
	}

	let client: PublicClient | null;
	try {
		client = await opts.clientRepository.findById(client_id);
	} catch (err) {
		// The client's id is its own input: recorded sanitised and capped.
		logClientRepositoryUnavailable(
			opts.logger,
			{ site: "authorize", step: "find", clientId: client_id },
			err,
		);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "client repository unavailable",
		});
		return null;
	}
	if (!client) {
		// Cannot redirect — client unknown, redirect_uri untrusted
		res.status(400).json({ error: "invalid_client", error_description: "client not found" });
		return null;
	}

	// Exact string equality, except that an `http:` loopback IP literal on both
	// sides is compared without the port — a native app's listener binds an
	// ephemeral port the registration cannot name (RFC 8252 §7.3). `localhost`
	// and `https:` get no carve-out. The PRESENTED URI is bound to the code, so
	// the token endpoint's §4.1.3 equality check compares the URI actually used.
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

// Runs after the redirect target is validated, so the refusal redirects (RFC
// 6749 §4.1.2.1). Also refuses a repeat, which Express surfaces as an array.
const checkResponseTypeIsCode = (ctx: AuthorizeContext): boolean => {
	const raw = ctx.params.response_type;
	if (toStr(raw) !== "code") {
		// Names what arrived: a missing and a repeated parameter are different
		// client bugs. Quoted with `'`, as `redirectError` holds the text to
		// RFC 6749's character set.
		const description =
			raw === undefined
				? "response_type is required"
				: Array.isArray(raw)
					? "response_type must not be included more than once"
					: `response_type '${String(raw)}' is not supported`;
		redirectError(ctx, "unsupported_response_type", description);
		return false;
	}
	return true;
};

// The code flow leads to `grant_type=authorization_code`, so a client not
// registered for it is refused here, before the user authenticates and a code
// is minted.
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
	// The token endpoint's words for the same refusal.
	redirectError(
		ctx,
		"unauthorized_client",
		"client is not authorized for grant_type 'authorization_code'",
	);
	return false;
};

// A client that is not first-party is served only through consent, so without
// a consent store it is refused here, ahead of the request-shape checks.
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

/**
 * This authorization request as a GET URL on the issuer's origin, with a
 * POST's form parameters written as the query: what the consent, login and
 * step-up pages return to, and what an ask is bound to. Not
 * `req.originalUrl`: a POST's URL alone names no client, `redirect_uri` or
 * PKCE.
 */
const authorizeRequestUrl = (issuerOrigin: string, req: Request): URL => {
	const url = new URL(buildCanonicalRequestUrl(issuerOrigin, req.originalUrl));
	url.search = "";
	for (const [name, value] of Object.entries(authorizeParams(req))) {
		if (typeof value === "string") {
			url.searchParams.append(name, value);
		} else if (Array.isArray(value)) {
			for (const item of value) {
				if (typeof item === "string") url.searchParams.append(name, item);
			}
		}
	}
	return url;
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

// Refuse before a code is minted when a verified email is required and the
// Store has published none. Artifacts derived from a code (refresh, token
// exchange) are not re-checked: that would end a live session on a Store
// hiccup. `access_denied` does not suggest the client sent something malformed.
const checkEmailVerified = async (ctx: AuthorizeContext): Promise<boolean> => {
	if (!(ctx.opts.oauth.requireEmailVerified && !isEmailVerified(ctx.req.session.user))) return true;
	await auditFailure(ctx, { reason: "email_not_verified" });
	redirectError(ctx, "access_denied", "email address is not verified");
	return false;
};

/**
 * PKCE (OAuth 2.1 §4.1.1, RFC 9700 §2.1.1) for every client: a
 * `code_challenge` is required — confidential clients included, since a
 * client secret proves who redeems the code, not that the redeemer is the
 * party it was issued to — and the method is `S256` unless this client's
 * registration opts into `plain` (`pkceMethodsForClient`). Runs before the
 * policy hook so a bad method costs no external I/O.
 */
const checkPkce = (
	ctx: AuthorizeContext,
	client: PublicClient,
	codeChallenge: unknown,
	codeChallengeMethod: unknown,
): { method: string } | null => {
	// The same resolved policy the authorization grant reads at `/token`. The
	// challenge is unconditionally required (`ResolvedPkceOptions.required` is
	// literally `true`).
	const policy = ctx.opts.oauth.pkce;
	if (typeof codeChallenge !== "string" || !codeChallenge) {
		redirectError(ctx, "invalid_request", "code_challenge is required");
		return null;
	}
	// A repeat was refused by `checkSingleValuedParams`, so undefined means
	// absent, which RFC 7636 §4.3 defines as `plain` — refused unless this
	// client opted in.
	const requestedMethod = toStr(codeChallengeMethod);
	const method = requestedMethod ?? PKCE_METHOD_ABSENT_DEFAULT;
	if (!pkceMethodsForClient(policy, client).includes(method)) {
		redirectError(
			ctx,
			"invalid_request",
			requestedMethod === undefined
				? `code_challenge_method is required and must be '${PKCE_METHOD_S256}'`
				: `code_challenge_method '${requestedMethod}' is not supported`,
		);
		return null;
	}
	return { method };
};

/**
 * `/authorize` parameters RFC 6749 §3.1 defines as single-valued. Express
 * surfaces a repeat as an array, which every read here narrows to
 * `undefined` — absence. Unchecked, a repeated `code_challenge_method` would
 * downgrade to `plain`, a repeated `scope` would fall back to the default,
 * and a repeated `state` would be dropped, silently failing the client's
 * CSRF check.
 *
 * Deliberately absent: `response_type` (its own `unsupported_response_type`),
 * `resource` (repeatable, RFC 8707 §2), `client_id`/`redirect_uri` (checked
 * before a redirect target exists, so 400 JSON) and `nonce` (`checkNonce`
 * owns it). One owner per parameter.
 */
const SINGLE_VALUED_QUERY_PARAMS = [
	"scope",
	"state",
	"code_challenge",
	"code_challenge_method",
	"max_age",
	"acr_values",
	"reauth_ask",
	// One JSON object, read by `checkClaimsParameter`.
	"claims",
] as const;

/**
 * The authorization request's parameters: a POST's form body or a GET's
 * query (OIDC Core §3.1.2.1 requires both methods). Read in one place so no
 * check silently applies to GET alone.
 */
export const authorizeParams = (req: Request): Record<string, unknown> =>
	req.method === "POST"
		? ((req.body ?? {}) as Record<string, unknown>)
		: (req.query as Record<string, unknown>);

/** The `prompt` values this server honours. */
type PromptDirective = {
	readonly silent: boolean;
	readonly login: boolean;
	readonly consent: boolean;
};

const NO_PROMPT: PromptDirective = { silent: false, login: false, consent: false };

/**
 * OIDC Core §3.1.2.1 `prompt`. `none` answers `login_required` instead of a
 * login page, which a hidden iframe doing silent renewal cannot act on.
 * `consent` forces the consent page for a client that is not first-party (a
 * no-op for first-party). `login` goes through the re-authentication ask
 * (`./reauthAsk.mts`), which keeps it from looping. Anything else
 * (`select_account`) is refused with `invalid_request`, not ignored: ignoring
 * it would return a token the RP believes honoured it.
 *
 * Returns the directive, or `null` when it has already answered.
 */
const resolvePrompt = (ctx: AuthorizeContext): PromptDirective | null => {
	const raw = ctx.params.prompt;
	if (raw === undefined) return NO_PROMPT;
	if (typeof raw !== "string") {
		redirectError(ctx, "invalid_request", "prompt must be a single string value");
		return null;
	}
	// §3.1.2.1: a space-delimited list read strictly (a tab is not a
	// delimiter); `none` may not be combined with any other value.
	const values = readSpaceDelimitedParameter(raw);
	if (values === null) {
		redirectError(ctx, "invalid_request", "prompt is not a space-delimited list of values");
		return null;
	}
	if (values.length === 0) return NO_PROMPT;
	if (values.includes("none") && values.length > 1) {
		redirectError(ctx, "invalid_request", "prompt=none cannot be combined with other values");
		return null;
	}
	// `login`: see `evaluateReauthentication`; `consent`: see `checkConsent`.
	const unsupported = values.filter((v) => v !== "none" && v !== "login" && v !== "consent");
	if (unsupported.length > 0) {
		redirectError(
			ctx,
			"invalid_request",
			`prompt values not supported: ${unsupported.join(" ")}; this authorization server ` +
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
 * `max_age` (OIDC Core §3.1.2.1): a non-negative integer, or a refusal.
 * Absent or empty means no constraint (RFC 6749 §3.1).
 */
const parseMaxAge = (ctx: AuthorizeContext): { readonly value: number | undefined } | null => {
	const raw = ctx.params.max_age;
	if (raw === undefined || raw === "") return { value: undefined };
	if (typeof raw !== "string" || !/^[0-9]+$/.test(raw)) {
		redirectError(ctx, "invalid_request", "max_age must be a non-negative integer");
		return null;
	}
	return { value: Number(raw) };
};

/**
 * The authorize request an ask is minted for and returned to: this request
 * as a GET URL (`authorizeRequestUrl` — a POST's form body written as the
 * query) without the ask parameter, so both sides agree by construction —
 * the POST that sends the browser away and the GET it comes back as.
 */
const askRequestOf = (ctx: AuthorizeContext): string => {
	const url = authorizeRequestUrl(ctx.issuerOrigin, ctx.req);
	url.searchParams.delete(REAUTH_ASK_PARAM);
	return url.toString();
};

type ReauthOutcome = "proceed" | "login" | "answered";

/**
 * The presented ask, consumed so a replayed URL asks again rather than
 * minting twice: `null` when absent, unknown, bound to another request or
 * expired; `undefined` after an outage has been answered. Read only when a
 * decision needs it.
 */
const presentedAsk = async (
	ctx: AuthorizeContext,
	askStore: ReauthAskStore | undefined,
): Promise<ReauthAskRecord | null | undefined> => {
	const presented = ctx.params[REAUTH_ASK_PARAM];
	if (typeof presented !== "string" || presented.length === 0 || askStore === undefined) {
		return null;
	}
	try {
		return await askStore.consume(presented, askRequestOf(ctx));
	} catch (err) {
		// The same rule the session read applies: an outage is not a decision
		// either way.
		ctx.opts.logger.error({ err: loggableError(err) }, "authorize_reauth_ask_store_unavailable");
		redirectError(ctx, "temporarily_unavailable", "session store unavailable");
		return undefined;
	}
};

/** Writes an ask, or answers the outage and returns `null`. */
const recordAsk = async (
	ctx: AuthorizeContext,
	askStore: ReauthAskStore,
	record: ReauthAskRecord,
): Promise<string | null> => {
	try {
		return await askStore.ask(record);
	} catch (err) {
		ctx.opts.logger.error({ err: loggableError(err) }, "authorize_reauth_ask_store_unavailable");
		redirectError(ctx, "temporarily_unavailable", "session store unavailable");
		return null;
	}
};

/** The request to come back to, carrying the ask `askId` names. */
const returnWithAsk = (askRequest: string, askId: string): string => {
	const back = new URL(askRequest);
	back.searchParams.set(REAUTH_ASK_PARAM, askId);
	return back.toString();
};

/**
 * Whether the session's authentication is fresh enough. `prompt=login`, or a
 * `max_age` older than the session's `auth_time`, sends the browser to log in
 * with the ask recorded (`login_required` under `prompt=none`). When the
 * presented ask records a login trip, a session authenticated after the ask
 * satisfies both; one that was not is refused with `login_required` rather
 * than looped. Decided before admission's verdict is acted on.
 */
const evaluateReauthentication = (
	ctx: AuthorizeContext,
	prompt: PromptDirective,
	maxAge: number | undefined,
	session: UserSession | null,
	askStore: ReauthAskStore | undefined,
	ask: ReauthAskRecord | null,
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
	if (askStore === undefined) {
		// The ask is a record in the session store, and there is none to write
		// it to. A composition error, not a per-request condition — and the
		// alternative is asking for a re-authentication this endpoint could
		// never recognise on the way back.
		redirectError(
			ctx,
			"invalid_request",
			"max_age and prompt=login need a session store, which this deployment does not wire",
		);
		return "answered";
	}
	if (ask !== null && ask.loginAskedAt !== undefined) {
		// Strictly after the ask, to the millisecond: an authentication made
		// before it — even earlier in the same second — is not the one it asked for.
		if (session.authTime.getTime() > ask.loginAskedAt) return "proceed";
		redirectError(
			ctx,
			"login_required",
			"re-authentication was requested but the session was not re-established",
		);
		return "answered";
	}
	// An id that names no ask, names one for another request, or has expired,
	// is simply not an ask — and one that records a step-up trip alone asked
	// for no login: evaluate the request on its merits, which asks again
	// rather than proceeding.
	const nowSeconds = Math.floor(Date.now() / 1000);
	const authTimeSeconds = Math.floor(session.authTime.getTime() / 1000);
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
 * The login trip. The ask is a store record named by an opaque id on the URL:
 * a caller cannot invent an id that exists, the record survives the session
 * regeneration login performs, and it is bound to this request so it cannot
 * satisfy another's freshness requirement. A step-up trip already asked is
 * carried over, so the session is not sent on it twice.
 */
const sendToLogin = async (
	ctx: AuthorizeContext,
	askStore: ReauthAskStore,
	ask: ReauthAskRecord | null,
): Promise<void> => {
	const now = Date.now();
	const askRequest = askRequestOf(ctx);
	const askId = await recordAsk(ctx, askStore, {
		request: askRequest,
		// Kept across the trips of one request, which caps a chain of them.
		createdAt: ask?.createdAt ?? now,
		loginAskedAt: now,
		stepUpAskedAt: { ...ask?.stepUpAskedAt },
	});
	if (askId === null) return;
	loginRedirect(ctx.res, ctx.opts.login, returnWithAsk(askRequest, askId));
};

/**
 * `acr_values` (OIDC Core §3.1.2.1), read strictly: a malformed list is the
 * request's fault, not an acr this deployment lacks. Whether the values are
 * met is admission's decision (`asks.acrValues`).
 */
const parseAcrValues = (ctx: AuthorizeContext): readonly string[] | null => {
	const raw = ctx.params.acr_values;
	if (raw === undefined) return [];
	const requested = typeof raw === "string" ? readSpaceDelimitedParameter(raw) : [];
	if (requested === null) {
		redirectError(ctx, "invalid_request", "acr_values is not a space-delimited list of values");
		return null;
	}
	return requested;
};

/**
 * An `unmet` admission: `unmet_authentication_requirements` when the
 * requested `acr` is what nothing meets (naming values not configured here
 * rather than accepting them silently), else `login_required`, since only a
 * new login can change what the requirement decides on.
 */
const refuseUnmet = (
	ctx: AuthorizeContext,
	requirement: string,
	requested: readonly string[],
): void => {
	if (requirement === "acr") {
		// `Object.hasOwn` rather than a bare read: the table may be a plain
		// object a composition handed in, and the value being looked up is one
		// an unauthenticated caller writes.
		const table = ctx.opts.oauth.acrValues;
		const unknown = requested.filter((acr) => !Object.hasOwn(table, acr));
		redirectError(
			ctx,
			"unmet_authentication_requirements",
			unknown.length > 0
				? `acr_values not configured on this authorization server: ${unknown.join(" ")}`
				: `the session's authentication does not satisfy any requested acr: ${requested.join(" ")}`,
		);
		return;
	}
	redirectError(
		ctx,
		"login_required",
		`the session does not meet the ${requirement} requirement; a new login is required`,
	);
};

/**
 * A `step_up` admission: send the browser to the requirement's registered
 * page with `acr_values` (when the request asked for an acr) and
 * `redirect_to` naming this request with the ask recorded. A session that
 * comes back no later than the recorded trip is refused rather than sent
 * again (`unmet_authentication_requirements` or `login_required`); one
 * established after it may make one more. `prompt=none` is
 * `interaction_required`.
 */
const stepUpTrip = async (
	ctx: AuthorizeContext,
	admission: Extract<Admission, { outcome: "step_up" }>,
	prompt: PromptDirective,
	askStore: ReauthAskStore | undefined,
	ask: ReauthAskRecord | null,
): Promise<void> => {
	const { requirement, page } = admission;
	const trips = ask?.stepUpAskedAt;
	const askedAt =
		trips !== undefined && Object.hasOwn(trips, requirement) ? trips[requirement] : undefined;
	if (askedAt !== undefined && admission.session.authTime.getTime() <= askedAt) {
		if (admission.whenStillUnmet === "unmet") {
			redirectError(
				ctx,
				"unmet_authentication_requirements",
				`the session came back from ${requirement} still not meeting the request`,
			);
		} else {
			redirectError(
				ctx,
				"login_required",
				`the session came back from ${requirement} still not meeting it; a new login is required`,
			);
		}
		return;
	}
	if (prompt.silent) {
		redirectError(
			ctx,
			"interaction_required",
			`prompt=none was requested but the session must step up through ${requirement}`,
		);
		return;
	}
	if (askStore === undefined) {
		// As a login trip is refused without a store to record the ask in: a
		// composition error, not a per-request condition.
		redirectError(
			ctx,
			"invalid_request",
			"a step-up needs a session store, which this deployment does not wire",
		);
		return;
	}
	// The page as registered; this trip's own parameters are set on it below.
	const target = new URL(page.href);
	// Registration holds a page to the issuer's origin (core's
	// `checkStepUpPage`); a resolver built without an issuer does not. The
	// URL this endpoint is about to send a browser to is checked anyway, and
	// one off the origin is a composition fault, never followed.
	if (target.origin !== ctx.issuerOrigin) {
		ctx.opts.logger.error({ requirement }, "authorize_step_up_page_off_origin");
		redirectError(ctx, "server_error", "the step-up page is not on this server's origin");
		return;
	}
	if (admission.acrValues.length > 0) {
		target.searchParams.set("acr_values", admission.acrValues.join(" "));
	}
	const now = Date.now();
	const askRequest = askRequestOf(ctx);
	const askId = await recordAsk(ctx, askStore, {
		request: askRequest,
		// Kept across the trips of one request, as the login trip keeps it.
		createdAt: ask?.createdAt ?? now,
		loginAskedAt: ask?.loginAskedAt,
		stepUpAskedAt: { ...trips, [requirement]: now },
	});
	if (askId === null) return;
	target.searchParams.set(REDIRECT_TO_PARAM, returnWithAsk(askRequest, askId));
	ctx.res.redirect(target.toString());
};

/**
 * Regenerates the cookie session so nothing of the refused session survives.
 * A failure is that store's outage; a session that cannot regenerate at all
 * fails the same way.
 */
const regenerateCookieSession = (
	req: Request,
): Promise<{ readonly failed: false } | { readonly failed: true; readonly cause: unknown }> =>
	new Promise((resolve) => {
		const session = (req as { session?: { regenerate?: unknown } }).session;
		if (typeof session?.regenerate !== "function") {
			resolve({
				failed: true,
				cause: new TypeError("the request's session cannot be regenerated"),
			});
			return;
		}
		(session.regenerate as (callback: (err?: unknown) => void) => void)((err) =>
			resolve(err == null ? { failed: false } : { failed: true, cause: err }),
		);
	});

/**
 * A new login, for `not_live`, `revoked`, `reauthenticate` and
 * `unauthenticated`. Under `prompt=none` the answer is `login_required` (OIDC
 * Core §3.1.2.6). Otherwise the cookie session is regenerated first, so a
 * login page that forwards signed-in users cannot loop on the refused
 * session's flag; if regeneration fails, answer `temporarily_unavailable` and
 * abandon the session so express-session does not write to that store again.
 */
const newLogin = async (ctx: AuthorizeContext, prompt: PromptDirective): Promise<void> => {
	if (prompt.silent) {
		redirectError(
			ctx,
			"login_required",
			"prompt=none was requested but no end-user session is present",
		);
		return;
	}
	const regenerated = await regenerateCookieSession(ctx.req);
	if (regenerated.failed) {
		ctx.opts.logger.error(
			{ store: "cookie_session", step: "regenerate", err: loggableError(regenerated.cause) },
			"authorize_cookie_session_unavailable",
		);
		(ctx.req as { session?: unknown }).session = undefined;
		redirectError(ctx, "temporarily_unavailable", "session store unavailable");
		return;
	}
	loginRedirect(ctx.res, ctx.opts.login, authorizeRequestUrl(ctx.issuerOrigin, ctx.req).toString());
};

/**
 * Acts on the admission, or returns `null` once answered. An outage is
 * `temporarily_unavailable` on the validated redirect URI — never the login
 * page, whose forwarding of signed-in users would loop. A dead or
 * unauthenticated session gets a new login. For the outcomes that carry a
 * session, freshness (`max_age`, `prompt=login`) is decided first, so
 * `prompt=none` with a stale `max_age` is `login_required` whatever the
 * verdict; then `unmet` is refused, `step_up` is a trip, and `admitted`
 * proceeds with the `acr` the session met.
 */
const decideOnAdmission = async (
	ctx: AuthorizeContext,
	admission: Admission,
	prompt: PromptDirective,
	maxAge: number | undefined,
	requested: readonly string[],
	askStore: ReauthAskStore | undefined,
): Promise<{ readonly session: UserSession | null; readonly acr: string | undefined } | null> => {
	switch (admission.outcome) {
		case "unavailable":
			redirectError(ctx, "temporarily_unavailable", describeAdmissionOutage(admission.store));
			return null;
		case "not_live":
		case "revoked":
		case "reauthenticate":
		// Never reached: a cookie whose flag is not exactly `true` was sent to
		// log in, or answered `login_required`, before admission. Listed so the
		// switch stays exhaustive over core's `Admission`.
		case "unauthenticated":
			await newLogin(ctx, prompt);
			return null;
		case "admitted":
		case "step_up":
		case "unmet": {
			// The ask is read only when a decision below needs it.
			const needsAsk = prompt.login || maxAge !== undefined || admission.outcome === "step_up";
			const ask = needsAsk ? await presentedAsk(ctx, askStore) : null;
			if (ask === undefined) return null;
			const reauth = evaluateReauthentication(
				ctx,
				prompt,
				maxAge,
				admission.session,
				askStore,
				ask,
			);
			if (reauth === "answered") return null;
			if (reauth === "login") {
				// `evaluateReauthentication` refused already when there is no store.
				await sendToLogin(ctx, askStore as ReauthAskStore, ask);
				return null;
			}
			if (admission.outcome === "unmet") {
				refuseUnmet(ctx, admission.requirement, requested);
				return null;
			}
			if (admission.outcome === "step_up") {
				await stepUpTrip(ctx, admission, prompt, askStore, ask);
				return null;
			}
			return { session: admission.session, acr: admission.acr };
		}
	}
};

/**
 * Refuses request objects (`request`, `request_uri`), which this server does
 * not implement, with OIDC Core's `request_not_supported` /
 * `request_uri_not_supported`. Ignoring them would be unsafe: the RP would
 * believe its signed, tamper-proof parameters were honoured while the
 * unsigned query was processed instead.
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

/**
 * OIDC Core §5.5 `claims`: a request naming `acr` (for id_token or userinfo,
 * essential or not) is refused with `invalid_request` — this server vouches
 * for `acr` only through `acr_values`, and ignoring the request would return
 * a token the RP reads as honouring it. Other uses of `claims` are ignored
 * (discovery omits `claims_parameter_supported`). An empty value is omitted
 * (RFC 6749 §3.1); any other non-object is malformed. Runs before the
 * re-authentication decision, so a refused request is never first sent to
 * log in.
 */
const checkClaimsParameter = (ctx: AuthorizeContext): boolean => {
	const raw = ctx.params.claims;
	if (raw === undefined || raw === "") return true;
	let claims: unknown;
	try {
		claims = JSON.parse(raw as string);
	} catch {
		claims = undefined;
	}
	if (typeof claims !== "object" || claims === null || Array.isArray(claims)) {
		redirectError(ctx, "invalid_request", "claims is not a JSON object");
		return false;
	}
	const namesAcr = (member: unknown): boolean =>
		typeof member === "object" && member !== null && Object.hasOwn(member, "acr");
	const { id_token: idToken, userinfo } = claims as Record<string, unknown>;
	if (namesAcr(idToken) || namesAcr(userinfo)) {
		redirectError(ctx, "invalid_request", "request acr through acr_values");
		return false;
	}
	return true;
};

/** Refuses a repeated single-valued parameter before any of it is interpreted. */
const checkSingleValuedParams = (ctx: AuthorizeContext): boolean => {
	for (const name of SINGLE_VALUED_QUERY_PARAMS) {
		const value = ctx.params[name];
		if (value === undefined || typeof value === "string") continue;
		redirectError(ctx, "invalid_request", `${name} must be a single string value`);
		return false;
	}
	return true;
};

// Bounds `nonce`, which is stored on the code and echoed into the id_token,
// so an oversized value cannot exhaust memory or bloat tokens
// (`oauth.nonce.maxLength`). Runs after `redirect_uri` validation (so errors
// can redirect) and before the policy hook (so it costs no external I/O).
const checkNonce = (ctx: AuthorizeContext): boolean => {
	const nonceMaxLength = ctx.opts.oauth.nonceMaxLength;
	if (ctx.params.nonce === undefined) return true;
	// The sole owner of the single-value rule for `nonce` (it is not in
	// SINGLE_VALUED_QUERY_PARAMS): a repeat arrives as an array and would
	// otherwise mint a code with no nonce, failing only later at the client.
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
 * RFC 6749 §3.3 scope narrowing plus the openid requirement. Returns the
 * requested scopes and the allowlist-filtered set the policy step takes as
 * its ceiling, or `null` when a response has been sent.
 *
 * Scopes the client is not registered for are dropped (§3.3 allows it; the
 * token response's `scope` names what was granted). An omitted scope draws on
 * the declared `defaultScopes`, never the whole allowlist; with none declared
 * it is `invalid_scope`, except that a client with an empty allowlist keeps
 * the empty grant.
 */
const resolveScopes = (
	ctx: AuthorizeContext,
	scope: unknown,
	client: PublicClient,
): { requestedScopes: string[]; allowedFilteredScopes: readonly string[] } | null => {
	const allowedScopes = client.allowedScopes;
	// RFC 6749 §3.3, read strictly: narrowing (below) is the answer to a scope
	// this client may not have, and a malformed one is a different answer
	// (§4.1.2.1 `invalid_scope`) — `read\tbogus` is not the scope `read` with a
	// typo beside it. A repeat never reaches here (`checkSingleValuedParams`).
	const named = readSpaceDelimitedParameter(toStr(scope) ?? "");
	if (named === null) {
		redirectError(ctx, "invalid_scope", "scope is not a space-delimited list of scope-tokens");
		return null;
	}
	const requestedScopes = [...named];
	let allowedFilteredScopes: readonly string[];
	if (requestedScopes.length > 0) {
		allowedFilteredScopes = requestedScopes.filter((s) => allowedScopes.includes(s));
	} else if (client.defaultScopes !== undefined) {
		// Filtered even so: a custom ClientRepository is not schema-validated.
		allowedFilteredScopes = client.defaultScopes.filter((s) => allowedScopes.includes(s));
	} else if (allowedScopes.length === 0) {
		allowedFilteredScopes = [];
	} else {
		void auditFailure(ctx, { reason: "scope_omitted_without_default" });
		redirectError(ctx, "invalid_scope", "scope is required: this client declares no defaultScopes");
		return null;
	}
	// The router refuses a missing issuer, so `oidcMode` alone decides.
	if (
		ctx.opts.oauth.oidcMode === "oidc-required" &&
		// Both undermine "OIDC required": the request omits openid, or the
		// client allowlist filtered it out.
		(!requestedScopes.includes("openid") || !allowedFilteredScopes.includes("openid"))
	) {
		// The requested scopes are the caller's: logged as the first ten, each
		// capped, with the count when cut.
		const loggedScopes = auditErrorList(requestedScopes);
		ctx.opts.logger.warn(
			{
				clientId: ctx.clientId,
				requestedScopes: loggedScopes,
				...(loggedScopes.length < requestedScopes.length
					? { requestedScopeCount: requestedScopes.length }
					: {}),
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
		// `prompt=none` must not get a login page (a hidden iframe cannot act on
		// it); it falls through so `login_required` can be delivered at the
		// validated `redirect_uri`. Any list naming `none` opens this gate —
		// forbidden combinations included, read tolerantly (`parseScopeTokens`)
		// — since such a request still comes from a silent context and its
		// `invalid_request` belongs at the RP's `redirect_uri`. Every other
		// unauthenticated request is answered before any lookup.
		const promptRaw = authorizeParams(req).prompt;
		const wantsSilentAuth =
			typeof promptRaw === "string" && parseScopeTokens(promptRaw).includes("none");

		// The cookie's flag is checked first, with no store read, so an
		// anonymous request costs no lookup. Whether the session behind it is
		// live is admission's to decide, once, below.
		const claim = cookieClaim(req);
		if (!claim.authenticated && !wantsSilentAuth) {
			loginRedirect(res, opts.login, authorizeRequestUrl(issuerOrigin, req).toString());
			return;
		}

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
		if (prompt.silent && !claim.authenticated) {
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
