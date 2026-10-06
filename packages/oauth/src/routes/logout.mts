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
	AuditSink,
	ClientRepository,
	EventLogger,
	FederationProvider,
	FederationTokenStore,
	KeyStore,
	Logger,
	RefreshTokenFamilyRevocation,
	SessionFederations,
	SessionLifecycle,
	SessionLiveness,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	auditErrorText,
	auditedError,
	checkRedirectUri,
	emitAuditEvent,
	isVerificationUnavailable,
	JwtVerificationError,
	logClientRepositoryUnavailable,
	loggableError,
	sanitizeErrorText,
	supportsLogout,
	verifyJwt,
} from "@o3co/auth-provider-core";
import accepts from "accepts";
import type { Request, RequestHandler, Response, Router } from "express";
import { parseAccessTokenHeader } from "../accessTokenHeader.mjs";
import {
	type UsableFrontchannelRP,
	usableFrontchannelRP,
} from "../logout/frontchannelLogoutUri.mjs";
import { renderFrontchannelLogoutHtml } from "../logout/renderFrontchannel.mjs";
import { refuseVerificationUnavailable } from "../verificationUnavailable.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

/**
 * The slice of the express-session bag this route touches. Every field is
 * optional at runtime: `/oauth/logout` may be mounted with no session
 * middleware (the pure back-channel shape), and a session may carry no `sid`.
 */
interface BrowserSessionLike {
	sid?: unknown;
	destroy?: (callback: (err?: unknown) => void) => unknown;
}

/**
 * Ends the browser session that owns `sid`. The session's close deletes the
 * `UserSession` record, but the express-session cookie is separate and would
 * keep satisfying `/authorize`, minting codes for a dead `sid` that `/token`
 * refuses — a login loop no RP could break.
 *
 * Only a cookie whose `sid` matches is destroyed: RP-initiated logout is a
 * request anyone may make about any session, so the cookie riding along is
 * not evidence this browser owns it. A session with no `sid` is left alone;
 * it cannot be the subject of an RP-initiated logout (a hint without `sid` is
 * refused earlier), and a code minted from it is refused at the token
 * endpoint when a session store is wired.
 *
 * Failures are logged, never propagated: the close already succeeded, and
 * `/authorize` refuses a surviving cookie regardless. Takes `EventLogger`
 * because the route's fallback logger is `console`.
 */
async function endBrowserSession(req: Request, sid: string, logger: EventLogger): Promise<void> {
	const session = (req as unknown as { session?: BrowserSessionLike }).session;
	const destroy = session?.destroy;
	if (!session || session.sid !== sid || typeof destroy !== "function") return;
	await new Promise<void>((resolve) => {
		try {
			destroy.call(session, (err?: unknown) => {
				if (err) {
					logger.warn({ err: loggableError(err), sid }, "logout_browser_session_destroy_failed");
				}
				resolve();
			});
		} catch (err) {
			// A store adapter that throws synchronously never reaches its own
			// callback, so resolve here or the request would hang.
			logger.warn({ err: loggableError(err), sid }, "logout_browser_session_destroy_failed");
			resolve();
		}
	});
}

function readLogoutParam(source: Record<string, unknown>, key: string): string | undefined {
	const value = source[key];
	return typeof value === "string" ? value : undefined;
}

function extractLogoutParams(req: Request): {
	idTokenHint: string | undefined;
	postLogoutRedirectUri: string | undefined;
	state: string | undefined;
} {
	const source =
		req.method === "GET"
			? (req.query as Record<string, unknown>)
			: ((req.body ?? {}) as Record<string, unknown>);
	return {
		idTokenHint: readLogoutParam(source, "id_token_hint"),
		postLogoutRedirectUri: readLogoutParam(source, "post_logout_redirect_uri"),
		state: readLogoutParam(source, "state"),
	};
}

/**
 * The client an `id_token_hint` was issued to, whose registered
 * `postLogoutRedirectUris` the logout's `post_logout_redirect_uri` is held to:
 * `azp` when the hint names one that is among its audiences (OIDC Core §2), else
 * its one audience — a string, or a list of one — else nobody, and the URI is
 * dropped. A hint for several audiences and no `azp` does not say which client
 * asked, and the first of them is not evidence of it.
 */
function issuedTo(payload: Record<string, unknown>): string | null {
	const aud = payload.aud;
	const audiences = typeof aud === "string" ? [aud] : Array.isArray(aud) ? aud : [];
	const azp = payload.azp;
	if (typeof azp === "string" && audiences.includes(azp)) return azp;
	const [only] = audiences;
	return audiences.length === 1 && typeof only === "string" ? only : null;
}

const HTML_ESCAPE: Record<string, string> = {
	"&": "&amp;",
	"<": "&lt;",
	">": "&gt;",
	'"': "&quot;",
	"'": "&#39;",
};

function escapeHtml(s: string): string {
	return s.replace(/[&<>"']/g, (c) => HTML_ESCAPE[c] ?? c);
}

function hiddenInput(name: string, value: string | undefined): string {
	if (typeof value !== "string" || value.length === 0) return "";
	return `    <input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}" />\n`;
}

function renderLogoutConfirmation(
	res: Response,
	params: {
		idTokenHint?: string;
		postLogoutRedirectUri?: string;
		state?: string;
	},
): Response {
	// The original logout params ride along as hidden inputs so the confirmed
	// POST can complete the hint-based flow. `action=""` posts to the current
	// URL, avoiding `/oauth/logout/logout` when reached with a trailing slash.
	const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Confirm Logout</title></head>
<body>
  <h1>Sign out</h1>
  <p>Do you want to sign out from all applications?</p>
  <form method="POST" action="">
${hiddenInput("id_token_hint", params.idTokenHint)}${hiddenInput("post_logout_redirect_uri", params.postLogoutRedirectUri)}${hiddenInput("state", params.state)}    <input type="hidden" name="confirmed" value="1" />
    <button type="submit">Sign out</button>
  </form>
</body>
</html>`;
	res.setHeader("Content-Type", "text/html; charset=utf-8");
	return res.status(200).send(html);
}

export interface LogoutRouterOptions {
	keyStore: KeyStore;
	/** Issuer URL of this auth provider — used for logout_token `iss` claim and iframe `iss` param. */
	issuer: string;
	/** Read to answer a logout of a session already gone as the no-op it is. */
	userSessionStore: UserSessionStore;
	federationTokenStore: FederationTokenStore;
	refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	clientRepository: ClientRepository;
	/**
	 * Getter for the federation providers Map, evaluated per request so module
	 * init order does not matter. Returns undefined when federation is not
	 * configured.
	 */
	getFederationProviders: () => ReadonlyMap<string, FederationProvider> | undefined;
	/** Override for unit tests. Defaults to the global `fetch`. */
	fetchImpl?: typeof fetch;
	/** Structured logger for the route's lines. */
	logger?: Logger;
	/** Audit sink for operator observability events. No-op when undefined. */
	auditSink?: AuditSink;
	/**
	 * Accept tokens with no `typ` header, logging `jwt_verify_legacy_typ`.
	 * Default `false`; `true` is a legacy opt-in. Applies to the bearer access
	 * token and the id_token_hint.
	 */
	legacyTypAccept?: boolean;
	/**
	 * Core's session lifecycle: `/oauth/logout` ends the session with its
	 * `close`, and its notifier tells the relying parties back-channel; the
	 * federation logout reads whether the session is live and which
	 * federations it joined.
	 */
	sessionLifecycle: SessionLifecycle;
}

/**
 * How a logout ended the session: `ended`, with the federations it joined,
 * the upstream end-session URI and the relying parties' front-channel
 * registrations (read only for an HTML answer); or `unavailable`, already
 * logged and audited, answered `503` with `description`.
 */
type LogoutEnd =
	| {
			readonly outcome: "ended";
			readonly federations: readonly string[];
			readonly endSessionUri: string | undefined;
			readonly frontchannelRps: () => Promise<readonly UsableFrontchannelRP[]>;
	  }
	| { readonly outcome: "unavailable"; readonly description: string };

/** What an upstream end-session call is handed beside its hint. */
interface UpstreamEndRequest {
	readonly postLogoutRedirectUri: string | undefined;
	readonly state: string | undefined;
}

/**
 * OIDC RP-Initiated Logout 1.0 — GET/POST /oauth/logout, taking
 * `id_token_hint` (required), `post_logout_redirect_uri` and `state`:
 *
 *   1. verify the hint (fail → 400 invalid_token; keystore outage → 503);
 *   2. read `sid` (missing → 400) and the client the hint was issued to, and
 *      hold `post_logout_redirect_uri` to that client's registered list; a
 *      GET with a stale hint gets the confirmation page;
 *   3. load the session (missing → 200 no-op);
 *   4–6. end the session through core's session lifecycle: read the first
 *      federation's upstream `id_token` (best effort), then `close` it
 *      (`unavailable` → 503; `pending` → success, audited as
 *      `logout.close_pending`); the lifecycle's notifier tells the relying
 *      parties back-channel;
 *   7. respond: front-channel HTML | IdP redirect | post-logout redirect | JSON.
 *
 * Also mounts `POST /oauth/federation/:name/logout`, the bearer-authenticated
 * disconnect of one federation, which holds `post_logout_redirect_uri` to the
 * same rule for the access token's `azp`. It removes the federation's tokens
 * and leaves the federation listed as having joined the session: readers
 * acting on its tokens skip a federation that has none, and the session's
 * close may end it upstream again, which is idempotent.
 */
export function createRouter(express: ExpressLike, opts: LogoutRouterOptions): Router {
	const router = express.Router();

	// A store that cannot answer is `503`, logged once at error
	// (`federation_logout_store_unavailable` / `logout_store_unavailable`) with
	// `store`, `step` and the error's projection, never the error. The client
	// repository logs core's `client_repository_unavailable` instead.
	const federationLogoutStoreUnavailable = (
		logger: EventLogger,
		federation: string,
		store: "federation_token",
		step: "get" | "delete",
		error: unknown,
	): void => {
		logger.error(
			{ federation, store, step, err: loggableError(error) },
			"federation_logout_store_unavailable",
		);
	};
	/**
	 * The federation logout's `503` for the session lifecycle that could not
	 * answer `step`: one error line, carrying the error's projection when the
	 * lifecycle rejected; without `err` for the defensive fallback on any
	 * answer the step does not act on.
	 */
	const federationLogoutLifecycleUnavailable = (
		res: Response,
		logger: EventLogger,
		federation: string,
		step: "liveness" | "federations",
		thrown?: { readonly error: unknown },
	): Response => {
		logger.error(
			{
				federation,
				store: "session_lifecycle",
				step,
				...(thrown === undefined ? {} : { err: loggableError(thrown.error) }),
			},
			"federation_logout_store_unavailable",
		);
		return res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
	};

	/**
	 * The `post_logout_redirect_uri` a logout may pass on: the caller's value
	 * when it byte-for-byte matches one of the client's registered
	 * `postLogoutRedirectUris` (OIDC RP-Initiated Logout 1.0 §3), else nothing.
	 * Decided before any other step sees the value, since a federation's
	 * `endSession()` may redirect straight to what it is handed.
	 *
	 * A client repository outage drops the URI and the logout goes on: refusing
	 * would keep sessions alive to protect a redirect, and the spec forbids only
	 * the redirect. A match must also pass `checkRedirectUri`: a custom
	 * repository bypasses the boot schema, and an unparseable or `javascript:`
	 * entry is no place to send a browser. Such a match is dropped with a warn.
	 */
	const registeredPostLogoutRedirectUri = async (
		requested: unknown,
		clientId: string | null,
		logger: Pick<Logger, "error" | "warn">,
		site: "logout" | "federation_logout",
	): Promise<string | undefined> => {
		if (typeof requested !== "string" || requested.length === 0 || clientId === null) {
			return undefined;
		}
		let client: Awaited<ReturnType<typeof opts.clientRepository.findById>>;
		try {
			client = await opts.clientRepository.findById(clientId);
		} catch (error) {
			logClientRepositoryUnavailable(logger, { site, step: "find", clientId }, error);
			return undefined;
		}
		if (client?.postLogoutRedirectUris?.includes(requested) !== true) return undefined;
		const rejection = checkRedirectUri(requested);
		if (rejection !== null) {
			logger.warn(
				{ site, clientId: auditErrorText(clientId), reason: rejection.reason },
				"logout_registered_redirect_uri_refused",
			);
			return undefined;
		}
		return requested;
	};

	// POST /federation/:name/logout — mounted under /oauth → POST /oauth/federation/:name/logout
	router.post(
		"/federation/:name/logout",
		express.urlencoded({ extended: false }),
		async (req: Request, res: Response) => {
			const { name } = req.params as { name: string };
			// The path parameter is the caller's text, logged before any membership
			// check: every log line and every audit event carries it sanitised and
			// capped, as a client id is.
			const federation = auditErrorText(name);
			// A POST with no body leaves `req.body` unset: the form parser only
			// sets it for a form. Every field is read as the caller's, typed below.
			const { post_logout_redirect_uri: postLogoutRedirectUri, state } = (req.body ?? {}) as Record<
				string,
				unknown
			>;

			const logger = opts.logger ?? console;

			// RFC 6749 §5.1 / RFC 9207: cache headers on every response path.
			res.setHeader("Cache-Control", "no-store");
			res.setHeader("Pragma", "no-cache");

			// Step 1: Extract the access token from the Authorization header —
			// Bearer (RFC 6750 §2.1) or DPoP (RFC 9449 §7.1), both matched
			// case-insensitively per RFC 9110 §11.1. Scheme-vs-`cnf` agreement is
			// enforced by `protectedResourceBindingMw` upstream.
			const token = parseAccessTokenHeader(req.headers.authorization);
			if (token === null) {
				res.setHeader(
					"WWW-Authenticate",
					'Bearer error="invalid_token", error_description="missing access token"',
				);
				return res
					.status(401)
					.json({ error: "invalid_token", error_description: "missing access token" });
			}

			// Step 2: alg / iss / typ and signature, pinned by the verifier. typ
			// must be at+jwt: refresh and id tokens share the KeyStore, so typ is
			// the only defense against cross-type acceptance. Audience is not
			// checked (logged as `jwt_verify_aud_skipped`).
			let payload: Record<string, unknown>;
			try {
				const verified = await verifyJwt(token, opts.keyStore, {
					type: "access_token",
					expectedIssuer: opts.issuer ?? "",
					legacyTypAccept: opts.legacyTypAccept ?? false,
					// No revocation check, deliberately: logout only destroys the
					// session the token names, which is safe for a revoked token and
					// what a user does right after a credential-change cascade.
					revocation: "none",
					logger: opts.logger,
				});
				payload = verified.payload as Record<string, unknown>;
			} catch (error) {
				// The keystore did not answer: the server's outage, not a verdict
				// on the token (`isVerificationUnavailable`).
				if (isVerificationUnavailable(error)) {
					return refuseVerificationUnavailable(res, error, logger, "federation_logout");
				}
				// Log the verifier's reason only, never the token: this path can be
				// attacker-driven and the message quotes token content. The
				// verifier already logged `jwt_verify_rejected`.
				const verdict = error instanceof JwtVerificationError ? error.reason : undefined;
				logger.warn(
					verdict === undefined
						? { federation, err: loggableError(error) }
						: { federation, reason: verdict },
					"federation_logout_jwt_verify_failed",
				);
				res.setHeader(
					"WWW-Authenticate",
					'Bearer error="invalid_token", error_description="invalid token"',
				);
				return res.status(401).json({
					error: "invalid_token",
					error_description: "invalid token",
				});
			}

			// Step 3: Extract family_id, sid, sub and azp from verified payload.
			const familyId = typeof payload.family_id === "string" ? payload.family_id : null;
			const sid = typeof payload.sid === "string" ? payload.sid : null;
			const sub = typeof payload.sub === "string" ? payload.sub : null;
			// The client the token was issued to: whose registered
			// `postLogoutRedirectUris` the caller's `post_logout_redirect_uri` is
			// held to (Step 7b).
			const azp = typeof payload.azp === "string" ? payload.azp : null;

			// Step 4: family revocation, fail-closed. A throw is `503`, never
			// `401 invalid_token` (RFC 6750 §3.1 describes a token nobody judged).
			if (familyId !== null) {
				let revoked: boolean;
				try {
					revoked = await opts.refreshTokenFamilyRevocation.isFamilyRevoked(familyId);
				} catch (error) {
					logger.error(
						{ federation, store: "refresh_token_family", err: loggableError(error) },
						"federation_logout_store_unavailable",
					);
					return res.status(503).json({
						error: "temporarily_unavailable",
						error_description: "refresh token store unavailable",
					});
				}
				if (revoked) {
					emitAuditEvent(opts.auditSink, {
						timestamp: new Date(),
						type: "logout.family_revoked",
						subject: sub ?? undefined,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { sid: sid ?? undefined },
					});
					res.setHeader(
						"WWW-Authenticate",
						'Bearer error="invalid_token", error_description="family revoked"',
					);
					return res.status(401).json({
						error: "invalid_token",
						error_description: "family revoked",
					});
				}
			}

			// Step 5: sid is required to look up the session.
			if (!sid) {
				res.setHeader(
					"WWW-Authenticate",
					'Bearer error="invalid_token", error_description="missing sid claim"',
				);
				return res.status(401).json({
					error: "invalid_token",
					error_description: "missing sid claim",
				});
			}

			// Step 6: the session must be live, read from core's session
			// lifecycle: a session whose close has committed is not. Not live, or
			// another subject's → 401 (the token is effectively invalid).
			let liveness: SessionLiveness;
			try {
				liveness = await opts.sessionLifecycle.liveness(sid);
			} catch (error) {
				return federationLogoutLifecycleUnavailable(res, logger, federation, "liveness", {
					error,
				});
			}
			// Any answer other than `live` or `not_live` (core's lifecycle gives
			// none, as it rejects on an outage) is answered as the outage.
			if (liveness.outcome !== "live" && liveness.outcome !== "not_live") {
				return federationLogoutLifecycleUnavailable(res, logger, federation, "liveness");
			}
			if (liveness.outcome !== "live" || liveness.session.sub !== sub) {
				res.setHeader(
					"WWW-Authenticate",
					'Bearer error="invalid_token", error_description="session not found"',
				);
				return res.status(401).json({
					error: "invalid_token",
					error_description: "session not found",
				});
			}

			// Step 7: the named federation must have joined this session.
			let listed: SessionFederations;
			try {
				listed = await opts.sessionLifecycle.federations(sid);
			} catch (error) {
				return federationLogoutLifecycleUnavailable(res, logger, federation, "federations", {
					error,
				});
			}
			// Any answer other than `listed` (core's lifecycle gives none, as it
			// rejects on an outage) is answered as the outage.
			if (listed.outcome !== "listed") {
				return federationLogoutLifecycleUnavailable(res, logger, federation, "federations");
			}
			const federations = listed.federations;

			if (!federations.includes(name)) {
				return res.status(404).json({
					error: "federation_not_linked",
					error_description: sanitizeErrorText(
						`federation '${name}' is not linked to this session`,
					),
				});
			}

			// Step 7b: the post_logout_redirect_uri the IdP end-session call may be
			// handed (Step 11) — the caller's only when the token's client
			// registered it. A client repository that cannot answer drops it, and
			// the disconnect goes on.
			const allowedRedirect = await registeredPostLogoutRedirectUri(
				postLogoutRedirectUri,
				azp,
				logger,
				"federation_logout",
			);

			// Step 8: Get federation tokens (may be null — best-effort idTokenHint).
			let fedTokens: Awaited<ReturnType<typeof opts.federationTokenStore.get>>;
			try {
				fedTokens = await opts.federationTokenStore.get(sid, name);
			} catch (error) {
				federationLogoutStoreUnavailable(logger, federation, "federation_token", "get", error);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "federation token store unavailable",
				});
			}

			// Step 9: Delete federation token record.
			try {
				await opts.federationTokenStore.delete(sid, name);
			} catch (error) {
				federationLogoutStoreUnavailable(logger, federation, "federation_token", "delete", error);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "federation token store unavailable",
				});
			}

			// The federation stays listed as having joined the session: the
			// lifecycle keeps who joined until the session closes.

			// Step 11: IdP end-session redirect, best effort. Providers are looked
			// up per request so module init order does not matter.
			const provider = opts.getFederationProviders()?.get(name);
			if (supportsLogout(provider)) {
				try {
					const endSessionResult = await provider.endSession({
						idTokenHint: fedTokens?.idToken ?? undefined,
						// Registered for the token's client, or none (Step 7b).
						postLogoutRedirectUri: allowedRedirect,
						state: typeof state === "string" ? state : undefined,
					});
					// Local state already cleared — redirect to IdP end-session URL.
					emitAuditEvent(opts.auditSink, {
						timestamp: new Date(),
						type: "federation.logout.success",
						subject: sub ?? undefined,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { federation, redirected_to_idp: true },
					});
					return res.redirect(303, endSessionResult.url.toString());
				} catch (error) {
					// Best-effort: IdP logout failed but local state is already cleared.
					// Log at warn — "orphan IdP session" case, critical for operators.
					logger.warn(
						{ federation, err: loggableError(error) },
						"federation_logout_end_session_failed",
					);
					emitAuditEvent(opts.auditSink, {
						timestamp: new Date(),
						type: "federation.logout.idp_unreachable",
						subject: sub ?? undefined,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						// The error's name and code, never its message: an IdP's
						// refusal carries the IdP's own words.
						details: { federation, cause: auditedError(error) },
					});
					return res.status(200).json({ disconnected: true });
				}
			}

			// Step 12: No endSession support → return 200 disconnected.
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "federation.logout.success",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { federation, redirected_to_idp: false },
			});
			return res.status(200).json({ disconnected: true });
		},
	);

	/**
	 * The stored upstream `id_token` of `federation` in `sid`, the hint its
	 * end-session call is handed. Best effort: a record that cannot be read is
	 * no hint, said once at warn, and the logout goes on — the IdP may then
	 * ask the user to confirm, or choose the account itself.
	 */
	const readUpstreamIdToken = async (
		sid: string,
		federation: string,
	): Promise<string | undefined> => {
		try {
			const tokens = await opts.federationTokenStore.get(sid, federation);
			return tokens?.idToken ?? undefined;
		} catch (err) {
			(opts.logger ?? console).warn(
				{
					federation: auditErrorText(federation),
					store: "federation_token",
					step: "get",
					err: loggableError(err),
				},
				"logout_federation_token_read_failed",
			);
			return undefined;
		}
	};

	/**
	 * The IdP end-session URI of `federation`, when its provider ends sessions
	 * upstream; providers are looked up per request. Best effort: a call that
	 * fails is logged and the logout answers without the redirect.
	 */
	const upstreamEndSessionUri = async (
		federation: string,
		idTokenHint: () => Promise<string | undefined>,
		upstream: UpstreamEndRequest,
	): Promise<string | undefined> => {
		const provider = opts.getFederationProviders()?.get(federation);
		if (!supportsLogout(provider)) return undefined;
		try {
			const result = await provider.endSession({
				idTokenHint: await idTokenHint(),
				postLogoutRedirectUri: upstream.postLogoutRedirectUri,
				state: upstream.state,
			});
			return result.url.toString();
		} catch (err) {
			(opts.logger ?? console).warn(
				{ federation: auditErrorText(federation), err: loggableError(err) },
				"logout_federation_end_session_failed",
			);
			return undefined;
		}
	};

	/**
	 * The front-channel registrations of the relying parties `clientIds`
	 * names, each read from its client registration. A registration that
	 * cannot be read drops that relying party alone, logged once as
	 * `client_repository_unavailable`; one gone, or with no usable URI, is
	 * skipped.
	 */
	const registeredFrontchannelRps = async (
		clientIds: readonly string[],
	): Promise<readonly UsableFrontchannelRP[]> => {
		const logger = opts.logger ?? console;
		const usable = await Promise.all(
			clientIds.map(async (clientId) => {
				let client: Awaited<ReturnType<typeof opts.clientRepository.findById>>;
				try {
					client = await opts.clientRepository.findById(clientId);
				} catch (error) {
					logClientRepositoryUnavailable(logger, { site: "logout", step: "find", clientId }, error);
					return undefined;
				}
				if (client === null || client === undefined) return undefined;
				// Each field read through core's guarded read: a refused one drops this iframe alone.
				return usableFrontchannelRP(client, "logout", logger);
			}),
		);
		return usable.filter((rp): rp is UsableFrontchannelRP => rp !== undefined);
	};

	/**
	 * Ends `sid` through core's session lifecycle. The upstream hint is read
	 * first, since the close removes the federation tokens that carry it; it
	 * goes upstream only to the federation it was read for. The relying
	 * parties are told back-channel by the lifecycle's notifier, and the
	 * front-channel and upstream steps read the close's answer.
	 */
	const endThroughLifecycle = async (
		lifecycle: SessionLifecycle,
		req: Request,
		sid: string,
		sub: string | null,
		upstream: UpstreamEndRequest,
	): Promise<LogoutEnd> => {
		// The hint is best effort: a listing that cannot be read, answered or
		// rejected, leaves the logout without it, and the close says the outage.
		let listed: SessionFederations | undefined;
		try {
			listed = await lifecycle.federations(sid);
		} catch {
			listed = undefined;
		}
		const hinted = listed?.outcome === "listed" ? listed.federations[0] : undefined;
		const hint =
			hinted !== undefined && supportsLogout(opts.getFederationProviders()?.get(hinted))
				? { federation: hinted, idToken: await readUpstreamIdToken(sid, hinted) }
				: undefined;

		// The close did not commit, or whether it did could not be read: the
		// route's one line for its 503, with the error's projection when the
		// lifecycle rejected; without `err` for the defensive fallback on any
		// answer other than `done` or `pending`.
		const closeUnavailable = (thrown?: { readonly error: unknown }): LogoutEnd => {
			(opts.logger ?? console).error(
				{
					store: "session_lifecycle",
					step: "close",
					...(thrown === undefined ? {} : { err: loggableError(thrown.error) }),
				},
				"logout_store_unavailable",
			);
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "logout.cascade_failed",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { sid, store: "session_lifecycle" },
			});
			return { outcome: "unavailable", description: "session store unavailable" };
		};
		let closed: Awaited<ReturnType<SessionLifecycle["close"]>>;
		try {
			closed = await lifecycle.close(sid, "rp_logout");
		} catch (error) {
			// Every rejection is the outage it may be, a RangeError included: a
			// store's own error can be one, and answering it as a session already
			// gone would report a logout that revoked nothing.
			return closeUnavailable({ error });
		}
		// Any answer other than `done` or `pending` (core's lifecycle gives none,
		// as it rejects on an outage) is answered as the outage: fail-closed.
		if (closed.outcome !== "done" && closed.outcome !== "pending") return closeUnavailable();
		// The session has ended — nothing joins it and no liveness read answers
		// it live — while some of its close work is left to a later close or
		// the sweep.
		if (closed.outcome === "pending") {
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "logout.close_pending",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { sid },
			});
		}

		const first = closed.federations[0];
		const endSessionUri =
			first === undefined
				? undefined
				: await upstreamEndSessionUri(
						first,
						async () => (hint?.federation === first ? hint.idToken : undefined),
						upstream,
					);
		return {
			outcome: "ended",
			federations: closed.federations,
			endSessionUri,
			frontchannelRps: () => registeredFrontchannelRps(closed.rps),
		};
	};

	const handleLogout = async (req: Request, res: Response) => {
		// RFC 6749 §5.1 / RFC 9207: cache headers on every response path.
		res.setHeader("Cache-Control", "no-store");
		res.setHeader("Pragma", "no-cache");

		const { idTokenHint, postLogoutRedirectUri, state } = extractLogoutParams(req);

		// Step 1: Verify id_token_hint.
		if (typeof idTokenHint !== "string" || idTokenHint.length === 0) {
			// No hint available — there is nothing to pass through to a
			// confirmed POST, so the confirmation page would render a button
			// that always fails the POST hint requirement. Reject directly.
			return res.status(400).json({
				error: "invalid_request",
				error_description: "id_token_hint is required",
			});
		}

		let payload: Record<string, unknown>;
		try {
			// alg / iss / typ (JWT) and signature pinned. Audience cannot be pinned
			// before the client is known, so the verifier records the gap.
			const verified = await verifyJwt(idTokenHint, opts.keyStore, {
				type: "id_token",
				expectedIssuer: opts.issuer ?? "",
				legacyTypAccept: opts.legacyTypAccept ?? false,
				// Deliberately no revocation check: the hint names who is logging
				// out (OIDC RP-Initiated Logout 1.0); it is not a credential.
				revocation: "none",
				logger: opts.logger,
			});
			payload = verified.payload as Record<string, unknown>;
		} catch (err) {
			// The keystore did not answer: the server's outage, not a verdict
			// on the hint (`isVerificationUnavailable`). A confirmation page
			// would carry a hint that fails again the same way, so GET gets the
			// 503 too.
			if (isVerificationUnavailable(err)) {
				return refuseVerificationUnavailable(res, err, opts.logger ?? console, "logout");
			}
			// A hint that fails verification fails the confirmed POST too, so a
			// confirmation page would be a dead button: reject GET as well.
			return res.status(400).json({
				error: "invalid_token",
				error_description: "id_token_hint verification failed",
			});
		}

		// Step 2: Extract sid and the client the hint was issued to.
		const sid = typeof payload.sid === "string" ? payload.sid : null;
		const sub = typeof payload.sub === "string" ? payload.sub : null;
		const hintClient = issuedTo(payload);

		// A hint that names no session can log nothing out, on GET as on POST:
		// refused before the client repository is asked about its redirect, and
		// before a stale GET's confirmation page, whose "Sign out" could only
		// post the same hint back to this refusal.
		if (!sid) {
			return res.status(400).json({
				error: "invalid_request",
				error_description: "id_token_hint missing sid claim",
			});
		}

		// Held to the initiating client's registered list once, here — before the
		// confirmation page echoes it, before any RP or upstream hears of the
		// logout, and before the close — and the only value later steps read.
		// Unregistered or unknowable, it is `undefined` and the logout goes on.
		const validatedPostLogoutRedirectUri = await registeredPostLogoutRedirectUri(
			postLogoutRedirectUri,
			hintClient,
			opts.logger ?? console,
			"logout",
		);

		// What the upstream end-session call is handed beside its hint.
		const upstreamRequest: UpstreamEndRequest = {
			// Registered for the client, or none.
			postLogoutRedirectUri: validatedPostLogoutRedirectUri,
			state: typeof state === "string" ? state : undefined,
		};

		if (req.method === "GET") {
			const iat = typeof payload.iat === "number" ? payload.iat : 0;
			const maxAgeMs = 24 * 60 * 60 * 1000;
			if (Date.now() - iat * 1000 > maxAgeMs) {
				// Only a registered URI round-trips into the confirm page: an
				// unregistered one reflected on this origin would weaken the
				// invariant that a caller's URI never appears here.
				return renderLogoutConfirmation(res, {
					idTokenHint,
					postLogoutRedirectUri: validatedPostLogoutRedirectUri,
					state,
				});
			}
		}

		// Step 3: Load session. Missing → defensive 200 no-op.
		let session: Awaited<ReturnType<typeof opts.userSessionStore.get>>;
		try {
			session = await opts.userSessionStore.get(sid);
		} catch (err) {
			(opts.logger ?? console).error(
				{ store: "user_session", step: "get", err: loggableError(err) },
				"logout_store_unavailable",
			);
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "session store unavailable",
			});
		}

		if (!session) {
			// The store entry is already gone (expired, or deleted out of band):
			// nothing to close, but the cookie still has to end.
			await endBrowserSession(req, sid, opts.logger ?? console);
			return res.status(200).json({ logged_out: true });
		}

		const ended = await endThroughLifecycle(opts.sessionLifecycle, req, sid, sub, upstreamRequest);
		if (ended.outcome === "unavailable") {
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: ended.description,
			});
		}
		const { federations, endSessionUri } = ended;

		// End the browser's own session so the cookie stops satisfying
		// `/authorize`: after the session ended and before response selection, so
		// every success branch gets it once and the 503 above does not (a retry
		// needs the cookie).
		await endBrowserSession(req, sid, opts.logger ?? console);

		// Step 7: Select response.

		// Emitted once, for every success branch.
		emitAuditEvent(opts.auditSink, {
			timestamp: new Date(),
			type: "logout.success",
			subject: sub ?? undefined,
			ip: req.ip,
			userAgent: req.get("user-agent"),
			details: { sid, federations },
		});

		// Where the browser goes back to the RP, with its `state` (OIDC
		// RP-Initiated Logout 1.0 §3), for the redirect (7c). The front-channel
		// page (7a) is handed the parts and composes the same URL.
		let postLogoutRedirectTarget: string | undefined;
		if (validatedPostLogoutRedirectUri) {
			const redirectUrl = new URL(validatedPostLogoutRedirectUri);
			if (typeof state === "string" && state.length > 0) {
				redirectUrl.searchParams.set("state", state);
			}
			postLogoutRedirectTarget = redirectUrl.toString();
		}

		// 7a: Front-channel logout — if Accept: text/html AND any RP has an http(s) frontchannelLogoutUri.
		// Use q-weighted negotiation: application/json is first so Accept: */* defaults to JSON.
		// Only when text/html explicitly outranks json (e.g. browser requests) do we serve HTML.
		const negotiated = accepts(req).type(["application/json", "text/html"]);
		const acceptsHtml = negotiated === "text/html";
		// The relying parties' usable front-channel registrations, read only
		// for an HTML answer. With none, the logout answers as without
		// front-channel logout (7b–7d).
		const frontchannelRps = acceptsHtml ? await ended.frontchannelRps() : [];
		if (frontchannelRps.length > 0) {
			const html = renderFrontchannelLogoutHtml({
				rps: frontchannelRps,
				issuer: opts.issuer,
				sid,
				// The allowlist-validated URI and the RP's state, as parts: the
				// page checks the URI and appends the state itself.
				...(validatedPostLogoutRedirectUri
					? {
							postLogoutRedirect: {
								uri: validatedPostLogoutRedirectUri,
								state: typeof state === "string" ? state : undefined,
							},
						}
					: {}),
				logger: opts.logger,
			});
			res.setHeader("Content-Type", "text/html; charset=utf-8");
			return res.status(200).send(html);
		}

		// 7b: IdP end-session redirect.
		if (endSessionUri) {
			return res.redirect(303, endSessionUri);
		}

		// 7c: post_logout_redirect_uri — the registered value decided in Step 2.
		if (postLogoutRedirectTarget) {
			return res.redirect(303, postLogoutRedirectTarget);
		}

		// 7d: Default — JSON success.
		return res.status(200).json({ logged_out: true });
	};

	// POST /logout — mounted under /oauth → POST /oauth/logout
	router.post("/logout", express.urlencoded({ extended: false }), handleLogout);
	// GET /logout — mounted under /oauth → GET /oauth/logout
	router.get("/logout", handleLogout);

	return router;
}
