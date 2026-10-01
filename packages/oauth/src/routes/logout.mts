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
	SessionFamilyIndex,
	SessionFederationIndex,
	SessionRPRegistry,
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
import { broadcastBackchannelLogout } from "../logout/broadcastBackchannel.mjs";
import { cascadeLogout } from "../logout/cascadeLogout.mjs";
import { renderFrontchannelLogoutHtml } from "../logout/renderFrontchannel.mjs";
import { beginLogout } from "../logout/sessionEnd.mjs";
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
 * Ends the browser session that owns `sid`. The cascade deletes the
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
 * Failures are logged, never propagated: the cascade already succeeded, and
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
	userSessionStore: UserSessionStore;
	sessionRPRegistry: SessionRPRegistry;
	sessionFamilyIndex: SessionFamilyIndex;
	sessionFederationIndex: SessionFederationIndex;
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
	/** Structured logger shared with broadcastBackchannelLogout and cascadeLogout. */
	logger?: Logger;
	/** Audit sink for operator observability events. No-op when undefined. */
	auditSink?: AuditSink;
	/**
	 * Accept tokens with no `typ` header, logging `jwt_verify_legacy_typ`.
	 * Default `false`; `true` is a legacy opt-in. Applies to the bearer access
	 * token and the id_token_hint.
	 */
	legacyTypAccept?: boolean;
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
 *   4. broadcast back-channel logout (best effort);
 *   5. resolve the first federation's IdP end-session URI, if supported;
 *   6. run the cascade;
 *   7. respond: front-channel HTML | IdP redirect | post-logout redirect | JSON.
 *
 * Also mounts `POST /oauth/federation/:name/logout`, the bearer-authenticated
 * disconnect of one federation, which holds `post_logout_redirect_uri` to the
 * same rule for the access token's `azp`.
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
		store: "user_session" | "session_federation_index" | "federation_token",
		step: "get" | "list" | "delete" | "remove",
		error: unknown,
	): void => {
		logger.error(
			{ federation, store, step, err: loggableError(error) },
			"federation_logout_store_unavailable",
		);
	};
	const logoutStoreUnavailable = (
		logger: EventLogger,
		store:
			| "user_session"
			| "session_rp_registry"
			| "session_federation_index"
			| "session_family_index",
		step: "get" | "list" | "endSession",
		error: unknown,
		/** What the failure left of the session, and a second store that failed in the same read, already projected. */
		also: {
			readonly session?: string;
			readonly alsoUnavailable?: { readonly store: string; readonly err: unknown };
		} = {},
	): void => {
		logger.error({ store, step, err: loggableError(error), ...also }, "logout_store_unavailable");
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

			// Step 6: Load session. null → 401 (no session = token is effectively invalid).
			let session: Awaited<ReturnType<typeof opts.userSessionStore.get>>;
			try {
				session = await opts.userSessionStore.get(sid);
			} catch (error) {
				federationLogoutStoreUnavailable(logger, federation, "user_session", "get", error);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "session store unavailable",
				});
			}
			if (!session) {
				res.setHeader(
					"WWW-Authenticate",
					'Bearer error="invalid_token", error_description="session not found"',
				);
				return res.status(401).json({
					error: "invalid_token",
					error_description: "session not found",
				});
			}

			// Step 7: the named federation must be linked to this session.
			let federations: ReadonlyArray<string>;
			try {
				federations = await opts.sessionFederationIndex.listFederations(sid);
			} catch (error) {
				federationLogoutStoreUnavailable(
					logger,
					federation,
					"session_federation_index",
					"list",
					error,
				);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "session store unavailable",
				});
			}

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

			// Step 10: Remove federation link from session.
			try {
				await opts.sessionFederationIndex.removeFederation(sid, name);
			} catch (error) {
				federationLogoutStoreUnavailable(
					logger,
					federation,
					"session_federation_index",
					"remove",
					error,
				);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "session store unavailable",
				});
			}

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
		// logout, and before the cascade — and the only value later steps read.
		// Unregistered or unknowable, it is `undefined` and the logout goes on.
		const validatedPostLogoutRedirectUri = await registeredPostLogoutRedirectUri(
			postLogoutRedirectUri,
			hintClient,
			opts.logger ?? console,
			"logout",
		);

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
			logoutStoreUnavailable(opts.logger ?? console, "user_session", "get", err);
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "session store unavailable",
			});
		}

		if (!session) {
			// The store entry is already gone (expired, or deleted out of band):
			// no cascade to run, but the cookie still has to end.
			await endBrowserSession(req, sid, opts.logger ?? console);
			return res.status(200).json({ logged_out: true });
		}

		// Begin the logout: the relying parties to tell, the federations, and
		// what the cascade starts from. An outage is one log line, saying what
		// it left of the session.
		const begun = await beginLogout(opts, sid, session.expiresAt);
		if (begun.outcome === "unavailable") {
			const { store, step, session: left, error, alsoUnavailable } = begun.outage;
			logoutStoreUnavailable(opts.logger ?? console, store, step, error, {
				session: left,
				...(alsoUnavailable
					? {
							alsoUnavailable: {
								store: alsoUnavailable.store,
								err: loggableError(alsoUnavailable.error),
							},
						}
					: {}),
			});
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "session store unavailable",
			});
		}
		const { rps, federations } = begun;

		// Step 4: Broadcast Back-Channel Logout (best-effort — never throws).
		if (sub) {
			await broadcastBackchannelLogout({
				rps,
				issuer: opts.issuer,
				sub,
				sid,
				keyStore: opts.keyStore,
				fetchImpl: opts.fetchImpl,
				logger: opts.logger,
			});
		}

		// Step 5: resolve the IdP end-session URI for the first federation only.
		// Providers are looked up per request.
		let endSessionUri: string | undefined;
		const firstFederation = federations[0];
		if (firstFederation) {
			const providers = opts.getFederationProviders();
			const provider = providers?.get(firstFederation);
			if (supportsLogout(provider)) {
				try {
					let idTokenHintForIdP: string | undefined;
					try {
						const tokens = await opts.federationTokenStore.get(sid, firstFederation);
						idTokenHintForIdP = tokens?.idToken ?? undefined;
					} catch (err) {
						// Best effort: the logout proceeds, and the upstream end-session
						// call goes without `id_token_hint` — the IdP may then ask the
						// user to confirm, or choose the account itself. Said once, at
						// warn: the route answers as it would have, not a 503.
						(opts.logger ?? console).warn(
							{
								federation: auditErrorText(firstFederation),
								store: "federation_token",
								step: "get",
								err: loggableError(err),
							},
							"logout_federation_token_read_failed",
						);
					}
					const result = await provider.endSession({
						idTokenHint: idTokenHintForIdP,
						// Registered for the client, or none (Step 2).
						postLogoutRedirectUri: validatedPostLogoutRedirectUri,
						state: typeof state === "string" ? state : undefined,
					});
					endSessionUri = result.url.toString();
				} catch (err) {
					// Best-effort: log and proceed without the IdP redirect.
					(opts.logger ?? console).warn(
						{ federation: auditErrorText(firstFederation), err: loggableError(err) },
						"logout_federation_end_session_failed",
					);
				}
			}
		}

		// Step 6: Cascade logout.
		const cascade = await cascadeLogout({
			sid,
			expiresAt: session.expiresAt,
			familyIds: begun.familyIds,
			refreshTokenFamilyRevocation: opts.refreshTokenFamilyRevocation,
			federationTokenStore: opts.federationTokenStore,
			userSessionStore: opts.userSessionStore,
			sessionRPRegistry: opts.sessionRPRegistry,
			sessionFamilyIndex: opts.sessionFamilyIndex,
			sessionFederationIndex: opts.sessionFederationIndex,
			logger: opts.logger,
		});

		if (cascade.outcome === "failed") {
			// The outage's one error-level line. Which step stopped the cascade,
			// and how many operations failed there; the first failure's
			// projection (each step-2 failure also has its own structured warn
			// line from `cascadeLogout`).
			(opts.logger ?? console).error(
				{
					store: "logout_cascade",
					cascadeStep: cascade.step,
					failures: cascade.errors.length,
					err: loggableError(cascade.errors[0]),
				},
				"logout_store_unavailable",
			);
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "logout.cascade_failed",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { sid, step: cascade.step },
			});
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "logout cascade failed",
			});
		}

		// End the browser's own session so the cookie stops satisfying
		// `/authorize`: after the cascade and before response selection, so
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
		// RP-Initiated Logout 1.0 §3): the same URL from the front-channel page
		// (7a) and the redirect (7c).
		let postLogoutRedirectTarget: string | undefined;
		if (validatedPostLogoutRedirectUri) {
			const redirectUrl = new URL(validatedPostLogoutRedirectUri);
			if (typeof state === "string" && state.length > 0) {
				redirectUrl.searchParams.set("state", state);
			}
			postLogoutRedirectTarget = redirectUrl.toString();
		}

		// 7a: Front-channel logout — if Accept: text/html AND any RP has a frontchannelLogoutUri.
		// Use q-weighted negotiation: application/json is first so Accept: */* defaults to JSON.
		// Only when text/html explicitly outranks json (e.g. browser requests) do we serve HTML.
		const negotiated = accepts(req).type(["application/json", "text/html"]);
		const acceptsHtml = negotiated === "text/html";
		const hasFrontchannel = rps.some(
			(rp) => typeof rp.frontchannelLogoutUri === "string" && rp.frontchannelLogoutUri.length > 0,
		);
		if (acceptsHtml && hasFrontchannel) {
			const html = renderFrontchannelLogoutHtml({
				rps,
				issuer: opts.issuer,
				sid,
				// The allowlist-validated URI, with state — prevents open redirect via HTML branch.
				postLogoutRedirectUri: postLogoutRedirectTarget,
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
