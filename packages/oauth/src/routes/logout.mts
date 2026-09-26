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
import { refuseVerificationUnavailable } from "../verificationUnavailable.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

/**
 * The slice of the express-session bag this route touches. Every field is
 * optional at runtime even where `@types/express-session` says otherwise: a
 * deployment may mount `/oauth/logout` with no session middleware at all (the
 * pure back-channel shape), and a session written before the login wiring
 * recorded `sid` carries none.
 */
interface BrowserSessionLike {
	sid?: unknown;
	destroy?: (callback: (err?: unknown) => void) => unknown;
}

/**
 * R1a — ends the browser session that owns `sid`.
 *
 * The cascade deletes the `UserSession` record, but the express-session is a
 * separate object: until this ran, the same cookie kept satisfying
 * `req.session.isAuthenticated` at `/authorize`, which went on minting
 * authorization codes carrying the now-dead `sid` that `/token` then refused
 * with `invalid_grant`. The user saw a login loop with no login page for up
 * to `session.maxAge`, and `prompt=login` is refused by this provider (#284),
 * so no RP could force its way out.
 *
 * Scope — the substance of this helper. RP-initiated logout is a request any
 * party may make about any session, so the cookie that happens to ride along
 * on the request is NOT evidence that this browser owns the session being
 * logged out. It is compared against `sid` first: a cookie naming a different
 * `sid`, or naming none at all, is left alone, because destroying it would
 * sign out an unrelated user on the strength of an id_token they never held.
 * A browser session that recorded no `sid` at all is therefore left alone by
 * both halves of R1 — this helper and `/authorize`'s liveness check, which
 * also stands aside when there is no `sid` to resolve. That is deliberate, and
 * it does not leave the loop open:
 *
 *   - Such a session cannot be the subject of an RP-initiated logout in the
 *     first place. Step 2 refuses an `id_token_hint` carrying no `sid` with
 *     `400 invalid_request` long before this helper runs, so there is no
 *     logout whose effect could be missed.
 *   - Where a `userSessionStore` IS wired, a code minted from such a session
 *     is refused at the token endpoint (`grants/authorization.mts`, the
 *     `userSessionStore && !sid` guard), so it buys no token either.
 *   - Where one is NOT wired there are no `UserSession` records to delete, no
 *     `sid` on any token, and no RP-initiated logout at all — the
 *     backward-compatible composition this endpoint has always declined to
 *     serve.
 *
 * Refusing such a session at `/authorize` instead would revoke authentication
 * from every deployment whose own login route sets `isAuthenticated` without
 * recording a `sid`, which is a supported wiring; absence of a `sid` is not
 * evidence of a dead session.
 *
 * Failure is logged, never propagated. By the time this runs the cascade has
 * already succeeded; reporting the whole logout as failed would invite a
 * retry of a cascade that already ran, and a cookie the session store could
 * not delete is the weaker of the two failures — R1b refuses it at
 * `/authorize` regardless.
 *
 * Takes `EventLogger`, not `Logger`: the route's own fallback is
 * `opts.logger ?? console`, and `console` cannot satisfy `Logger` (no `fatal`,
 * no `child`). This helper only ever emits one named structured event, which
 * is exactly the narrow shape `EventLogger` exists for.
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
	// Pass the original logout params through as hidden inputs so that the
	// confirmed POST can complete the standard hint-based flow. Without this,
	// the POST handler rejects with 400 invalid_request because id_token_hint
	// is missing — the "Sign out" button would never actually log out.
	// `action=""` posts to the current URL: this avoids a relative-URL trap
	// when /oauth/logout is reached with a trailing slash (`/oauth/logout/`),
	// where `action="logout"` would resolve to `/oauth/logout/logout`.
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
	 * Getter for the federation providers Map. Evaluated at request time (not at
	 * router construction time) so module init order does not matter — Task 6b
	 * will pass `() => context.federationProviders` rather than a captured Map
	 * reference. Returns undefined when federation is not configured.
	 */
	getFederationProviders: () => ReadonlyMap<string, FederationProvider> | undefined;
	/** Override for unit tests. Defaults to the global `fetch`. */
	fetchImpl?: typeof fetch;
	/** Structured logger shared with broadcastBackchannelLogout and cascadeLogout. */
	logger?: Logger;
	/** Audit sink for operator observability events. No-op when undefined. */
	auditSink?: AuditSink;
	/**
	 * SF-1 / Phase G / S2: when true, the central JWT verifier
	 * accepts tokens whose `typ` header is absent and emits a
	 * `jwt_verify_legacy_typ` deprecation warning. the default is
	 * `false` (typ-less tokens rejected); `true` is an explicit
	 * legacy-acceptance opt-in. The v0.5.x default was `true`. Forwarded
	 * to `verifyJwt` for the bearer AT and id_token_hint paths.
	 */
	legacyTypAccept?: boolean;
}

/**
 * OIDC RP-Initiated Logout 1.0 — GET/POST /oauth/logout
 *
 * Accepts application/x-www-form-urlencoded POST body or GET query with:
 *   - id_token_hint (required)
 *   - post_logout_redirect_uri (optional)
 *   - state (optional)
 *
 * Flow:
 *   1. Verify id_token_hint via keyStore. Fail → 400 invalid_token, on GET as
 *      on POST; a keystore that cannot answer → 503.
 *   2. Extract `sid` and the client the hint was issued to (`issuedTo`).
 *      Missing sid → 400 invalid_request. Hold `post_logout_redirect_uri` to
 *      the client's registered `postLogoutRedirectUris` — the one value every
 *      later step uses. A GET whose hint is stale answers the confirmation
 *      page here.
 *   3. Load session from userSessionStore. Missing → 200 JSON { logged_out: true } (no-op).
 *   4. Broadcast Back-Channel Logout to all registered RPs (best-effort).
 *   5. Resolve IdP end-session URI for the first federation (if any, if provider supportsEndSession).
 *   6. Cascade logout (revokeFamily + removeBySid + delete session).
 *   7. Respond: front-channel HTML | IdP redirect | post-logout redirect | 200 JSON.
 *
 * `POST /oauth/federation/:name/logout`, the bearer-authenticated disconnect of
 * one federation, is the other route this router mounts; it holds
 * `post_logout_redirect_uri` to the same rule, for the access token's `azp`.
 */
export function createRouter(express: ExpressLike, opts: LogoutRouterOptions): Router {
	const router = express.Router();

	// Every store a logout route reads or writes that cannot answer is `503`,
	// logged once at error level — `federation_logout_store_unavailable` for
	// the federation logout, `logout_store_unavailable` for RP-initiated
	// logout — `store` naming which and `step` the operation, with the error's
	// projection, never the error: a store's error carries the command it
	// refused. The client repository, asked only to check a
	// `post_logout_redirect_uri`, is the one exception to the event name: its
	// line is core's `client_repository_unavailable`, as at every other client
	// lookup (`registeredPostLogoutRedirectUri`).
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
		store: "user_session" | "session_rp_registry" | "session_federation_index",
		step: "get" | "list",
		error: unknown,
		/** A second store that failed in the same read, already projected. */
		also: { readonly alsoUnavailable?: { readonly store: string; readonly err: unknown } } = {},
	): void => {
		logger.error({ store, step, err: loggableError(error), ...also }, "logout_store_unavailable");
	};

	/**
	 * The `post_logout_redirect_uri` a logout may pass on: the caller's value
	 * when it is exactly, byte for byte, one of the client's registered
	 * `postLogoutRedirectUris`, and otherwise nothing — for no value, no client
	 * to hold it to, or a client this deployment does not know. OIDC
	 * RP-Initiated Logout 1.0 §3: the OP MUST NOT redirect to a
	 * `post_logout_redirect_uri` that does not match one registered for the
	 * client.
	 *
	 * Decided before any other step sees the value, and nothing else is passed
	 * on: a federation's `endSession()` is handed this or `undefined`. An
	 * adapter for an upstream that publishes no end-session endpoint (Google,
	 * GitHub, Apple) redirects straight to the URI it is handed, and one with an
	 * endpoint forwards it to the upstream — handed the caller's value, this
	 * provider's origin answered `303` to any site.
	 *
	 * The client repository is asked only when there is a value to check, so a
	 * logout that names none does not depend on it. When it cannot answer, the
	 * URI is not used — an outage says nothing about whether it is registered —
	 * and the logout goes on as if none had been sent, logged once at error as
	 * `client_repository_unavailable` with `site`. Refusing the logout instead
	 * would keep the session, its refresh-token families and the relying
	 * parties' sessions alive to protect a redirect, and OIDC RP-Initiated
	 * Logout forbids only the redirect.
	 *
	 * A match is also held to the shape every registration is held to at boot
	 * (core's `checkRedirectUri`: an absolute URL, no fragment or userinfo,
	 * `https:` — `http:` on loopback — or a reverse-domain custom scheme).
	 * `ClientEntrySchema` enforces it for the bundled repositories; a custom
	 * `ClientRepository` bypasses that schema, and an entry it holds that the
	 * parser cannot read, or in an executable scheme (`javascript:`), is no place
	 * to send a browser: the first made the redirect's `new URL()` throw after
	 * the cascade, the second ran on this origin from the front-channel page.
	 * Such a match is dropped like an unregistered URI, and the logout goes on,
	 * with one warn — `logout_registered_redirect_uri_refused`, naming `site`,
	 * the client and the rejection's `reason`, never the entry — since it is a
	 * registration the operator has to fix.
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

			// Step 2: SF-1 — alg / iss / typ + signature pinned by the central
			// verifier. typ must be at+jwt (refresh and id_tokens are signed by
			// the same KeyStore so a typ check is the only defense against
			// cross-type acceptance). Audience is deferred — bearer-as-credential
			// route, calling-client identity is not separately authenticated
			// here; the verifier records the gap via `jwt_verify_aud_skipped`.
			let payload: Record<string, unknown>;
			try {
				const verified = await verifyJwt(token, opts.keyStore, {
					type: "access_token",
					expectedIssuer: opts.issuer ?? "",
					legacyTypAccept: opts.legacyTypAccept ?? false,
					// #367: deliberate. Logout only destroys the session the token
					// names — a safe, idempotent direction for a revoked token, and
					// exactly what a user does right after a credential-change
					// cascade (#322). Consulting revocation here would strand them
					// logged in.
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
				// The verifier's reason alone, never the token: this path can be
				// attacker-driven, and the verifier's message quotes what the token
				// carries (the `typ` header, read before the signature is checked,
				// and claims). The verifier has already logged its own
				// `jwt_verify_rejected`. `verifyJwt` throws nothing but its verdict;
				// anything else would be logged as its projection.
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

			// Step 4: Check family revocation. Fail-closed: a throw → 503, the
			// outage it is — as the session store's below — never `401
			// invalid_token` (RFC 6750 §3.1 describes the token, and nobody
			// could judge it).
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

			// Step 7: Verify the named federation is linked to this session.
			// A4 §6.2 Step 1: read federation index once for membership check.
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

			// Step 11: Attempt IdP end-session redirect (best-effort).
			// getFederationProviders() is called at request time (lazy) so module init order
			// does not affect resolution — the closure captures `context` by reference.
			const provider = opts.getFederationProviders()?.get(name);
			// `supportsLogout` is core's, and so is the capability it narrows to.
			// This route carried a structural copy of both while the contract lived
			// in `@o3co/auth-provider-session`, which depends on core (#626 P1). It
			// answers `false` for a missing provider, so the `get` result goes
			// straight in.
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
			// SF-1: pin alg / iss / typ (=JWT; the pre-#394 `id+jwt` spelling
			// was accepted through the #394 window, which #402 closed) +
			// signature. Audience is
			// derived from the id_token's aud claim post-verification (the
			// id_token was issued for a specific client); we can't pin aud
			// before knowing the client, so the verifier records the gap.
			const verified = await verifyJwt(idTokenHint, opts.keyStore, {
				type: "id_token",
				expectedIssuer: opts.issuer ?? "",
				legacyTypAccept: opts.legacyTypAccept ?? false,
				// #367: deliberate. An id_token_hint names WHO is logging out
				// (OIDC RP-Initiated Logout 1.0); it is not presented as a
				// credential, and the jti denylist tracks access tokens anyway.
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
			// Invalid signature / iss / typ. The POST verifier uses identical
			// options, so a hint that fails GET verification will deterministically
			// fail POST verification too — rendering a confirmation page with
			// the same hint passed through hidden inputs would just produce a
			// "Sign out" button that returns 400 invalid_token. Reject directly
			// for GET as well as POST.
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

		// The post_logout_redirect_uri this logout may use, held to the initiating
		// client's registered list once, here — before the confirmation page
		// echoes it, before any RP or upstream hears of the logout, and before
		// the cascade — and the only value every later step reads: the upstream
		// end-session call (Step 5), the front-channel page (7a) and the redirect
		// (7c). Unregistered, missing, or unknowable because the client
		// repository cannot answer, it is `undefined`, and the logout goes on.
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
			// R1a: the store entry is already gone — expired, or deleted out of
			// band — which is exactly the state a browser gets stuck in. There
			// is no cascade to run, but the cookie still has to end.
			await endBrowserSession(req, sid, opts.logger ?? console);
			return res.status(200).json({ logged_out: true });
		}

		// A4 §6.2 Step 1 (route-level read for pre-cascade ops):
		//   - rps: needed by broadcastBackchannelLogout (best-effort, before cascade)
		//   - federations: needed for IdP endSession redirect (route handler step 5)
		// familyIds is read internally by cascadeLogout per §6.2 Step 1.
		// Both read together, and one line for the outage: `store` names the
		// relying-party registry when it failed, else the federation index.
		// When both failed, the federation index's failure rides on the same
		// line as `alsoUnavailable` — one outage, one line, nothing dropped.
		const [rpsRead, federationsRead] = await Promise.allSettled([
			opts.sessionRPRegistry.listRPs(sid),
			opts.sessionFederationIndex.listFederations(sid),
		]);
		if (rpsRead.status === "rejected" || federationsRead.status === "rejected") {
			if (rpsRead.status === "rejected") {
				logoutStoreUnavailable(
					opts.logger ?? console,
					"session_rp_registry",
					"list",
					rpsRead.reason,
					federationsRead.status === "rejected"
						? {
								alsoUnavailable: {
									store: "session_federation_index",
									err: loggableError(federationsRead.reason),
								},
							}
						: {},
				);
			} else if (federationsRead.status === "rejected") {
				logoutStoreUnavailable(
					opts.logger ?? console,
					"session_federation_index",
					"list",
					federationsRead.reason,
				);
			}
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "session store unavailable",
			});
		}
		const rps = rpsRead.value;
		const federations: ReadonlyArray<string> = federationsRead.value;

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

		// Step 5: Resolve IdP end-session URI for the FIRST federation (spec Open Issue #2).
		// getFederationProviders() is called at request time so module init order does not matter.
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

		// R1a: the cascade emptied the stores; now end the browser's own
		// session so the cookie stops satisfying `/authorize`. Placed here —
		// after the cascade, ahead of response selection — so every success
		// branch (front-channel HTML / IdP redirect / post-logout redirect /
		// JSON) gets it exactly once, and the 503 above deliberately does not:
		// a retry needs the cookie to still name the session.
		await endBrowserSession(req, sid, opts.logger ?? console);

		// Step 7: Select response.

		// Emit logout.success before all terminal success response paths.
		// Placed here (after cascade, before response selection) so every
		// success branch (HTML / IdP redirect / post-logout redirect / JSON)
		// emits exactly once without duplicating the call.
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
