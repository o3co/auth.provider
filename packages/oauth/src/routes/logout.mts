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
	AuditSinkBase,
	ClientRepository,
	FederationProviderHandle,
	FederationTokenStoreBase,
	KeyStore,
	Logger,
	RefreshTokenFamilyRevocation,
	SessionFamilyIndex,
	SessionFederationIndex,
	SessionRPRegistry,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { emitAuditEvent } from "@o3co/auth-provider-core";
import accepts from "accepts";
import type { Request, RequestHandler, Response, Router } from "express";
import { decodeProtectedHeader, jwtVerify } from "jose";
import { broadcastBackchannelLogout } from "../logout/broadcastBackchannel.mjs";
import { cascadeLogout } from "../logout/cascadeLogout.mjs";
import { renderFrontchannelLogoutHtml } from "../logout/renderFrontchannel.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

/**
 * Minimal structural capability interface for OIDC RP-Initiated Logout.
 *
 * `SupportsLogout` and `FederationProviderBase` live in `@o3co/auth-provider-session`,
 * which depends on core — importing them here would create a circular package dependency.
 * This local structural type captures only the end-session surface needed by the logout route.
 * The `supportsEndSession` type guard below performs the duck-type check at runtime.
 */
interface SupportsEndSession {
	endSession(req: {
		idTokenHint?: string;
		postLogoutRedirectUri?: string;
		state?: string;
	}): Promise<{ url: URL; method: "GET" }>;
}

/**
 * Duck-type guard: does `provider` expose an `endSession` method?
 * Returns `false` for null/undefined so callers can pass Map.get() results directly.
 */
function supportsEndSession(
	provider: FederationProviderHandle | undefined | null,
): provider is FederationProviderHandle & SupportsEndSession {
	if (provider == null) return false;
	return typeof (provider as { endSession?: unknown }).endSession === "function";
}

export interface LogoutRouterOptions {
	keyStore: KeyStore;
	/** Issuer URL of this auth provider — used for logout_token `iss` claim and iframe `iss` param. */
	issuer: string;
	userSessionStore: UserSessionStore;
	sessionRPRegistry: SessionRPRegistry;
	sessionFamilyIndex: SessionFamilyIndex;
	sessionFederationIndex: SessionFederationIndex;
	federationTokenStore: FederationTokenStoreBase;
	refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	clientRepository: ClientRepository;
	/**
	 * Getter for the federation providers Map. Evaluated at request time (not at
	 * router construction time) so module init order does not matter — Task 6b
	 * will pass `() => context.federationProviders` rather than a captured Map
	 * reference. Returns undefined when federation is not configured.
	 */
	getFederationProviders: () => ReadonlyMap<string, FederationProviderHandle> | undefined;
	/** Override for unit tests. Defaults to the global `fetch`. */
	fetchImpl?: typeof fetch;
	/** Structured logger shared with broadcastBackchannelLogout and cascadeLogout. */
	logger?: Logger;
	/** Audit sink for operator observability events. No-op when undefined. */
	auditSink?: AuditSinkBase;
}

/**
 * OIDC RP-Initiated Logout 1.0 — POST /oauth/logout
 *
 * Accepts application/x-www-form-urlencoded with:
 *   - id_token_hint (required)
 *   - post_logout_redirect_uri (optional)
 *   - state (optional)
 *
 * Flow:
 *   1. Verify id_token_hint via keyStore. Fail → 400 invalid_token.
 *   2. Extract `sid` and `aud` (= client_id). Missing sid → 400 invalid_request.
 *   3. Load session from userSessionStore. Missing → 200 JSON { logged_out: true } (no-op).
 *   4. Broadcast Back-Channel Logout to all registered RPs (best-effort).
 *   5. Resolve IdP end-session URI for the first federation (if any, if provider supportsEndSession).
 *   6. Cascade logout (revokeFamily + deleteBySession + delete session).
 *   7. Respond: front-channel HTML | IdP redirect | post-logout redirect | 200 JSON.
 *
 * /oauth/federation/:name/logout is handled in Task 6b (not this file).
 */
export function createRouter(express: ExpressLike, opts: LogoutRouterOptions): Router {
	const router = express.Router();

	// POST /federation/:name/logout — mounted under /oauth → POST /oauth/federation/:name/logout
	router.post(
		"/federation/:name/logout",
		express.urlencoded({ extended: false }),
		async (req: Request, res: Response) => {
			const { name } = req.params as { name: string };
			const { post_logout_redirect_uri: postLogoutRedirectUri, state } = req.body as Record<
				string,
				string | undefined
			>;

			const logger = opts.logger ?? console;

			// RFC 6749 §5.1 / RFC 9207: cache headers on every response path.
			res.setHeader("Cache-Control", "no-store");
			res.setHeader("Pragma", "no-cache");

			// Step 1: Extract Bearer access_token from Authorization header.
			const auth = req.headers.authorization;
			// RFC 6750 §2.1: "Bearer" is case-insensitive in practice but the spec
			// uses "Bearer". We do a case-insensitive prefix check per §2.1 common usage.
			if (!auth || !/^Bearer /i.test(auth)) {
				res.setHeader(
					"WWW-Authenticate",
					'Bearer error="invalid_token", error_description="missing Bearer token"',
				);
				return res
					.status(401)
					.json({ error: "invalid_token", error_description: "missing Bearer token" });
			}
			const token = auth.slice(auth.indexOf(" ") + 1);

			// Step 2: Verify JWT signature + check typ === "at+jwt".
			// Reject refresh (rt+jwt), id (id+jwt), and logout (logout+jwt) tokens.
			let payload: Record<string, unknown>;
			try {
				const header = decodeProtectedHeader(token);
				if (header.typ !== "at+jwt") {
					throw new Error("invalid token type");
				}
				const key = await opts.keyStore.getVerificationKey(
					header.kid ?? opts.keyStore.getSigningKidFallback(),
				);
				const verified = await jwtVerify(token, key);
				payload = verified.payload as Record<string, unknown>;
			} catch (error) {
				// Log the reason at warn level — keep minimal (don't log the token itself,
				// since this path can be attacker-driven).
				logger.warn(
					`/oauth/federation/${name}/logout: jwtVerify failed:`,
					error instanceof Error ? error.message : String(error),
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

			// Step 3: Extract family_id, sid, sub from verified payload.
			const familyId = typeof payload.family_id === "string" ? payload.family_id : null;
			const sid = typeof payload.sid === "string" ? payload.sid : null;
			const sub = typeof payload.sub === "string" ? payload.sub : null;

			// Step 4: Check family revocation. Fail-closed: any throw → 401.
			if (familyId !== null) {
				let revoked: boolean;
				try {
					revoked = await opts.refreshTokenFamilyRevocation.isFamilyRevoked(familyId);
				} catch (error) {
					logger.warn(
						`/oauth/federation/${name}/logout: isFamilyRevoked failed (refresh store outage):`,
						error,
					);
					return res.status(401).json({
						error: "invalid_token",
						error_description: "revocation check unavailable",
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
				logger.warn(`/oauth/federation/${name}/logout: userSessionStore.get failed:`, error);
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
				logger.warn(
					`/oauth/federation/${name}/logout: sessionFederationIndex.listFederations failed:`,
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
					error_description: `federation "${name}" is not linked to this session`,
				});
			}

			// Step 8: Get federation tokens (may be null — best-effort idTokenHint).
			let fedTokens: Awaited<ReturnType<typeof opts.federationTokenStore.get>>;
			try {
				fedTokens = await opts.federationTokenStore.get(sid, name);
			} catch (error) {
				logger.warn(`/oauth/federation/${name}/logout: federationTokenStore.get failed:`, error);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "federation token store unavailable",
				});
			}

			// Step 9: Delete federation token record.
			try {
				await opts.federationTokenStore.delete(sid, name);
			} catch (error) {
				logger.warn(`/oauth/federation/${name}/logout: federationTokenStore.delete failed:`, error);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "federation token store unavailable",
				});
			}

			// Step 10: Remove federation link from session.
			try {
				await opts.sessionFederationIndex.removeFederation(sid, name);
			} catch (error) {
				logger.warn(
					`/oauth/federation/${name}/logout: sessionFederationIndex.removeFederation failed:`,
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
			if (supportsEndSession(provider)) {
				try {
					const endSessionResult = await provider.endSession({
						idTokenHint: fedTokens?.idToken ?? undefined,
						postLogoutRedirectUri:
							typeof postLogoutRedirectUri === "string" ? postLogoutRedirectUri : undefined,
						state: typeof state === "string" ? state : undefined,
					});
					// Local state already cleared — redirect to IdP end-session URL.
					emitAuditEvent(opts.auditSink, {
						timestamp: new Date(),
						type: "federation.logout.success",
						subject: sub ?? undefined,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { federation: name, redirected_to_idp: true },
					});
					return res.redirect(303, endSessionResult.url.toString());
				} catch (error) {
					// Best-effort: IdP logout failed but local state is already cleared.
					// Log at warn — "orphan IdP session" case, critical for operators.
					logger.warn(
						`/oauth/federation/${name}/logout: provider.endSession failed (orphan IdP session):`,
						error,
					);
					emitAuditEvent(opts.auditSink, {
						timestamp: new Date(),
						type: "federation.logout.idp_unreachable",
						subject: sub ?? undefined,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: {
							federation: name,
							error: error instanceof Error ? error.message : String(error),
						},
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
				details: { federation: name, redirected_to_idp: false },
			});
			return res.status(200).json({ disconnected: true });
		},
	);

	// POST /logout — mounted under /oauth → POST /oauth/logout
	router.post(
		"/logout",
		express.urlencoded({ extended: false }),
		async (req: Request, res: Response) => {
			// RFC 6749 §5.1 / RFC 9207: cache headers on every response path.
			res.setHeader("Cache-Control", "no-store");
			res.setHeader("Pragma", "no-cache");

			const {
				id_token_hint: idTokenHint,
				post_logout_redirect_uri: postLogoutRedirectUri,
				state,
			} = req.body as Record<string, string | undefined>;

			// Step 1: Verify id_token_hint.
			if (typeof idTokenHint !== "string" || idTokenHint.length === 0) {
				return res.status(400).json({
					error: "invalid_request",
					error_description: "id_token_hint is required",
				});
			}

			let payload: Record<string, unknown>;
			try {
				const header = decodeProtectedHeader(idTokenHint);
				const key = await opts.keyStore.getVerificationKey(
					header.kid ?? opts.keyStore.getSigningKidFallback(),
				);
				const verified = await jwtVerify(idTokenHint, key);
				payload = verified.payload as Record<string, unknown>;
			} catch {
				return res.status(400).json({
					error: "invalid_token",
					error_description: "id_token_hint verification failed",
				});
			}

			// Step 2: Extract sid and aud (client_id).
			const sid = typeof payload.sid === "string" ? payload.sid : null;
			const sub = typeof payload.sub === "string" ? payload.sub : null;
			const rawAud = payload.aud;
			const aud: string | null =
				typeof rawAud === "string"
					? rawAud
					: Array.isArray(rawAud) && typeof rawAud[0] === "string"
						? rawAud[0]
						: null;

			if (!sid) {
				return res.status(400).json({
					error: "invalid_request",
					error_description: "id_token_hint missing sid claim",
				});
			}

			// Step 3: Load session. Missing → defensive 200 no-op.
			let session: Awaited<ReturnType<typeof opts.userSessionStore.get>>;
			try {
				session = await opts.userSessionStore.get(sid);
			} catch (err) {
				const logger = opts.logger ?? console;
				logger.warn("POST /oauth/logout: userSessionStore.get failed", err);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "session store unavailable",
				});
			}

			if (!session) {
				return res.status(200).json({ logged_out: true });
			}

			// A4 §6.2 Step 1 (route-level read for pre-cascade ops):
			//   - rps: needed by broadcastBackchannelLogout (best-effort, before cascade)
			//   - federations: needed for IdP endSession redirect (route handler step 5)
			// familyIds is read internally by cascadeLogout per §6.2 Step 1.
			let rps: Awaited<ReturnType<typeof opts.sessionRPRegistry.listRPs>>;
			let federations: ReadonlyArray<string>;
			try {
				[rps, federations] = await Promise.all([
					opts.sessionRPRegistry.listRPs(sid),
					opts.sessionFederationIndex.listFederations(sid),
				]);
			} catch (err) {
				const logger = opts.logger ?? console;
				logger.warn("POST /oauth/logout: reverse-index read failed", err);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "session store unavailable",
				});
			}

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
				if (supportsEndSession(provider)) {
					try {
						let idTokenHintForIdP: string | undefined;
						try {
							const tokens = await opts.federationTokenStore.get(sid, firstFederation);
							idTokenHintForIdP = tokens?.idToken ?? undefined;
						} catch {
							// Best-effort: if we can't get the federation token, proceed without idTokenHint
						}
						const result = await provider.endSession({
							idTokenHint: idTokenHintForIdP,
							postLogoutRedirectUri:
								typeof postLogoutRedirectUri === "string" ? postLogoutRedirectUri : undefined,
							state: typeof state === "string" ? state : undefined,
						});
						endSessionUri = result.url.toString();
					} catch (err) {
						// Best-effort: log and proceed without IdP redirect
						const logger = opts.logger ?? console;
						logger.warn(`POST /oauth/logout: federation ${firstFederation} endSession failed`, err);
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

			// Validate post_logout_redirect_uri against the initiating client's allowlist ONCE.
			// Both the HTML branch (7a) and the redirect branch (7c) use this validated value.
			// Invalid or missing URIs become undefined — fall through to JSON fallback.
			let validatedPostLogoutRedirectUri: string | undefined;
			if (typeof postLogoutRedirectUri === "string" && postLogoutRedirectUri.length > 0 && aud) {
				try {
					const client = await opts.clientRepository.findById(aud);
					if (client?.postLogoutRedirectUris?.includes(postLogoutRedirectUri)) {
						validatedPostLogoutRedirectUri = postLogoutRedirectUri;
					}
				} catch {
					// Client repo throw → treat as unvalidated; fall through to JSON
				}
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
					// Use the allowlist-validated URI — prevents open redirect via HTML branch.
					postLogoutRedirectUri: validatedPostLogoutRedirectUri,
					logger: opts.logger,
				});
				res.setHeader("Content-Type", "text/html; charset=utf-8");
				return res.status(200).send(html);
			}

			// 7b: IdP end-session redirect.
			if (endSessionUri) {
				return res.redirect(303, endSessionUri);
			}

			// 7c: post_logout_redirect_uri — use the already-validated value (allowlist checked above).
			if (validatedPostLogoutRedirectUri) {
				const redirectUrl = new URL(validatedPostLogoutRedirectUri);
				if (typeof state === "string" && state.length > 0) {
					redirectUrl.searchParams.set("state", state);
				}
				return res.redirect(303, redirectUrl.toString());
			}

			// 7d: Default — JSON success.
			return res.status(200).json({ logged_out: true });
		},
	);

	return router;
}
