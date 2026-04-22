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
	ClientRepository,
	FederationProviderHandle,
	FederationTokenStoreBase,
	KeyStore,
	Logger,
	RefreshTokenStoreBase,
	UserSessionStoreBase,
} from "@o3co/auth-provider-core";
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
	userSessionStore: UserSessionStoreBase;
	federationTokenStore: FederationTokenStoreBase;
	refreshTokenStore: RefreshTokenStoreBase;
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

	// POST /logout — mounted under /oauth → POST /oauth/logout
	router.post(
		"/logout",
		express.urlencoded({ extended: false }),
		async (req: Request, res: Response) => {
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

			// Step 4: Broadcast Back-Channel Logout (best-effort — never throws).
			if (sub) {
				await broadcastBackchannelLogout({
					rps: session.activeRPs,
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
			const firstFederation = session.federations[0];
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
				familyIds: session.familyIds,
				refreshTokenStore: opts.refreshTokenStore,
				federationTokenStore: opts.federationTokenStore,
				userSessionStore: opts.userSessionStore,
				logger: opts.logger,
			});

			if (cascade.outcome === "failed") {
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "logout cascade failed",
				});
			}

			// Step 7: Select response.

			// 7a: Front-channel logout — if Accept: text/html AND any RP has a frontchannelLogoutUri.
			// Use q-weighted negotiation: application/json is first so Accept: */* defaults to JSON.
			// Only when text/html explicitly outranks json (e.g. browser requests) do we serve HTML.
			const negotiated = accepts(req).type(["application/json", "text/html"]);
			const acceptsHtml = negotiated === "text/html";
			const hasFrontchannel = session.activeRPs.some(
				(rp) => typeof rp.frontchannelLogoutUri === "string" && rp.frontchannelLogoutUri.length > 0,
			);
			if (acceptsHtml && hasFrontchannel) {
				const html = renderFrontchannelLogoutHtml({
					rps: session.activeRPs,
					issuer: opts.issuer,
					sid,
					postLogoutRedirectUri:
						typeof postLogoutRedirectUri === "string" ? postLogoutRedirectUri : undefined,
				});
				res.setHeader("Content-Type", "text/html; charset=utf-8");
				return res.status(200).send(html);
			}

			// 7b: IdP end-session redirect.
			if (endSessionUri) {
				return res.redirect(303, endSessionUri);
			}

			// 7c: post_logout_redirect_uri — validate against client allowlist.
			if (typeof postLogoutRedirectUri === "string" && postLogoutRedirectUri.length > 0 && aud) {
				let client: Awaited<ReturnType<typeof opts.clientRepository.findById>> | null = null;
				try {
					client = await opts.clientRepository.findById(aud);
				} catch {
					// Fall through to JSON on lookup failure
				}
				if (client?.postLogoutRedirectUris?.includes(postLogoutRedirectUri)) {
					const redirectUrl = new URL(postLogoutRedirectUri);
					if (typeof state === "string" && state.length > 0) {
						redirectUrl.searchParams.set("state", state);
					}
					return res.redirect(303, redirectUrl.toString());
				}
			}

			// 7d: Default — JSON success.
			return res.status(200).json({ logged_out: true });
		},
	);

	return router;
}
