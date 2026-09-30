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
	type AccessTokenDenylist,
	type AppConfig,
	type AuditSink,
	auditedError,
	type ClientRepository,
	type CodeRepository,
	type ConsentStore,
	checkResolver,
	consoleLogger,
	createRateLimitGuard,
	emitAuditEvent,
	type FederationProvider,
	type FederationTokenStore,
	formatObject,
	type GrantHandlerResolver,
	type GrantPolicyHook,
	isVerificationUnavailable,
	JwtVerificationError,
	type KeyStore,
	type Logger,
	type LoginEntry,
	livenessSidOf,
	loggableError,
	type PendingConsentStore,
	type RateLimiter,
	type RefreshTokenFamilyRevocation,
	type ReplaySeenSet,
	readAccessTokenRevocationMode,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRequirementResolver,
	type SessionRPRegistry,
	type SubjectRevocation,
	tokenTypeForConfirmation,
	type UserSessionStore,
	verifyJwt,
	wellFormedAcr,
	wellFormedAmr,
	wellFormedAuthTime,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
// Session data type augmentation. /authorize writes no identity binding into
// the session (`Code.client_id` and `Code.redirect_uri` carry it); `code` is
// kept because the /token grant clears it from older sessions (see
// authorization.mts `sessionMutation.clear`).
import type {} from "express-session";
import { parseAccessTokenHeader } from "./accessTokenHeader.mjs";
import type { ClientIdMetadataDocumentOptions } from "./clients/clientIdMetadataDocument.mjs";
import { createClientAuthMiddleware } from "./middleware/clientAuth.mjs";
import { OAUTH_RATE_LIMIT_PREFIXES } from "./rateLimitPrefixes.mjs";
import { createAuthorizeHandler } from "./routes/authorize.mjs";
import { createConsentRouter } from "./routes/consent.mjs";
import * as federationTokenRoute from "./routes/federationToken.mjs";
import * as logoutRoute from "./routes/logout.mjs";
import { createRevokeRouter } from "./routes/revoke.mjs";
import { resolveRouterSettings } from "./routes/routerSettings.mjs";
import { createTokenHandler } from "./routes/token.mjs";
import * as userinfo from "./routes/userinfo.mjs";
import {
	extractConfirmation,
	type IntrospectResponse,
	isCompoundConfirmation,
} from "./types/introspect.mjs";
import { refuseVerificationUnavailable } from "./verificationUnavailable.mjs";

/**
 * The login page `/authorize` sends a browser that is not signed in to: the
 * `loginEntry` slot. Required to serve `/authorize`, and read here, when the
 * endpoint is built, so an entry that names no page refuses boot rather than
 * the first such browser.
 */
const requireLoginEntry = (entry: LoginEntry | undefined): LoginEntry => {
	if (entry === undefined) {
		throw new Error(
			"/authorize sends a browser that is not signed in to the login page, which the loginEntry slot names, and no module provides it: install the session module (sessionModule), which provides it, or a module of your own that does",
		);
	}
	void entry.url;
	return entry;
};

declare module "express-session" {
	interface SessionData {
		client?: Record<string, unknown>;
		user?: Record<string, unknown>;
		code?: string;
		isAuthenticated?: boolean;
		/** UserSession ID — set by the federation callback hook or local login (`POST /session/login`) and preserved across session regeneration. */
		sid?: string;
	}
}

/**
 * Every path this router serves, its sub-routers' included — the only
 * requests whose bodies it parses. The authorize, logout, federation-token
 * and consent routes are listed only when mounted, so a deployment's own
 * route at one of those paths receives its body unread too.
 *
 * Other modules mount routes under `/oauth` too (the device grant,
 * federation grants, WebAuthn, a deployment's own), and `body-parser` does
 * not parse a body twice: parsers running for every request beneath `/oauth`
 * would consume those routes' streams, and their own parser, limit and media
 * types would silently never run, depending on module order. Hence a route
 * on exactly these paths (`router.all`), not `router.use`, which would also
 * match `/token/custom`. `bodyParsing.test.mts` holds this list to the
 * router's routes.
 *
 * @internal Exported for that test only; not part of the package's API.
 */
export const oauthRoutePaths = (mounted: {
	readonly authorize: boolean;
	readonly logout: boolean;
	readonly federationToken: boolean;
	readonly consent: boolean;
}): string[] => [
	"/token",
	"/introspect",
	...(mounted.authorize ? ["/authorize"] : []),
	"/userinfo",
	"/revoke",
	...(mounted.logout ? ["/logout", "/federation/:name/logout"] : []),
	...(mounted.federationToken ? ["/federation/:name/token"] : []),
	...(mounted.consent ? ["/consent"] : []),
];

export const createOAuthRouter = async (
	express: {
		Router: () => Router;
		json: () => RequestHandler;
		urlencoded: (opts: { extended: boolean }) => RequestHandler;
	},
	{
		registry,
		config,
		clientRepository: registeredClients,
		codeRepository,
		keyStore,
		rateLimiter,
		auditSink,
		grantPolicy,
		refreshTokenFamilyRevocation,
		accessTokenDenylist,
		subjectRevocation,
		userSessionStore,
		sessionRPRegistry,
		sessionFamilyIndex,
		sessionFederationIndex,
		federationTokenStore,
		replaySeenSet,
		consentStore,
		pendingConsentStore,
		loginEntry,
		clientIdMetadataDocuments: clientIdMetadataDocumentSeams = {},
		getFederationProviders = () => undefined,
		requirements,
		logger = consoleLogger,
	}: {
		/**
		 * Where `/oauth/token` looks a `grant_type` up, and whether `/authorize`
		 * is mounted: only when it holds the `authorization_code` grant as the
		 * router is built — `/token` reads it per request, `/authorize` once
		 * here. Only `get` is read —
		 * `grant_types_supported` is derived in `module.mts` from the planner's
		 * resolver, not from this one — so this is the contract: the
		 * planner's `GrantHandlerResolver` satisfies it, and so does a test's
		 * bare `GrantRegistry`.
		 */
		registry: Pick<GrantHandlerResolver, "get">;
		config: AppConfig;
		clientRepository: ClientRepository;
		/**
		 * Where `/authorize` issues its codes. Required when `registry` holds
		 * the `authorization_code` grant, which redeems them; the router
		 * mounts no `/authorize` without that grant and reads none.
		 */
		codeRepository?: CodeRepository;
		keyStore: KeyStore;
		rateLimiter?: RateLimiter;
		auditSink?: AuditSink;
		grantPolicy?: GrantPolicyHook;
		refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
		/** RFC 7009 access-token revocation. Optional: when absent, AT revocation is a warn-logged no-op. */
		accessTokenDenylist?: AccessTokenDenylist;
		/**
		 * Per-subject access-token watermark. The subject-level companion
		 * to `accessTokenDenylist`: the denylist revokes a token the client named,
		 * this revokes every token a subject held as of a credential change, which
		 * cannot be expressed as a set of jtis. Forwarded to every surface that
		 * already consults the denylist, so a watermark written by
		 * `revokeAllForSubject` is honoured rather than inert.
		 */
		subjectRevocation?: SubjectRevocation;
		userSessionStore?: UserSessionStore;
		sessionRPRegistry?: SessionRPRegistry;
		sessionFamilyIndex?: SessionFamilyIndex;
		sessionFederationIndex?: SessionFederationIndex;
		federationTokenStore?: FederationTokenStore;
		/**
		 * The `jti` single-use record for `private_key_jwt` client
		 * assertions, consulted by every client-authenticated endpoint here.
		 * Optional to wire; an assertion request without it is `server_error`.
		 */
		replaySeenSet?: ReplaySeenSet;
		/**
		 * Where an end-user's consent to a client that is not first-party
		 * is recorded. Optional: without it `/authorize` refuses such clients
		 * and the consent endpoints are not mounted.
		 */
		consentStore?: ConsentStore;
		/**
		 * Where a request is parked while the consent page asks, consumed
		 * by exactly one answer. Wired with `consentStore`: the bundled memory
		 * module provides both, and this router refuses one without the other.
		 */
		pendingConsentStore?: PendingConsentStore;
		/**
		 * The deployment's login page and its `redirect_to` protocol — the
		 * `loginEntry` slot the session module provides. Required to serve
		 * `/authorize`, which sends a browser that is not signed in there: the
		 * router refuses to build that endpoint without one, or with one that
		 * names no page. Unread without the authorization_code grant.
		 */
		loginEntry?: LoginEntry;
		/**
		 * The seams of the Client ID Metadata Document fetch (`fetch`,
		 * `lookup`, `now`), for tests. Everything else about the feature comes
		 * from `oauth.clientIdMetadataDocuments` in the config.
		 */
		clientIdMetadataDocuments?: Pick<ClientIdMetadataDocumentOptions, "fetch" | "lookup" | "now">;
		/**
		 * Getter for the installed federation providers Map. Defaults to
		 * `() => undefined` (no federation) when not provided.
		 *
		 * Read **once when `createOAuthRouter` is called**, so it must already
		 * answer every federation the composition installs: installed federations
		 * decide which acr entries are satisfiable (`./acrValues.mts`), and a map
		 * that fills later leaves those entries dropped. `oauthModule`'s map is
		 * filled by the boot planner before any route factory runs (federations
		 * are name-keyed contributions, registered before `routes`). Read again
		 * at request time by the federation logout and token routes.
		 */
		getFederationProviders?: () => ReadonlyMap<string, FederationProvider> | undefined;
		/**
		 * The registered session requirements (see ADR
		 * 2026-09-28-session-admission): what every consumer of admission in
		 * this router — `/authorize`, the consent step — reads its session
		 * through, and what a step-up can add, which decides which acr entries
		 * this composition can satisfy (`./acrValues.mts`). `oauthModule` passes
		 * the synthetic key `sessionRequirementResolver`, filled by the boot
		 * planner before any route factory runs. A router built by hand without
		 * one, or with one the planner (or `resolverForTests`) did not build, is
		 * refused here (core's `checkResolver`).
		 */
		requirements: SessionRequirementResolver;
		logger?: Logger;
	},
): Promise<{ router: Router; registry: Pick<GrantHandlerResolver, "get"> }> => {
	checkResolver(requirements, "createOAuthRouter");
	// `/authorize` issues the codes the authorization_code grant redeems, so it
	// is mounted exactly when that grant is registered — the registry
	// `/oauth/token` dispatches against — and needs the code repository then.
	const authorizationEndpoint = registry.get("authorization_code") !== undefined;
	if (authorizationEndpoint && codeRepository === undefined) {
		throw new Error(
			"createOAuthRouter: the authorization_code grant is registered but no codeRepository is wired — /authorize issues its codes into it; wire one, or leave the grant out",
		);
	}
	const router = express.Router();

	const { options, acrTable, canonicalIssuer, clientRepository } = resolveRouterSettings({
		config,
		authorizationEndpoint,
		requirements,
		getFederationProviders,
		registeredClients,
		consentStore,
		clientIdMetadataDocumentSeams,
		logger,
	});
	const legacyTypAcceptOpt = options.legacyTypAccept;
	// `/oauth/token` MUST accept public clients (`tokenEndpointAuthMethod: "none"`)
	// because PKCE/S256 at `/oauth/authorize` is their authenticity gate.
	// `private_key_jwt` on every client-authenticated endpoint: the
	// assertion's `aud` may name the issuer or this token endpoint.
	const tokenEndpoint = `${canonicalIssuer}/oauth/token`;
	const tokenClientAuthMw = createClientAuthMiddleware(clientRepository, {
		issuer: canonicalIssuer,
		logger,
		allowPublicClients: true,
		replaySeenSet,
		tokenEndpoint,
	});
	// `/oauth/introspect` MUST reject public clients per RFC 7662 §2.1 — a
	// known client_id is a non-secret value and would otherwise let any party
	// query token metadata. The default (`allowPublicClients: false`) applies.
	const introspectClientAuthMw = createClientAuthMiddleware(clientRepository, {
		issuer: canonicalIssuer,
		logger,
		replaySeenSet,
		tokenEndpoint,
	});

	// The check and outage policy (the limiter's failMode, context, 429
	// envelope) live in core's `createRateLimitGuard`, shared with the `/session/login`
	// brute-force guard. These endpoints emit RFC RateLimit-* headers too; no
	// `headerFallback` is passed because no per-endpoint spec is configured
	// here, so the guard advertises only what the adapter reported. Without a
	// `rateLimiter` the routes apply no rate limiting.
	const rateLimitGuard = (tag: string): RequestHandler =>
		rateLimiter
			? createRateLimitGuard({
					limiter: rateLimiter,
					tag,
					logger,
					auditSink,
				})
			: (_req, _res, next) => next();

	// One handler instance behind both methods, so a check can never be
	// mounted on GET and forgotten on POST. None without the grant.
	const authorizeHandler =
		authorizationEndpoint && codeRepository !== undefined && acrTable !== undefined
			? createAuthorizeHandler({
					clientRepository,
					codeRepository,
					grantPolicy,
					auditSink,
					logger,
					issuer: canonicalIssuer,
					// The session module's login entry, required here.
					login: requireLoginEntry(loginEntry),
					// The consent page, `oauth.consentPage.url`, read per request. The
					// default lives in the package's reference.conf; a hand-built config
					// without the key falls back the same way.
					consentUrl: () =>
						(config.oauth as { consentPage?: { url?: string } }).consentPage?.url ?? "/consent",
					consentStore,
					pendingConsentStore,
					oauth: { ...options, acrValues: acrTable },
					// `/authorize` reads the cookie's session through admission with the
					// router's own slots — the durable store (optional, as the slot is: a
					// composition without session-backed login wires none), the
					// subject-revocation boundary (applied when wired) and the resolver.
					userSessionStore,
					subjectRevocation,
					requirements,
				})
			: undefined;

	/**
	 * Introspection that could not verify the token because the keystore or a
	 * revocation store did not answer: `503`, never RFC 7662 §2.2's
	 * `active: false`, which is a statement about the token and would send
	 * the client to discard a credential that may be perfectly good. Audited
	 * as `introspect.store_unavailable`. See README, "Introspection: which
	 * tokens a caller may ask about".
	 */
	const answerIntrospectionUnavailable = (
		req: Request,
		res: Response,
		err: Parameters<typeof refuseVerificationUnavailable>[1],
	): Response => {
		emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "introspect.store_unavailable",
			ip: req.ip,
			userAgent: req.get("user-agent"),
			details: { reason: err.reason, cause: auditedError(err) },
		});
		return refuseVerificationUnavailable(res, err, logger, "introspect");
	};

	/**
	 * Introspection whose family or session check could not be made because
	 * the store did not answer: the same `503` as a verification outage, for
	 * the same reason, logged as `introspect_store_unavailable` with the
	 * error's projection — never the error, which can carry what the store
	 * was sent — and audited as `introspect.store_unavailable`, whose `cause`
	 * is core's `auditedError` (the error's name and code, never its message);
	 * the log line carries the rest.
	 */
	const answerStoreUnavailable = (
		req: Request,
		res: Response,
		outage: {
			readonly store: "refresh_token_family" | "user_session";
			readonly details: Readonly<Record<string, string>>;
			readonly cause: unknown;
		},
	): Response => {
		logger.error(
			{ store: outage.store, err: loggableError(outage.cause) },
			"introspect_store_unavailable",
		);
		emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "introspect.store_unavailable",
			ip: req.ip,
			userAgent: req.get("user-agent"),
			details: { ...outage.details, cause: auditedError(outage.cause) },
		});
		return res.status(503).json({
			error: "temporarily_unavailable",
			error_description:
				outage.store === "user_session"
					? "session store unavailable"
					: "refresh token store unavailable",
		});
	};

	// Federation endpoints — mount conditionally based on available stores and config.
	// federationTokenStore is required for both POST /oauth/federation/:name/logout and
	// POST /oauth/federation/:name/token.
	// logout_token signing needs the issuer; it is the router-scope canonical one.

	// Logout (back-channel logout_token signing requires issuer).
	const logoutSupported =
		!!userSessionStore &&
		!!sessionRPRegistry &&
		!!sessionFamilyIndex &&
		!!sessionFederationIndex &&
		!!federationTokenStore &&
		!!refreshTokenFamilyRevocation;

	// Federation-token endpoint forwards upstream; does NOT need our issuer.
	// Gated like logoutSupported, though it consumes only some of these
	// stores: createApp enforces that when ANY is wired, ALL are wired.
	const federationTokenSupported =
		!!userSessionStore &&
		!!sessionRPRegistry &&
		!!sessionFamilyIndex &&
		!!sessionFederationIndex &&
		!!federationTokenStore &&
		!!refreshTokenFamilyRevocation;

	// Mounted below only with both consent stores, and only beside the
	// `/authorize` whose requests it parks; one store without the other is
	// refused there. Decided once, here, for the parsers and the mount alike —
	// and by truthiness, so a JS caller's `null` is no store rather than a
	// parser scoped to a route that is never mounted.
	const consentMounted = !!consentStore && !!pendingConsentStore && authorizeHandler !== undefined;

	router
		.all(
			oauthRoutePaths({
				authorize: authorizeHandler !== undefined,
				logout: logoutSupported,
				federationToken: federationTokenSupported,
				consent: consentMounted,
			}),
			express.json(),
			express.urlencoded({ extended: false }),
		)
		.post(
			"/token",
			// Rate limit BEFORE client auth so repeated unauthenticated
			// hits cannot escape rate limiting via the clientAuthMw rejection path
			// (and so DoS amplification through repository lookups is bounded).
			rateLimitGuard(OAUTH_RATE_LIMIT_PREFIXES.token),
			tokenClientAuthMw,
			createTokenHandler({ registry, options, canonicalIssuer, auditSink, logger }),
		)
		// RFC 7662: Token Introspection
		.post(
			"/introspect",
			(_req, res, next) => {
				// Every introspection response is token metadata — `active`, and on
				// the positive path scope/sub/exp — so an intermediary caching one
				// keeps serving yesterday's liveness after a revocation. Same header
				// pair the token endpoint sets on issuance (RFC 6749 §5.1). Ahead of
				// the rate-limit guard, whose 429/503 exits end the chain without
				// calling next().
				res.set("Cache-Control", "no-store");
				res.set("Pragma", "no-cache");
				next();
			},
			rateLimitGuard(OAUTH_RATE_LIMIT_PREFIXES.introspect),
			async (req: Request, res: Response, next) => {
				// Bearer (RFC 6750 §2.1) or DPoP (RFC 9449 §7.1) — the caller's own
				// access token used as the introspection credential. Which scheme a
				// given token may use is enforced against its `cnf` by
				// `protectedResourceBindingMw` upstream.
				const credentialToken = parseAccessTokenHeader(req.headers.authorization);
				if (credentialToken !== null) {
					// Self-introspection pattern: RFC 7662 requires a valid credential to call introspect.
					// When the caller uses their own access token as that credential, the token in the
					// request body must match the one in the Authorization header. If they differ, return
					// inactive (not 403) per RFC 7662 §2.2 — the server must not reveal whether the
					// token exists.
					if (req.body.token !== credentialToken) {
						return res.status(200).json({ active: false });
					}
					try {
						// Token-as-credential self-intro — calling-client identity is not
						// established (introspectClientAuthMw is skipped on this
						// fall-through path), so audience pinning is deferred. alg / iss /
						// typ + signature are still pinned by the central verifier, and
						// the denylist is consulted so revoked ATs cannot serve as their
						// own introspection credential.
						await verifyJwt(credentialToken, keyStore, {
							type: "access_token",
							expectedIssuer: canonicalIssuer,
							legacyTypAccept: legacyTypAcceptOpt ?? false,
							// Token-accepting surface — forward what the composition
							// wired, jti denylist and subject watermark both.
							revocation: { denylist: accessTokenDenylist, subjectRevocation },
							logger,
						});
						return next();
					} catch (cause) {
						// A keystore or revocation store that could not answer says
						// nothing about the token: 503, never `active: false` — see
						// `answerIntrospectionUnavailable` above.
						if (isVerificationUnavailable(cause)) {
							return answerIntrospectionUnavailable(req, res, cause);
						}
						// Distinguish non-access-token typ rejections so SIEM
						// can spot a refresh / id token presented as a Bearer
						// credential. RFC 7662 §2.2 forbids leaking the typ to the
						// caller — the audit log carries the signal instead.
						// Other JwtVerificationError reasons (alg / iss / aud /
						// signature / expired / kid_*) already emit
						// `jwt_verify_rejected` from the central verifier — SIEM
						// rule authors should NOT double-count by also matching
						// `introspect_non_access_token` for those reasons.
						if (cause instanceof JwtVerificationError && cause.reason === "typ") {
							logger.warn(
								{ reason: "non_access_token", site: "introspect_bearer" },
								"introspect_non_access_token",
							);
						}
						return res.status(200).json({ active: false });
					}
				}
				return introspectClientAuthMw(req, res, next);
			},
			async (req: Request, res: Response) => {
				const { token } = req.body;
				if (!token) {
					return res.status(200).json({ active: false });
				}
				try {
					// Bind aud to the calling client when introspectClientAuthMw has
					// identified it; on the bearer-self-intro fall-through path the
					// identity is unknown and the verifier records the gap via
					// `jwt_verify_aud_skipped`. The denylist is consulted so revoked
					// ATs report active:false.
					//
					// The pin is the calling client's `allowedAudiences` ∪
					// `{clientId}` — the ceiling every issuing grant already derives
					// an audience within — so a resource server can introspect the
					// tokens issued FOR it under RFC 8707. See README, "The audience
					// pin is `allowedAudiences` ∪ `{client_id}`".
					const expectedAudiences = req.oauthClient
						? [...(req.oauthClient.allowedAudiences ?? []), req.oauthClient.clientId]
						: null;
					const verified = await verifyJwt(token, keyStore, {
						type: "access_token",
						expectedIssuer: canonicalIssuer,
						...(expectedAudiences ? { expectedAudience: expectedAudiences } : {}),
						legacyTypAccept: legacyTypAcceptOpt ?? false,
						// Token-accepting surface — forward what the composition
						// wired, jti denylist and subject watermark both.
						revocation: { denylist: accessTokenDenylist, subjectRevocation },
						logger,
					});
					const { payload } = verified;

					// Cascading revoke (RFC 7009 §2.1 SHOULD): once a refresh_token family
					// is revoked, every access_token minted under the same authorization
					// grant introspects as inactive. family_id is optional — older tokens
					// without it still succeed (no cascade available).
					const rawFamilyId = (payload as Record<string, unknown>).family_id;
					const familyId =
						typeof rawFamilyId === "string" && rawFamilyId.length > 0 ? rawFamilyId : null;
					if (familyId !== null && refreshTokenFamilyRevocation) {
						let revoked: boolean;
						try {
							revoked = await refreshTokenFamilyRevocation.isFamilyRevoked(familyId);
						} catch (cause) {
							// Fail-closed, as the outage it is: 503, not `active: false`
							// — see `answerIntrospectionUnavailable` for why a verdict
							// on the token is the wrong answer to a store that did not
							// answer.
							return answerStoreUnavailable(req, res, {
								store: "refresh_token_family",
								details: { family_id: familyId },
								cause,
							});
						}
						if (revoked) {
							emitAuditEvent(auditSink, {
								timestamp: new Date(),
								type: "introspect.family_revoked",
								ip: req.ip,
								userAgent: req.get("user-agent"),
								details: { family_id: familyId },
							});
							return res.status(200).json({ active: false });
						}
					}

					// Session liveness — the same read `/oauth/userinfo` and the
					// refresh grant perform. Without it a token whose browser session
					// was logged out would introspect as `active: true`, and a
					// resource server that trusts introspection (the BFF / proxy
					// topology) would honour it for the rest of its lifetime. It
					// answers for the access token in hand, not for the refresh-token
					// family behind it. Fail-closed on a store throw: 503, never
					// `active: false`. See README, "Revoked families and ended
					// sessions".
					//
					// The session is the token's own `sid` or, for a token-exchange
					// result, its `liveness_sid` (core's `livenessSidOf`): a derived
					// token ends with the session it came from, as its subject token
					// does.
					const sid = livenessSidOf(payload as Record<string, unknown>);
					if (sid !== null && userSessionStore) {
						let userSession: Awaited<ReturnType<UserSessionStore["get"]>>;
						try {
							userSession = await userSessionStore.get(sid);
						} catch (cause) {
							return answerStoreUnavailable(req, res, {
								store: "user_session",
								details: { sid },
								cause,
							});
						}
						if (!userSession) {
							emitAuditEvent(auditSink, {
								timestamp: new Date(),
								type: "introspect.session_invalid",
								ip: req.ip,
								userAgent: req.get("user-agent"),
								details: { sid },
							});
							return res.status(200).json({ active: false });
						}
					}

					const { exp, iat, iss, aud, sub, jti } = payload;
					const claims = payload as Record<string, unknown>;
					const azp = typeof claims.azp === "string" ? claims.azp : undefined;
					const rawClientId = claims.client_id;
					const clientId = typeof rawClientId === "string" ? rawClientId : azp;
					const scope = typeof claims.scope === "string" ? claims.scope : undefined;
					// token_type follows the confirmation: "DPoP" for cnf.jkt (RFC 9449
					// §5); "Bearer" for mTLS-bound tokens (RFC 8705 §3: cnf.x5t#S256
					// does not change the wire-level type) and unbound ones.
					// `extractConfirmation` validates member types; see
					// types/introspect.mts.
					// A compound cnf (both `jkt` and `x5t#S256`) is refused: this AS
					// cannot mint one, so it signals a forgery or a bug. Reporting
					// either member would claim a binding never issued, and dropping
					// the cnf while keeping `active: true` would let the RS treat a
					// bound token as plain bearer. Fail closed, as the refresh path
					// does (`grants/refreshToken.mts`); RFC 7662 §2.2 permits
					// `active: false` for any token the AS declines to vouch for.
					if (isCompoundConfirmation(claims.cnf)) {
						logger.warn(
							{ reason: "compound_cnf", site: "introspect_body", jti },
							"introspect_compound_cnf_rejected",
						);
						return res.status(200).json({ active: false });
					}
					const cnf = extractConfirmation(claims.cnf);
					// Core's one reading, which the token response uses too.
					const tokenType = tokenTypeForConfirmation(claims.cnf);
					const response: IntrospectResponse = {
						active: true,
						exp,
						iat,
						iss,
						aud,
						sub,
						azp,
						client_id: clientId,
						scope,
						token_type: tokenType,
						jti: typeof jti === "string" ? jti : undefined,
						cnf,
						// The authentication event the token carries: RFC 9470 §6.2's `acr`
						// and `auth_time`, and its `amr`.
						acr: wellFormedAcr(claims.acr),
						amr: wellFormedAmr(claims.amr),
						auth_time: wellFormedAuthTime(claims.auth_time),
					};
					return res.status(200).json(formatObject(response));
				} catch (cause) {
					if (isVerificationUnavailable(cause)) {
						return answerIntrospectionUnavailable(req, res, cause);
					}
					// Same non-access-token signal as the bearer path above:
					// `active: false` whatever the reason (RFC 7662 §2.2), and only
					// `reason === "typ"` logs `introspect_non_access_token`; other
					// reasons already emit `jwt_verify_rejected` from the central
					// verifier, so SIEM rules should NOT double-count.
					if (cause instanceof JwtVerificationError && cause.reason === "typ") {
						logger.warn(
							{ reason: "non_access_token", site: "introspect_body" },
							"introspect_non_access_token",
						);
					}
					return res.status(200).json({ active: false });
				}
			},
		);

	// /authorize — the RFC 6749 §4.1 authorization-code sequence lives in
	// routes/authorize.mts, behind the rate-limit guard; the handler consumes
	// the composition-time `options`, so no request re-reads config. OIDC Core
	// §3.1.2.1: "Authorization Servers MUST support the use of the HTTP GET and
	// POST methods". The handler reads its parameters through one accessor
	// (`authorizeParams`), so both methods run the identical sequence of
	// checks. Mounted only with the authorization_code grant.
	if (authorizeHandler !== undefined) {
		router
			.get("/authorize", rateLimitGuard(OAUTH_RATE_LIMIT_PREFIXES.authorize), authorizeHandler)
			.post("/authorize", rateLimitGuard(OAUTH_RATE_LIMIT_PREFIXES.authorize), authorizeHandler);
	}

	// OIDC Core §5.3 — UserInfo endpoint
	router.use(
		userinfo.createRouter(express, {
			keyStore,
			userSessionStore,
			refreshTokenFamilyRevocation,
			accessTokenDenylist,
			subjectRevocation,
			issuer: canonicalIssuer,
			legacyTypAccept: legacyTypAcceptOpt,
			logger,
		}),
	);

	// Federation endpoints — mounted below when `logoutSupported` /
	// `federationTokenSupported` (decided ahead of the body parsers, which
	// are scoped to the routes actually mounted).

	if (logoutSupported) {
		router.use(
			logoutRoute.createRouter(express, {
				keyStore,
				issuer: canonicalIssuer,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				userSessionStore: userSessionStore!,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				sessionRPRegistry: sessionRPRegistry!,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				sessionFamilyIndex: sessionFamilyIndex!,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				sessionFederationIndex: sessionFederationIndex!,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				federationTokenStore: federationTokenStore!,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				refreshTokenFamilyRevocation: refreshTokenFamilyRevocation!,
				clientRepository,
				getFederationProviders,
				auditSink,
				logger,
				legacyTypAccept: legacyTypAcceptOpt,
			}),
		);
	}

	if (federationTokenSupported) {
		router.use(
			federationTokenRoute.createRouter(express, {
				keyStore,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				refreshTokenFamilyRevocation: refreshTokenFamilyRevocation!,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				userSessionStore: userSessionStore!,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				sessionFederationIndex: sessionFederationIndex!,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				federationTokenStore: federationTokenStore!,
				clientRepository,
				getFederationProviders,
				accessTokenDenylist,
				subjectRevocation,
				auditSink,
				logger,
				issuer: canonicalIssuer,
				legacyTypAccept: legacyTypAcceptOpt,
			}),
		);
	}

	// RFC 7009 — Token Revocation endpoint. Always mounted; what it does with
	// an ACCESS token comes from `oauth.revocation.accessToken`, which
	// `readAccessTokenRevocationMode` reports as `undefined` when undeclared,
	// so `createRevokeRouter` can tell apart:
	//   - declared `"denylist"` with no `accessTokenDenylist` → it THROWS, and a
	//     deployment claiming a capability it cannot perform fails to build;
	//   - undeclared with no denylist → it reports `unsupported_token_type`
	//     rather than a 200 that revokes nothing (through `createApp`, core's
	//     boot validator already refuses this composition).
	// Refresh-token revocation is independent of the mode and of the denylist.
	//
	// Throttled like `/token`, `/introspect` and `/authorize`: RFC 7009 §2.1
	// lets a public client revoke its own tokens, so this unauthenticated
	// entry point reaches the client repository on every attempt (with Client
	// ID Metadata Documents on, an outbound fetch). A guard route ahead of
	// `createRevokeRouter`, which owns the path: `router.all` matches `/revoke`
	// exactly, where `router.use` would throttle every path beneath it too.
	router.all("/revoke", rateLimitGuard(OAUTH_RATE_LIMIT_PREFIXES.revoke));
	router.use(
		createRevokeRouter(express, {
			clientRepository,
			keyStore,
			refreshTokenFamilyRevocation,
			accessTokenDenylist,
			accessTokenRevocation: readAccessTokenRevocationMode(config),
			logger,
			issuer: canonicalIssuer,
			// private_key_jwt at /oauth/revoke, verified as at /oauth/token.
			replaySeenSet,
			tokenEndpoint,
		}),
	);

	// The consent step's endpoints, mounted only when a store is wired.
	// Without one there is nothing to record, and `/authorize` refuses the
	// clients that would need it. The step records consent in one store and
	// parks every request in the other, so a composition with one and not the
	// other — in either direction — is refused here, where the operator can
	// read why, rather than at the first third-party `/authorize`.
	if (!consentStore !== !pendingConsentStore) {
		const [wired, missing] = consentStore
			? ["consentStore", "pendingConsentStore"]
			: ["pendingConsentStore", "consentStore"];
		throw new Error(
			`createOAuthRouter: ${wired} is wired but ${missing} is not — the consent step records consent in consentStore and parks each request under a challenge in pendingConsentStore, and cannot run with one of them; wire both (the bundled memory consent module provides both) or neither`,
		);
	}
	if (consentMounted) {
		router.use(
			createConsentRouter(express, {
				consentStore,
				pendingConsentStore,
				clientRepository,
				auditSink,
				logger,
				// The same reading `/authorize` makes, through admission with the
				// same slots.
				userSessionStore,
				subjectRevocation,
				requirements,
			}),
		);
	}

	return { router, registry };
};
