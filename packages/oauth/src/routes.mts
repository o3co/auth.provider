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
	auditErrorText,
	auditedError,
	type ClientRepository,
	type CodeRepository,
	type ConsentStore,
	checkCanonicalIssuer,
	checkResolver,
	consoleLogger,
	createRateLimitGuard,
	describeIssuerRejection,
	emitAuditEvent,
	errorEnvelope,
	type FederationProvider,
	type FederationTokenStore,
	formatObject,
	type GrantHandlerResolver,
	type GrantHandlerResult,
	type GrantPolicyHook,
	isGrantTypeAllowed,
	isVerificationUnavailable,
	isWellFormedErrorCode,
	JwtVerificationError,
	type KeyStore,
	type Logger,
	type LoginEntry,
	livenessSidOf,
	loggableError,
	ownedConfirmation,
	type PendingConsentStore,
	type RateLimiter,
	type RefreshTokenFamilyRevocation,
	type ReplaySeenSet,
	readAccessTokenRevocationMode,
	type SenderConstraint,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRequirementResolver,
	type SessionRPRegistry,
	type SubjectRevocation,
	sanitizeErrorText,
	stepUpReach,
	tokenTypeForConfirmation,
	type UserSessionStore,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
// Session data type augmentation. /authorize writes no identity binding into
// the session (`Code.client_id` and `Code.redirect_uri` carry it); `code` is
// kept because the /token grant clears it from older sessions (see
// authorization.mts `sessionMutation.clear`).
import type {} from "express-session";
import { parseAccessTokenHeader } from "./accessTokenHeader.mjs";
import { logUnsatisfiableAcrValues, vouchableAcrValues } from "./acrValues.mjs";
import { stepUpOf } from "./admission.mjs";
import {
	type ClientIdMetadataDocumentOptions,
	withClientIdMetadataDocuments,
} from "./clients/clientIdMetadataDocument.mjs";
import { createClientAuthMiddleware, resolveRealm } from "./middleware/clientAuth.mjs";
import { resolveOAuthOptions } from "./resolveOAuthOptions.mjs";
import { createAuthorizeHandler, loginTripFromConfig } from "./routes/authorize.mjs";
import { createConsentRouter } from "./routes/consent.mjs";
import * as federationTokenRoute from "./routes/federationToken.mjs";
import * as logoutRoute from "./routes/logout.mjs";
import { createRevokeRouter } from "./routes/revoke.mjs";
import * as userinfo from "./routes/userinfo.mjs";
import {
	extractConfirmation,
	type IntrospectResponse,
	isCompoundConfirmation,
} from "./types/introspect.mjs";
import { refuseVerificationUnavailable } from "./verificationUnavailable.mjs";

/**
 * The `reason` of a grant handler's `token.issued.failure`: its
 * `error_description`, or its `error` when it gives none.
 *
 * A grant's `error` alone does not tell its refusals apart — token exchange
 * answers a malformed request and a stolen, unproven bound token alike with
 * `invalid_request` (RFC 8693 §2.2.2) — while the description names the check
 * that refused. Some descriptions quote client input, so it is recorded
 * through core's `auditErrorText` (sanitised and capped) to bound what a
 * client can put into the audit stream. A description that is empty or not a
 * string — a JavaScript policy's deny can carry anything — falls back to the
 * code.
 */
const auditReason = (error: string, errorDescription: unknown): string =>
	auditErrorText(errorDescription) || auditErrorText(error);

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
		 * is mounted: only with the `authorization_code` grant. Only `get` is read —
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
		 * `loginEntry` slot the session module provides. Optional: the oauth
		 * module boots without the session module, and `/authorize` then reads
		 * `endpoints.login.url` per request.
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

	// Every `oauth.*` knob this router consumes is resolved exactly once,
	// here, at router composition; see `resolveOAuthOptions` for the defensive
	// reads and per-field defaults. The /authorize handler receives the whole
	// object (routes/authorize.mts).
	const options = resolveOAuthOptions(config, logger);
	// `/authorize` answers `acr_values` only from the entries this composition
	// can satisfy — the same table discovery advertises — and an entry dropped
	// is said once, here, at composition (ADR
	// 2026-09-25-multi-factor-authentication).
	// What the registered requirements can add to a session by a step-up: read
	// once here, after every name-keyed contribution registered.
	const reach = stepUpReach(Array.from(requirements.entries(), ([, r]) => r));
	const acrValues = vouchableAcrValues(options.acrValues, getFederationProviders(), config, reach);
	logUnsatisfiableAcrValues(acrValues.dropped, reach, logger);
	// `iss` is a property of the deployment, never of a request: a fallback to
	// the `Host` header would let a caller choose the issuer of its tokens. A
	// canonical issuer is required and is the only source, resolved once here
	// so no request path can reach a fallback. It also populates the `realm`
	// parameter on `WWW-Authenticate: Basic` challenges (RFC 7235 §2.2).
	const issuerRejection = checkCanonicalIssuer(options.issuer);
	if (issuerRejection) {
		throw new Error(
			`createOAuthRouter: oauth.jwt.issuer ${describeIssuerRejection(issuerRejection)}`,
		);
	}
	// `checkCanonicalIssuer` returned null above, which only a string satisfies.
	const canonicalIssuer = options.issuer as string;
	// Client ID Metadata Documents. Pre-registered clients answer first; a
	// client_id that is an https URL is then resolved from the document it
	// names, under the operator's ceilings. One repository for every endpoint
	// below — /authorize, /token, /revoke — so a document client is the same
	// client everywhere.
	//
	// Wired only with a consent store, the gate discovery applies: a document
	// client is never first-party, so `/authorize` refuses it without one, and
	// resolving it anyway would make each request a guarded outbound HTTPS
	// fetch before the refusal — an amplification surface where no request
	// can succeed.
	const cimd = options.clientIdMetadataDocuments;
	const clientRepository: ClientRepository =
		cimd.enabled && consentStore !== undefined
			? withClientIdMetadataDocuments(registeredClients, {
					allowedScopes: cimd.allowedScopes,
					allowedAudiences: cimd.allowedAudiences,
					allowedHosts: cimd.allowedHosts,
					deniedHosts: cimd.deniedHosts,
					...(cimd.maxBytes === undefined ? {} : { maxBytes: cimd.maxBytes }),
					...(cimd.timeoutMs === undefined ? {} : { timeoutMs: cimd.timeoutMs }),
					...(cimd.cacheMaxAgeMs === undefined ? {} : { cacheMaxAgeMs: cimd.cacheMaxAgeMs }),
					...(cimd.maxCacheEntries === undefined ? {} : { maxCacheEntries: cimd.maxCacheEntries }),
					...(cimd.staleIfErrorMs === undefined ? {} : { staleIfErrorMs: cimd.staleIfErrorMs }),
					...(cimd.negativeCacheMs === undefined ? {} : { negativeCacheMs: cimd.negativeCacheMs }),
					...(cimd.maxConcurrentFetches === undefined
						? {}
						: { maxConcurrentFetches: cimd.maxConcurrentFetches }),
					logger,
					...clientIdMetadataDocumentSeams,
				})
			: registeredClients;
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

	// The check and outage policy (failMode, context, 429 envelope) live in
	// core's `createRateLimitGuard`, shared with the `/session/login`
	// brute-force guard. These endpoints emit RFC RateLimit-* headers too; no
	// `headerFallback` is passed because no per-endpoint spec is configured
	// here, so the guard advertises only what the adapter reported. Without a
	// `rateLimiter` the routes apply no rate limiting.
	const rateLimitGuard = (tag: string): RequestHandler =>
		rateLimiter
			? createRateLimitGuard({
					limiter: rateLimiter,
					tag,
					failMode: config.rateLimit.failMode,
					logger,
					auditSink,
				})
			: (_req, _res, next) => next();

	// One handler instance behind both methods, so a check can never be
	// mounted on GET and forgotten on POST. None without the grant.
	const authorizeHandler =
		authorizationEndpoint && codeRepository !== undefined
			? createAuthorizeHandler({
					clientRepository,
					codeRepository,
					grantPolicy,
					auditSink,
					logger,
					issuer: canonicalIssuer,
					// The session module's login entry when a module provides it;
					// otherwise the login page read from the configuration per request.
					login: loginEntry ?? loginTripFromConfig(() => config.endpoints.login.url),
					// The consent page, read like the login page. The default lives
					// in HOCON; a hand-built config without the key falls back the same way.
					consentUrl: () => config.endpoints.consent?.url ?? "/consent",
					consentStore,
					pendingConsentStore,
					oauth: { ...options, acrValues: acrValues.table },
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

	// Mounted below only with both consent stores; one without
	// the other is refused there. Decided once, here, for the parsers and the
	// mount alike — and by truthiness, so a JS caller's `null` is no store
	// rather than a parser scoped to a route that is never mounted.
	const consentMounted = !!consentStore && !!pendingConsentStore;

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
			rateLimitGuard("token"),
			tokenClientAuthMw,
			async (req: Request, res: Response) => {
				const { grant_type } = req.body;

				if (typeof grant_type !== "string" || grant_type === "") {
					await emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "token.issued.failure",
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { reason: "missing_grant_type" },
					});
					// RFC 6749 §5.2: a missing required parameter is `invalid_request`;
					// `unsupported_grant_type` is reserved for a value the server does
					// not support, which the next branch answers.
					return res.status(400).json({
						error: "invalid_request",
						error_description: "grant_type must be a non-empty string",
					});
				}

				const handler = registry.get(grant_type);
				if (!handler) {
					await emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "token.issued.failure",
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { reason: "unsupported_grant_type", grant_type: auditErrorText(grant_type) },
					});
					return res.status(400).json({
						error: "unsupported_grant_type",
						error_description: sanitizeErrorText(`grant_type '${grant_type}' is not supported`),
					});
				}

				// `clientAuthMw` populates `req.oauthClient` after RFC 6749 §2.3
				// authentication. Grant handlers consult `ctx.authenticatedClient`
				// rather than the raw body so identity flows are not body-spoofable.
				const ctx = {
					body: req.body,
					session: req.session,
					issuer: canonicalIssuer,
					metadata: { ip: req.ip },
					ip: req.ip,
					userAgent: req.get("user-agent"),
					tokenBinding: req.tokenBinding,
					authenticatedClient: req.oauthClient
						? {
								clientId: req.oauthClient.clientId,
								tokenEndpointAuthMethod: req.oauthClient.tokenEndpointAuthMethod,
								allowedScopes: req.oauthClient.allowedScopes,
								defaultScopes: req.oauthClient.defaultScopes,
								allowedGrantTypes: req.oauthClient.allowedGrantTypes,
								allowedAudiences: req.oauthClient.allowedAudiences,
								senderConstrained: req.oauthClient.senderConstrained,
								// The authorization-code grant applies the same
								// per-client PKCE method list `/authorize` applied when
								// it minted the code, so the opt-in has to travel with
								// the authenticated identity.
								allowPlainPkce: req.oauthClient.allowPlainPkce,
							}
						: null,
				};
				// allowedGrantTypes is enforced at dispatch, like the
				// sender-constraint check below: it runs once for every grant_type
				// before the concrete handler, so every grant — including one
				// registered later through `GrantFactory` — inherits it without
				// opting in.
				//
				// Absence of the field is "no policy declared", not "deny", so a
				// registration written before the field existed keeps its grants.
				// A deployment that has audited its registrations flips that with
				// `oauth.requireGrantTypeAllowlist`, read once at composition for
				// both enforcement points. Handlers that declare
				// `requiresExplicitGrantAllowlist` add deny-by-absence on top (just
				// before the handler runs, below), so machine-to-machine access is
				// never acquired by omission.
				//
				// RFC 6749 §5.2 `unauthorized_client`: "The authenticated client is
				// not authorized to use this authorization grant type."
				if (
					!isGrantTypeAllowed(ctx.authenticatedClient?.allowedGrantTypes, grant_type, {
						requireAllowlist: options.requireGrantTypeAllowlist,
					})
				) {
					await emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "token.issued.failure",
						clientId: req.oauthClient?.clientId,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { reason: "grant_type_not_allowed", grant_type },
					});
					return res.status(400).json({
						error: "unauthorized_client",
						error_description: sanitizeErrorText(
							`client is not authorized for grant_type '${grant_type}'`,
						),
					});
				}

				// senderConstrained enforcement at dispatch: runs once for every
				// grant_type before the concrete handler, so custom grants
				// registered via GrantFactory inherit the check. No-op when the
				// client did not opt into a sender constraint.
				const sc: SenderConstraint | undefined = ctx.authenticatedClient?.senderConstrained;
				if (sc?.required) {
					// Use truthy check (not `=== undefined`) so a custom downstream
					// middleware that sets `req.tokenBinding = null` cannot bypass
					// the constraint. The type contract is `tokenBinding?:
					// TokenBinding` so this is purely defensive at the JS layer.
					if (!ctx.tokenBinding) {
						await emitAuditEvent(auditSink, {
							timestamp: new Date(),
							type: "token.issued.failure",
							clientId: req.oauthClient?.clientId,
							ip: req.ip,
							userAgent: req.get("user-agent"),
							details: {
								reason: "sender_constraint_no_binding",
								grant_type,
								required_methods: sc.methods,
							},
						});
						// The realm is a property of the deployment, so it comes from
						// the router-scope `canonicalIssuer` (config only) through the
						// same filter `clientAuthMw` uses.
						//
						// `Basic` challenge: this response is `invalid_client` + 401,
						// and RFC 6749 §5.2 requires a challenge matching the scheme
						// the client authenticated with via the Authorization header.
						// Whether `invalid_client` is the right code here is a
						// separate, breaking question; changing the challenge alone
						// would make the pair non-conformant.
						return res
							.status(401)
							.set("WWW-Authenticate", `Basic realm="${resolveRealm(canonicalIssuer)}"`)
							.json(
								errorEnvelope(
									"invalid_client",
									sanitizeErrorText("sender-constrained binding required, none provided"),
								),
							);
					}
					if (!sc.methods.includes(ctx.tokenBinding.kind)) {
						await emitAuditEvent(auditSink, {
							timestamp: new Date(),
							type: "token.issued.failure",
							clientId: req.oauthClient?.clientId,
							ip: req.ip,
							userAgent: req.get("user-agent"),
							details: {
								reason: "sender_constraint_kind_mismatch",
								grant_type,
								presented_kind: ctx.tokenBinding.kind,
								required_methods: sc.methods,
							},
						});
						return res
							.status(400)
							.json(
								errorEnvelope(
									"unauthorized_client",
									sanitizeErrorText(`client not allowed to use kind=${ctx.tokenBinding.kind}`),
								),
							);
					}
					// The kind is allowed, but the binding must also carry a member
					// that kind owns: every grant stamps `ownedConfirmation` and
					// nothing else, so a binding with none — a DPoP binding
					// presenting an mTLS thumbprint, a contributed kind core has no
					// confirmation for — would be minted an unbound Bearer token,
					// and the required constraint downgraded without a word. A client
					// that does not require a constraint gets that unbound token,
					// advertised as Bearer; this one is refused.
					if (ownedConfirmation(ctx.tokenBinding) === undefined) {
						await emitAuditEvent(auditSink, {
							timestamp: new Date(),
							type: "token.issued.failure",
							clientId: req.oauthClient?.clientId,
							ip: req.ip,
							userAgent: req.get("user-agent"),
							details: {
								reason: "sender_constraint_unowned_confirmation",
								grant_type,
								presented_kind: ctx.tokenBinding.kind,
								required_methods: sc.methods,
							},
						});
						return res
							.status(400)
							.json(
								errorEnvelope(
									"invalid_request",
									"sender-constrained binding carries no confirmation its mechanism owns",
								),
							);
					}
				}
				// Deny-by-absence for handlers that declare
				// `requiresExplicitGrantAllowlist`. The base check above admits an
				// absent allowlist ("no policy declared"); a strict handler refuses
				// exactly that case, so the grant is never acquired by omission.
				// Strictness is a property of the handler contract, and this is the
				// single place both rules compose.
				// - Position: after the sender-constraint gate, immediately before
				//   the handler.
				// - Skipped when `authenticatedClient` is null: client_credentials
				//   rejects null itself with `invalid_client`, and WebAuthn
				//   deliberately serves unauthenticated passkey callers.
				// - The denial goes through the shared result path below (not an
				//   early `res.json`), so it is audited like any grant's refusal.
				//   Its description is the base check's, word for word, so a client
				//   cannot tell which of the two rules refused it.
				const strictAllowlistDenial: GrantHandlerResult | null =
					handler.requiresExplicitGrantAllowlist === true &&
					ctx.authenticatedClient !== null &&
					ctx.authenticatedClient.allowedGrantTypes === undefined
						? {
								result: {
									status: 400,
									error: "unauthorized_client",
									errorDescription: `client is not authorized for grant_type '${grant_type}'`,
								},
							}
						: null;
				const { result, sessionMutation } = strictAllowlistDenial ?? (await handler.handle(ctx));

				if (sessionMutation?.clear) {
					for (const key of sessionMutation.clear) {
						(req.session as unknown as Record<string, unknown>)[key] = undefined;
					}
				}
				if (sessionMutation?.set) {
					Object.assign(req.session, sessionMutation.set);
				}

				if ("tokens" in result) {
					res.set("Cache-Control", "no-store");
					res.set("Pragma", "no-cache");
					await emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "token.issued",
						// Prefer the authenticated client over the raw body — body
						// `client_id` is not authoritative once `clientAuthMw` runs.
						clientId: req.oauthClient?.clientId,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { grant_type },
					});
					return res.status(result.status).json(result.tokens);
				}
				// RFC 6749 §5.2: `error` is 1*NQSCHAR. A grant can hand back any
				// code — a policy deny carries the policy's own — so one outside
				// that set, or none, goes out as `invalid_request`, and the code is
				// logged, sanitised, for whoever wired the grant or its policy.
				let error = result.error;
				if (!isWellFormedErrorCode(error)) {
					logger.warn(
						{ grant_type, error: auditErrorText(String(error)) },
						"token_error_code_malformed",
					);
					error = "invalid_request";
				}
				const errorBody: Record<string, unknown> = { error };
				// RFC 6749 §5.2's character set, whichever grant wrote it: several
				// quote the client's own input (a scope, an audience, a token type).
				// A description that is empty or not a string is not sent: RFC 6749
				// A.8 makes the field 1*NQSCHAR, and a JavaScript policy's deny,
				// passed through by core's policy evaluation, can carry anything.
				const errorDescription = sanitizeErrorText(result.errorDescription);
				if (errorDescription) errorBody.error_description = errorDescription;
				// A grant whose session can be met by a step-up names the
				// requirement beside `invalid_grant`, the one error it qualifies, so
				// an updated client can offer it (ADR 2026-09-28-session-admission).
				// A requirement's name is held to the same character set as `error`:
				// core refuses to register one outside it (the same
				// `isWellFormedErrorCode`), and a grant built by hand may set any
				// `step_up`, so it is checked again.
				const stepUp = error === "invalid_grant" ? stepUpOf(result) : undefined;
				if (stepUp !== undefined && isWellFormedErrorCode(stepUp)) errorBody.step_up = stepUp;
				// Do NOT inject `WWW-Authenticate: Bearer` here: the token endpoint
				// is not a protected resource (RFC 6750 §3), and `clientAuthMw`
				// already set the `WWW-Authenticate: Basic realm="..."` challenge
				// for client-auth failures, which Bearer would clobber for any grant
				// returning 401. RFC 6749 §5.2 does not mandate WWW-Authenticate.
				await emitAuditEvent(auditSink, {
					timestamp: new Date(),
					type: "token.issued.failure",
					clientId: req.oauthClient?.clientId,
					ip: req.ip,
					userAgent: req.get("user-agent"),
					details: {
						grant_type,
						error,
						reason: auditReason(error, result.errorDescription),
					},
				});
				return res.status(result.status).json(errorBody);
			},
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
			rateLimitGuard("introspect"),
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
			.get("/authorize", rateLimitGuard("authorize"), authorizeHandler)
			.post("/authorize", rateLimitGuard("authorize"), authorizeHandler);
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
	router.all("/revoke", rateLimitGuard("revoke"));
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
