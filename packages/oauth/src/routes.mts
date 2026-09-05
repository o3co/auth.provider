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
	type ClientRepository,
	type CodeRepository,
	checkCanonicalIssuer,
	consoleLogger,
	createRateLimitGuard,
	describeIssuerRejection,
	emitAuditEvent,
	errorEnvelope,
	type FederationProviderHandle,
	type FederationTokenStore,
	formatObject,
	type GrantHandlerResolver,
	type GrantHandlerResult,
	type GrantPolicyHook,
	isGrantTypeAllowed,
	JwtVerificationError,
	type KeyStore,
	type Logger,
	type RateLimiter,
	type RefreshTokenFamilyRevocation,
	readAccessTokenRevocationMode,
	type SenderConstraint,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type SubjectRevocation,
	type UserSessionStore,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
// Session data type augmentation
//
// D-1 (v0.5.1): `code_client_id`, `code_redirect_uri`, `granted_scopes` were
// removed because /authorize no longer writes identity binding into the
// session — `Code.client_id` and `Code.redirect_uri` carry it instead. `code`
// is retained because the /token grant clears it from in-flight pre-v0.5.1
// sessions (see authorization.mts `sessionMutation.clear`).
import type {} from "express-session";
import { parseAccessTokenHeader } from "./accessTokenHeader.mjs";
import { createClientAuthMiddleware, resolveRealm } from "./middleware/clientAuth.mjs";
import { resolveOAuthOptions } from "./resolveOAuthOptions.mjs";
import { createAuthorizeHandler } from "./routes/authorize.mjs";
import * as federationTokenRoute from "./routes/federationToken.mjs";
import * as logoutRoute from "./routes/logout.mjs";
import { createRevokeRouter } from "./routes/revoke.mjs";
import * as userinfo from "./routes/userinfo.mjs";
import {
	extractConfirmation,
	type IntrospectResponse,
	isCompoundConfirmation,
} from "./types/introspect.mjs";

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

export const createOAuthRouter = async (
	express: {
		Router: () => Router;
		json: () => RequestHandler;
		urlencoded: (opts: { extended: boolean }) => RequestHandler;
	},
	{
		registry,
		config,
		clientRepository,
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
		getFederationProviders = () => undefined,
		logger = consoleLogger,
	}: {
		registry: GrantHandlerResolver;
		config: AppConfig;
		clientRepository: ClientRepository;
		codeRepository: CodeRepository;
		keyStore: KeyStore;
		rateLimiter?: RateLimiter;
		auditSink?: AuditSink;
		grantPolicy?: GrantPolicyHook;
		refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
		/** Wave 1 — RFC 7009 access-token revocation. Optional: when absent, AT revocation is a warn-logged no-op. */
		accessTokenDenylist?: AccessTokenDenylist;
		/**
		 * #296 — per-subject access-token watermark. The subject-level companion
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
		 * Lazy getter for the federation providers Map. Evaluated at request time so
		 * module init order does not affect resolution — pass `() => context.federationProviders`
		 * from `module.mts`. Defaults to `() => undefined` when not provided.
		 */
		getFederationProviders?: () => ReadonlyMap<string, FederationProviderHandle> | undefined;
		logger?: Logger;
	},
): Promise<{ router: Router; registry: GrantHandlerResolver }> => {
	const router = express.Router();

	// #328: every `oauth.*` knob this router consumes is resolved exactly once,
	// here, at router composition. `resolveOAuthOptions` owns the defensive
	// reads for hand-built configs that never passed the zod schema — see its
	// JSDoc for the per-field defaults (which are unchanged: the strict
	// `=== true` opt-in for #297 `requireEmailVerified`, SF-1
	// `legacyTypAccept` left optional for sub-routers to default). The
	// /authorize handler receives the whole object (routes/authorize.mts).
	const options = resolveOAuthOptions(config, logger);
	// #266: `iss` is a property of the deployment, never of a request. The token
	// endpoint used to compute `config.oauth.jwt.issuer ?? req.get("host")`, so an
	// unconfigured deployment behind a trusted proxy minted tokens whose issuer the
	// caller chose. A canonical issuer is now required, and it is the only source —
	// resolved once at router-creation time so no request path can reach a fallback.
	// It also populates the `realm` parameter on `WWW-Authenticate: Basic`
	// challenges (RFC 7235 §2.2).
	const issuerRejection = checkCanonicalIssuer(options.issuer);
	if (issuerRejection) {
		throw new Error(
			`createOAuthRouter: oauth.jwt.issuer ${describeIssuerRejection(issuerRejection)}`,
		);
	}
	// `checkCanonicalIssuer` returned null above, which only a string satisfies.
	const canonicalIssuer = options.issuer as string;
	const legacyTypAcceptOpt = options.legacyTypAccept;
	// `/oauth/token` MUST accept public clients (`tokenEndpointAuthMethod: "none"`)
	// because PKCE/S256 at `/oauth/authorize` is their authenticity gate.
	const tokenClientAuthMw = createClientAuthMiddleware(clientRepository, {
		issuer: canonicalIssuer,
		logger,
		allowPublicClients: true,
	});
	// `/oauth/introspect` MUST reject public clients per RFC 7662 §2.1 — a
	// known client_id is a non-secret value and would otherwise let any party
	// query token metadata. The default (`allowPublicClients: false`) applies.
	const introspectClientAuthMw = createClientAuthMiddleware(clientRepository, {
		issuer: canonicalIssuer,
		logger,
	});

	// #325: the check + outage policy (OR-5 failMode, CP-10 context, AS-2 429
	// envelope) lives in core's `createRateLimitGuard`, shared with the
	// `/session/login` brute-force guard — one implementation of the security
	// throttles instead of two hand-synchronized copies. These endpoints now
	// also emit RFC RateLimit-* headers like `/session/login` does; no
	// `headerFallback` is passed because no per-endpoint spec is configured
	// here, so the guard only advertises what the adapter actually reported.
	// The slot is optional: when no `rateLimiter` is wired the routes degrade
	// gracefully (no rate limiting applied), as before.
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

	// #284: one handler instance behind both methods, so a check can never be
	// mounted on GET and forgotten on POST.
	const authorizeHandler = createAuthorizeHandler({
		clientRepository,
		codeRepository,
		grantPolicy,
		auditSink,
		logger,
		issuer: canonicalIssuer,
		loginUrl: () => config.endpoints.login.url,
		oauth: options,
		// R1b: `/authorize` re-checks that the express-session's `sid` still
		// names a live `UserSession` before minting. Optional here for the same
		// reason the slot itself is: a composition without session-backed login
		// wires no store, and the endpoint behaves exactly as it did.
		userSessionStore,
	});

	router
		.use(express.json())
		.use(express.urlencoded({ extended: false }))
		.post(
			"/token",
			// D-6 ordering: rate limit BEFORE client auth so repeated unauthenticated
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
					// not support (#293 item 10). The next branch keeps that one.
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
						details: { reason: "unsupported_grant_type", grant_type },
					});
					return res.status(400).json({
						error: "unsupported_grant_type",
						error_description: `grant_type "${grant_type}" is not supported`,
					});
				}

				// D-6: `clientAuthMw` populates `req.oauthClient` after RFC 6749 §2.3
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
								// #273: the authorization-code grant applies the same
								// per-client PKCE method list `/authorize` applied when
								// it minted the code, so the opt-in has to travel with
								// the authenticated identity.
								allowPlainPkce: req.oauthClient.allowPlainPkce,
							}
						: null,
				};
				// Shared grant-dispatch allowedGrantTypes enforcement (#268).
				// Mounted at dispatch for the same reason as the sender-constraint
				// check below: it runs once for every grant_type before the
				// concrete handler, so every grant — including one registered
				// later through `GrantFactory` — inherits it without opting in.
				// Enforcement used to be per-handler, and only `client_credentials`
				// and the WebAuthn grant had opted in, which meant a client
				// registered for one grant could exercise all the others and the
				// registration's restriction was void.
				//
				// Absence of the field is "no policy declared", not "deny": the
				// grants that ignored it predate it, so denying here would revoke
				// every grant from every registration written before it existed.
				// A deployment that has audited its registrations flips that with
				// `oauth.requireGrantTypeAllowlist` (#311), which is read once at
				// composition and applies to both enforcement points.
				// Handlers that declare `requiresExplicitGrantAllowlist` compose a
				// stricter deny-by-absence rule on top (#326, enforced just before
				// the handler runs below), so machine-to-machine access is still
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
						error_description: `client is not authorized for grant_type "${grant_type}"`,
					});
				}

				// Shared grant-dispatch senderConstrained enforcement (Wave 2
				// Token-binding Cluster spec §4.8 step 2). This runs once for
				// every grant_type before the concrete handler, so custom
				// grants registered via GrantFactory inherit the check for
				// free. No-op when the client did not opt into a sender
				// constraint — zero behavior change for v0.7.x consumers.
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
						// The `Basic` challenge scheme is retained: this response is
						// `invalid_client` + 401, and RFC 6749 §5.2 requires a
						// challenge matching the scheme the client used when it
						// authenticated via the Authorization header. Whether
						// `invalid_client` is the right code for "authenticated fine,
						// but presented no token binding" is a separate, breaking
						// question (#199 M3) — changing the challenge without changing
						// the error code would just make the pair non-conformant.
						return res
							.status(401)
							.set("WWW-Authenticate", `Basic realm="${resolveRealm(canonicalIssuer)}"`)
							.json(
								errorEnvelope(
									"invalid_client",
									"sender-constrained binding required, none provided",
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
									`client not allowed to use kind=${ctx.tokenBinding.kind}`,
								),
							);
					}
				}
				// #326: deny-by-absence for handlers that declare
				// `requiresExplicitGrantAllowlist`. The base check above admits an
				// absent allowlist ("no policy declared"); a strict handler refuses
				// exactly that case, so the grant is never acquired by omission.
				// Enforcement used to be hand-rolled inside `client_credentials`
				// and the WebAuthn grant — the next machine-to-machine grant had
				// to know that folklore to stay safe. The flag makes strictness a
				// property of the handler contract and this the single place both
				// rules compose.
				//
				// Three deliberate shape choices keep the refactor observable-
				// semantics-preserving:
				// - Position: after the sender-constraint gate, immediately before
				//   the handler — exactly where the deleted per-grant checks ran —
				//   so no dispatch-level rule changes relative order.
				// - Skip when `authenticatedClient` is null: the deleted checks
				//   never fired without a client (client_credentials rejects null
				//   itself with `invalid_client`; WebAuthn deliberately serves
				//   unauthenticated passkey callers).
				// - The denial is threaded through the shared result path below
				//   (not an early `res.json`), and its description keeps the
				//   per-grant wire format `client is not authorized for <type>`
				//   (the base check above quotes the type; the deleted checks did
				//   not), so response body and audit emission stay byte-identical.
				const strictAllowlistDenial: GrantHandlerResult | null =
					handler.requiresExplicitGrantAllowlist === true &&
					ctx.authenticatedClient !== null &&
					ctx.authenticatedClient.allowedGrantTypes === undefined
						? {
								result: {
									status: 400,
									error: "unauthorized_client",
									errorDescription: `client is not authorized for ${grant_type}`,
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
						// D-6: prefer the authenticated client over the raw body — body
						// `client_id` is no longer authoritative once `clientAuthMw` runs.
						clientId: req.oauthClient?.clientId,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { grant_type },
					});
					return res.status(result.status).json(result.tokens);
				}
				const errorBody: Record<string, unknown> = { error: result.error };
				if (result.errorDescription) errorBody.error_description = result.errorDescription;
				// Copilot review: do NOT inject `WWW-Authenticate: Bearer` here.
				// The token endpoint is not a protected resource (RFC 6750 §3 applies to
				// resource servers, not authorization endpoints), and `clientAuthMw`
				// already set the appropriate `WWW-Authenticate: Basic realm="..."`
				// challenge for client-auth failures upstream. Setting Bearer here
				// clobbered that more-correct value for any grant returning 401
				// (e.g., the new `ctx.authenticatedClient === null` branch). RFC 6749
				// §5.2 token-endpoint error responses do not mandate WWW-Authenticate.
				await emitAuditEvent(auditSink, {
					timestamp: new Date(),
					type: "token.issued.failure",
					clientId: req.oauthClient?.clientId,
					ip: req.ip,
					userAgent: req.get("user-agent"),
					details: { grant_type, error: result.error },
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
				// keeps serving yesterday's liveness after a revocation (#293 item
				// 2). Same header pair the token endpoint sets on issuance
				// (RFC 6749 §5.1). Ahead of the rate-limit guard, deliberately: the
				// guard's own 429/503 exits end the chain without calling next(),
				// and "every exit" includes those.
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
						// SF-1: token-as-credential self-intro — calling-client identity is not yet
						// established (introspectClientAuthMw is skipped on this fall-
						// through path), so audience pinning is deferred. alg / iss /
						// typ + signature are still pinned by the central verifier.
						// Wave 1 (C4): denylist consulted so revoked ATs cannot serve
						// as their own introspection credential.
						await verifyJwt(credentialToken, keyStore, {
							type: "access_token",
							expectedIssuer: canonicalIssuer,
							legacyTypAccept: legacyTypAcceptOpt ?? false,
							// #296/#367: token-accepting surface — forward what the
							// composition wired, jti denylist and subject watermark both.
							revocation: { denylist: accessTokenDenylist, subjectRevocation },
							logger,
						});
						return next();
					} catch (cause) {
						// SF-8: distinguish non-access-token typ rejections so SIEM
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
					// SF-1: bind aud to the calling client when introspectClientAuthMw
					// has identified them; for the bearer-self-intro fall-through path
					// the identity is unknown and the verifier records the gap via
					// `jwt_verify_aud_skipped`.
					// Wave 1 (C4): denylist consulted so revoked ATs report active:false.
					//
					// R4: the pin is the calling client's `allowedAudiences` ∪
					// `{clientId}`, not `clientId` alone. With RFC 8707 resource
					// indicators in use every access token carries `aud: <resource
					// URI>`, so pinning the client id made a resource server unable
					// to introspect the tokens issued FOR it — `active: false`
					// unless it happened to be registered under a `client_id` equal
					// to the resource URI, which is a workaround, not a design.
					// (`auth.proxy`'s `CLIENT_ID`/`CLIENT_SECRET` validation mode
					// walked into the same wall.)
					//
					// The widened set is not a new trust decision: it is exactly the
					// ceiling every issuing grant already derives an audience within
					// (`clientCredentials.mts`, `refreshToken.mts`,
					// `routes/authorize.mts` all bound derivation by
					// `allowedAudiences ∪ {clientId}`). A caller can therefore only
					// see tokens for audiences it was already registered to be
					// associated with; an audience outside that set still answers
					// `active: false`, and so do unknown, expired, revoked and
					// other-issuer tokens, which this pin never governed.
					const expectedAudiences = req.oauthClient
						? [...(req.oauthClient.allowedAudiences ?? []), req.oauthClient.clientId]
						: null;
					const verified = await verifyJwt(token, keyStore, {
						type: "access_token",
						expectedIssuer: canonicalIssuer,
						...(expectedAudiences ? { expectedAudience: expectedAudiences } : {}),
						legacyTypAccept: legacyTypAcceptOpt ?? false,
						// #296/#367: token-accepting surface — forward what the
						// composition wired, jti denylist and subject watermark both.
						revocation: { denylist: accessTokenDenylist, subjectRevocation },
						logger,
					});
					const { payload } = verified;

					// TODO-F-3: cascading revoke (RFC 7009 §2.1 SHOULD). When a refresh_token
					// family has been revoked, all access_tokens minted under the same
					// authorization grant must introspect as inactive. family_id claim is
					// optional — legacy tokens without it still succeed (no cascade available).
					const rawFamilyId = (payload as Record<string, unknown>).family_id;
					const familyId =
						typeof rawFamilyId === "string" && rawFamilyId.length > 0 ? rawFamilyId : null;
					if (familyId !== null && refreshTokenFamilyRevocation) {
						let revoked: boolean;
						try {
							revoked = await refreshTokenFamilyRevocation.isFamilyRevoked(familyId);
						} catch (cause) {
							// Fail-closed: RFC 7662 §2.2 defines `active: false` for revoked/invalid tokens.
							// When we cannot determine family revocation state, prefer inactive over active
							// (and over a 5xx) — introspect's response shape has no "temporarily_unavailable"
							// equivalent, so inactive keeps resource servers on the safe side of the scope gate.
							// Note: Tasks 3/4 use 503 temporarily_unavailable for store failures, but RFC 7662
							// has no such slot for introspect responses — inactive is the only safe fallback.
							emitAuditEvent(auditSink, {
								timestamp: new Date(),
								type: "introspect.store_unavailable",
								ip: req.ip,
								userAgent: req.get("user-agent"),
								details: {
									family_id: familyId,
									error: cause instanceof Error ? cause.message : String(cause),
								},
							});
							return res.status(200).json({ active: false });
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

					// R3: session liveness — the same read `/oauth/userinfo` and the
					// refresh grant already perform, and the missing third leg of
					// the set this handler consults. Without it a token whose
					// browser session has been logged out still introspected as
					// `active: true`, so a resource server that trusts
					// introspection (the BFF / proxy topology, where the `session`
					// grant's token now carries `sid`) kept honouring it for the
					// rest of the access-token lifetime.
					//
					// Both logout endpoints are covered, by the one read: the
					// record resolved here is deleted by `/oauth/logout`'s cascade
					// and by `/session/logout` alike. What they revoke AROUND it
					// still differs — only `/oauth/logout` revokes refresh-token
					// families — so a session that also holds a refresh token is
					// not fully ended by the session endpoint. That difference is
					// invisible from here; this check answers for the access token
					// in hand, not for the family behind it.
					//
					// Coverage, stated so the check is not read as more than it
					// is: it binds only callers that ASK. A resource server
					// validating the JWT offline — signature and `exp`, no
					// introspection — sees no logout at any point and accepts the
					// token until it expires. Self-contained tokens are like that;
					// the lever there is a short lifetime, not this read.
					//
					// Cost: one extra store read per introspection of a
					// `sid`-carrying token. Tokens without `sid` — client
					// credentials, jwt-bearer, anything minted outside a browser
					// session — do not pay it, and neither does a deployment that
					// wires no `userSessionStore`.
					//
					// Fail-closed on a store throw, for the reason the family
					// check states: RFC 7662 has no `temporarily_unavailable`
					// slot, so `active: false` is the only safe answer available.
					const rawSid = (payload as Record<string, unknown>).sid;
					const sid = typeof rawSid === "string" && rawSid.length > 0 ? rawSid : null;
					if (sid !== null && userSessionStore) {
						let userSession: Awaited<ReturnType<UserSessionStore["get"]>>;
						try {
							userSession = await userSessionStore.get(sid);
						} catch (cause) {
							emitAuditEvent(auditSink, {
								timestamp: new Date(),
								type: "introspect.store_unavailable",
								ip: req.ip,
								userAgent: req.get("user-agent"),
								details: {
									sid,
									error: cause instanceof Error ? cause.message : String(cause),
								},
							});
							return res.status(200).json({ active: false });
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
					// SF-8 + Wave 2: token_type follows the bound-token's confirmation.
					// DPoP-bound tokens (cnf.jkt present) return "DPoP" per RFC 9449 §5;
					// mTLS-bound tokens keep "Bearer" per RFC 8705 §3 (cnf.x5t#S256 does
					// not change the wire-level token type). Bearer tokens have no cnf
					// and return "Bearer". `extractConfirmation` validates member types
					// (rejects empty-string thumbprints, non-string variants); see
					// types/introspect.mts.
					// #199 I3: refuse to vouch for a token carrying an ambiguous
					// compound cnf (both `jkt` and `x5t#S256`). This AS cannot mint
					// one — a grant emits a single mechanism's confirmation — so it
					// signals a forgery or a bug. Narrowing it to the intent-explicit
					// winner would report a binding that was never issued, and
					// dropping the cnf while keeping `active: true` would be worse
					// still: the RS would treat a bound token as a plain bearer token
					// and enforce nothing. Fail closed instead, matching the refresh
					// path's structural reject (`grants/refreshToken.mts`).
					// RFC 7662 §2.2 permits `active: false` for any token the AS
					// declines to vouch for.
					if (isCompoundConfirmation(claims.cnf)) {
						logger.warn(
							{ reason: "compound_cnf", site: "introspect_body", jti },
							"introspect_compound_cnf_rejected",
						);
						return res.status(200).json({ active: false });
					}
					const cnf = extractConfirmation(claims.cnf);
					const tokenType: "Bearer" | "DPoP" = cnf && "jkt" in cnf ? "DPoP" : "Bearer";
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
					// SF-8: same non-access-token signal as the bearer path above.
					// `active: false` is required by RFC 7662 §2.2 regardless of
					// rejection reason; audit log carries the typ-mismatch signal.
					// Symmetric with the bearer-self-intro catch: only `reason
					// === "typ"` triggers `introspect_non_access_token`. All other
					// rejection reasons emit `jwt_verify_rejected` from the
					// central verifier; SIEM rules should NOT double-count.
					if (cause instanceof JwtVerificationError && cause.reason === "typ") {
						logger.warn(
							{ reason: "non_access_token", site: "introspect_body" },
							"introspect_non_access_token",
						);
					}
					return res.status(200).json({ active: false });
				}
			},
		)
		// GET /authorize — the RFC 6749 §4.1 authorization-code sequence lives in
		// routes/authorize.mts (#328), one step per concern. The #325 rate-limit
		// guard is mounted ahead of it, same position the inline handler ran its
		// check; the handler consumes the composition-time-resolved `options` —
		// no request re-reads config.
		// #284: OIDC Core §3.1.2.1 — "Authorization Servers MUST support the use
		// of the HTTP GET and POST methods". POST is how an RP sends a request
		// too large for a URL, and standard libraries reach for it. The handler
		// reads its parameters through one accessor (`authorizeParams`), so both
		// methods run the identical sequence of checks rather than a POST path
		// that quietly skips one. The router already parses form bodies.
		.get("/authorize", rateLimitGuard("authorize"), authorizeHandler)
		.post("/authorize", rateLimitGuard("authorize"), authorizeHandler);

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
	// Symmetry with logoutSupported: gates on all 4 sibling stores even
	// though federationToken only consumes 3 of them. Mirrors A4 §3.4 /
	// §8.1 composition-root invariant (now structurally enforced in
	// createApp — when ANY is wired, ALL are wired).
	const federationTokenSupported =
		!!userSessionStore &&
		!!sessionRPRegistry &&
		!!sessionFamilyIndex &&
		!!sessionFederationIndex &&
		!!federationTokenStore &&
		!!refreshTokenFamilyRevocation;

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
	// an ACCESS token comes from `oauth.revocation.accessToken` (#277).
	//
	// `readAccessTokenRevocationMode` reports an UNDECLARED key as `undefined`
	// rather than defaulting it here, which hands `createRevokeRouter` two
	// distinguishable cases:
	//   - declared `"denylist"` with no `accessTokenDenylist` → it THROWS, and a
	//     deployment claiming a capability it cannot perform fails to build.
	//   - undeclared with no denylist → it reports `unsupported_token_type`
	//     rather than a 200 that revokes nothing.
	// Whether the second case should have been allowed to boot at all is core's
	// boot validator's call (step 13.9), which reads omission as `"denylist"`
	// and refuses the composition — so through `createApp` that case never
	// reaches here, and this layer covers composition roots that call
	// `createOAuthRouter` directly.
	//
	// Refresh-token revocation is independent of the mode and of the denylist.
	router.use(
		createRevokeRouter(express, {
			clientRepository,
			keyStore,
			refreshTokenFamilyRevocation,
			accessTokenDenylist,
			accessTokenRevocation: readAccessTokenRevocationMode(config),
			logger,
			issuer: canonicalIssuer,
		}),
	);

	return { router, registry };
};
