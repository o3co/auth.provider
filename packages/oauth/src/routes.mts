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
	describeIssuerRejection,
	emitAuditEvent,
	errorEnvelope,
	type FederationProviderHandle,
	type FederationTokenStore,
	formatObject,
	type GrantHandlerResolver,
	type GrantPolicyHook,
	isEmailVerified,
	isGrantTypeAllowed,
	JwtVerificationError,
	type KeyStore,
	type Logger,
	type PublicClient,
	type RateLimiter,
	type RefreshTokenFamilyRevocation,
	type SenderConstraint,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type UserSessionStore,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import { parseAccessTokenHeader } from "./accessTokenHeader.mjs";
import {
	deriveAudienceFromResources,
	extractResourceParam,
	unrepresentedResources,
} from "./grants/_resourceIndicator.mjs";
import { resolvePkceSupportedMethods } from "./grants/pkce.mjs";
import { createClientAuthMiddleware, resolveRealm } from "./middleware/clientAuth.mjs";
import * as federationTokenRoute from "./routes/federationToken.mjs";
import * as logoutRoute from "./routes/logout.mjs";
import { createRevokeRouter } from "./routes/revoke.mjs";
import * as userinfo from "./routes/userinfo.mjs";
import {
	extractConfirmation,
	type IntrospectResponse,
	isCompoundConfirmation,
} from "./types/introspect.mjs";

// Session data type augmentation
//
// D-1 (v0.5.1): `code_client_id`, `code_redirect_uri`, `granted_scopes` were
// removed because /authorize no longer writes identity binding into the
// session — `Code.client_id` and `Code.redirect_uri` carry it instead. `code`
// is retained because the /token grant clears it from in-flight pre-v0.5.1
// sessions (see authorization.mts `sessionMutation.clear`).
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

	// #266: `iss` is a property of the deployment, never of a request. The token
	// endpoint used to compute `config.oauth.jwt.issuer ?? req.get("host")`, so an
	// unconfigured deployment behind a trusted proxy minted tokens whose issuer the
	// caller chose. A canonical issuer is now required, and it is the only source —
	// resolved once at router-creation time so no request path can reach a fallback.
	// It also populates the `realm` parameter on `WWW-Authenticate: Basic`
	// challenges (RFC 7235 §2.2).
	const issuerRejection = checkCanonicalIssuer(
		(config as { oauth?: { jwt?: { issuer?: unknown } } }).oauth?.jwt?.issuer,
	);
	if (issuerRejection) {
		throw new Error(
			`createOAuthRouter: oauth.jwt.issuer ${describeIssuerRejection(issuerRejection)}`,
		);
	}
	const canonicalIssuer = (config as unknown as { oauth: { jwt: { issuer: string } } }).oauth.jwt
		.issuer;
	// SF-1 / Phase G / S2: legacyTypAccept default is `false`
	// (v0.5.x was `true`). Use a defensive cast so partial-config test fixtures
	// (no `oauth.jwt` block at all) don't throw at router construction.
	const legacyTypAcceptOpt = (config as { oauth?: { jwt?: { legacyTypAccept?: boolean } } }).oauth
		?.jwt?.legacyTypAccept;
	// #267: the migration escape hatch for the `/authorize` first-party
	// invariant. Resolved once at router construction; `CoreConfigSchema`
	// requires the key, so a deployment that boots through the schema has
	// answered it deliberately. The defensive cast is for hand-built configs
	// that never passed the schema — same treatment `legacyTypAccept` gets
	// above, and the safe reading of an absent value is `false` (enforce).
	// #297: gate token issuance on Store-published email verification. Off
	// unless the deployment opted in; the defensive read matches the treatment
	// the sibling flags get, for hand-built configs that never met the schema.
	const requireEmailVerified =
		(config as { oauth?: { requireEmailVerified?: boolean } }).oauth?.requireEmailVerified === true;
	const allowUnmarkedClients =
		(config as { oauth?: { authorize?: { allowUnmarkedClients?: boolean } } }).oauth?.authorize
			?.allowUnmarkedClients === true;
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

	async function checkRateLimit(req: Request, res: Response, tag: string): Promise<boolean> {
		if (!rateLimiter) return true;
		const ip = req.ip ?? "unknown";
		const key = `${tag}:ip:${ip}`;
		let decision: Awaited<ReturnType<typeof rateLimiter.check>>;
		try {
			// CP-10: pass the same normalized ip into the check context as the
			// key derivation uses, so limiters that re-use ctx.ip for logging
			// or secondary keying observe the same value.
			decision = await rateLimiter.check(key, {
				ip,
				userAgent: req.get("user-agent"),
			});
		} catch (cause) {
			// OR-5: the previous implementation was silent fail-open with a
			// fire-and-forget audit event. The audit sink is typically Redis-
			// backed too, so during a Redis outage the audit emission also
			// silently drops — operators saw nothing while rate limiting was
			// down for hours. The `failMode` policy below makes the behavior
			// configurable, and the `logger.error` call ensures operators see
			// the outage regardless of audit-sink status.
			const failMode = config.rateLimit.failMode;
			const errorMessage = cause instanceof Error ? cause.message : String(cause);
			logger.error(
				{ error: errorMessage, mode: failMode, tag, ip },
				failMode === "open" ? "rate_limiter_failed_open" : "rate_limiter_failed_closed",
			);
			// Belt-and-suspenders: keep the audit event for ops dashboards
			// that consume it. The logger call above is the operator-visible
			// path; the audit event is the structured pipeline path.
			emitAuditEvent(auditSink, {
				timestamp: new Date(),
				type: "rate_limit.unavailable",
				ip,
				userAgent: req.get("user-agent"),
				details: {
					tag,
					error: errorMessage,
				},
			});
			if (failMode === "closed") {
				res.status(503).json({
					error: "service_unavailable",
					error_description: "Rate limiter temporarily unavailable",
				});
				return false;
			}
			return true;
		}
		if (!decision.allowed) {
			if (decision.resetAt) {
				const secs = Math.max(0, Math.ceil((decision.resetAt.getTime() - Date.now()) / 1000));
				res.setHeader("Retry-After", String(secs));
			}
			// AS-2: rate-limit body migrated from `{error, reason}` to RFC 6749 §5.2
			// `{error, error_description}` so all auth-product error responses share
			// a single shape. `decision.reason` is the operator-visible cause string.
			// `||` (not `??`) so that `decision.reason: ""` from a custom rate
			// limiter also falls back — the envelope helper would otherwise drop
			// the empty string and produce a 429 response with no `error_description`.
			res.status(429).json(errorEnvelope("rate_limited", decision.reason || "Rate limit exceeded"));
			return false;
		}
		return true;
	}

	router
		.use(express.json())
		.use(express.urlencoded({ extended: false }))
		.post(
			"/token",
			// D-6 ordering: rate limit BEFORE client auth so repeated unauthenticated
			// hits cannot escape rate limiting via the clientAuthMw rejection path
			// (and so DoS amplification through repository lookups is bounded).
			async (req: Request, res: Response, next) => {
				if (!(await checkRateLimit(req, res, "token"))) return;
				next();
			},
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
					return res.status(400).json({
						error: "unsupported_grant_type",
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
								allowedGrantTypes: req.oauthClient.allowedGrantTypes,
								allowedAudiences: req.oauthClient.allowedAudiences,
								senderConstrained: req.oauthClient.senderConstrained,
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
				// `client_credentials` and WebAuthn keep their stricter
				// deny-by-absence rule on top, so machine-to-machine access is
				// still never acquired by omission.
				//
				// RFC 6749 §5.2 `unauthorized_client`: "The authenticated client is
				// not authorized to use this authorization grant type."
				if (!isGrantTypeAllowed(ctx.authenticatedClient?.allowedGrantTypes, grant_type)) {
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
				const { result, sessionMutation } = await handler.handle(ctx);

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
			async (req: Request, res: Response, next) => {
				if (!(await checkRateLimit(req, res, "introspect"))) return;
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
							...(accessTokenDenylist ? { denylist: accessTokenDenylist } : {}),
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
					const verified = await verifyJwt(token, keyStore, {
						type: "access_token",
						expectedIssuer: canonicalIssuer,
						...(req.oauthClient ? { expectedAudience: req.oauthClient.clientId } : {}),
						legacyTypAccept: legacyTypAcceptOpt ?? false,
						...(accessTokenDenylist ? { denylist: accessTokenDenylist } : {}),
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
		.get("/authorize", async (req: Request, res: Response) => {
			if (!(await checkRateLimit(req, res, "authorize"))) return;
			if (!req.session.isAuthenticated) {
				return res.redirect(
					`${config.endpoints.login.url}?redirect_to=${encodeURIComponent(`${req.protocol}://${req.get("host")}${req.originalUrl}`)}`,
				);
			}

			// A-1: RFC 6749 §4.1.2.1 — errors that prevent redirect (invalid client / redirect_uri)
			// must return 400 JSON. Other errors redirect with error params.
			const redirectError = (
				redirectUri: string,
				error: string,
				errorDescription: string,
				state?: string | null,
			): Response => {
				const url = new URL(redirectUri);
				url.searchParams.append("error", error);
				url.searchParams.append("error_description", errorDescription);
				if (typeof state === "string") url.searchParams.append("state", state);
				return res.redirect(url.toString()) as unknown as Response;
			};

			if ([req.query.response_type].flat().includes("code")) {
				const {
					client_id = null,
					scope = null,
					state = null,
					code_challenge = null,
					code_challenge_method = null,
					redirect_uri = null,
				} = req.query;

				const toStr = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

				// A-1: invalid client_id and redirect_uri → 400 JSON (cannot redirect)
				if (typeof client_id !== "string" || !client_id) {
					return res
						.status(400)
						.json({ error: "invalid_request", error_description: "client_id is required" });
				}

				if (typeof redirect_uri !== "string" || !redirect_uri) {
					return res
						.status(400)
						.json({ error: "invalid_request", error_description: "redirect_uri is required" });
				}

				let client: PublicClient | null;
				try {
					client = await clientRepository.findById(client_id);
				} catch {
					return res
						.status(500)
						.json({ error: "server_error", error_description: "Failed to fetch client" });
				}
				if (!client) {
					// Cannot redirect — client unknown, redirect_uri untrusted
					return res
						.status(400)
						.json({ error: "invalid_client", error_description: "client not found" });
				}
				const allowedUris = client.allowedRedirectUris;
				const allowedScopes = client.allowedScopes;

				if (!allowedUris.includes(redirect_uri)) {
					// Cannot redirect — redirect_uri not trusted
					return res
						.status(400)
						.json({ error: "invalid_request", error_description: "redirect_uri not allowed" });
				}

				// From here redirect_uri is validated — use redirect-based errors per RFC 6749 §4.1.2.1

				// A-1: validate response_type (already checked above via includes("code") but handle unknown types)
				const responseType = toStr(req.query.response_type);
				if (responseType !== "code") {
					return redirectError(
						redirect_uri,
						"unsupported_response_type",
						`response_type "${responseType}" is not supported`,
						toStr(state),
					);
				}

				// #268: the code flow leads to `grant_type=authorization_code` at
				// the token endpoint, so a client not registered for it must be
				// turned away here rather than after the user has authenticated
				// and a code has been minted. `redirect_uri` is validated above,
				// so RFC 6749 §4.1.2.1 puts this error in the redirect.
				if (!isGrantTypeAllowed(client.allowedGrantTypes, "authorization_code")) {
					await emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "token.issued.failure",
						clientId: client_id,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { reason: "grant_type_not_allowed", grant_type: "authorization_code" },
					});
					return redirectError(
						redirect_uri,
						"unauthorized_client",
						"client is not authorized for the authorization_code grant",
						toStr(state),
					);
				}

				// #267: `/authorize` mints a code as soon as the session is
				// authenticated, with no consent step. A forced top-level
				// navigation from an attacker's page therefore makes a logged-in
				// victim's browser mint a code, bound to the victim's session and
				// delivered to the named client's registered `redirect_uri` —
				// and since the attacker chose the `code_challenge`, they redeem
				// it. That is defensible in a pure first-party OP and only there.
				//
				// The assumption is now enforced instead of assumed. This does
				// not make the endpoint safe against forced navigation for a
				// client that *is* first-party; it stops a client that should
				// never have been trusted with a silent code from being
				// registered into that position. Consent (#284) is the step that
				// changes the former.
				if (client.firstParty !== true) {
					if (!allowUnmarkedClients) {
						await emitAuditEvent(auditSink, {
							timestamp: new Date(),
							type: "token.issued.failure",
							clientId: client_id,
							ip: req.ip,
							userAgent: req.get("user-agent"),
							details: { reason: "client_not_first_party" },
						});
						return redirectError(
							redirect_uri,
							"unauthorized_client",
							"client is not authorized for the authorization endpoint",
							toStr(state),
						);
					}
					// The migration window: admitted, but every request says so,
					// naming the client, so the work left to do is visible in the
					// logs rather than only in a config file nobody re-reads.
					logger.warn(
						{ clientId: client_id, reason: "not_marked_first_party" },
						"authorize_client_not_marked_first_party",
					);
				}

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
				if (requireEmailVerified && !isEmailVerified(req.session.user)) {
					await emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "token.issued.failure",
						clientId: client_id,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { reason: "email_not_verified" },
					});
					return redirectError(
						redirect_uri,
						"access_denied",
						"email address is not verified",
						toStr(state),
					);
				}

				// B-7/B-8: resolve PKCE config
				const grantsConfig = config.oauth.grants as
					| Record<string, Record<string, unknown>>
					| undefined;
				const authorizationConfig = grantsConfig?.authorization_code as
					| Record<string, unknown>
					| undefined;
				const pkceConfig = authorizationConfig?.pkce as Record<string, unknown> | undefined;
				const pkceRequired: boolean = pkceConfig?.required === true;
				const defaultMethod: string =
					typeof pkceConfig?.defaultMethod === "string" ? pkceConfig.defaultMethod : "plain";
				// TS-4 (v0.5.1): per-element validation via `resolvePkceSupportedMethods`.
				// See authorization.mts for the rationale — `Array.isArray + as string[]`
				// silently accepted non-string operator-typed values. The router
				// already has `logger` in scope (createOAuthRouter options); forward
				// it so the helper's misconfig warnings reach the operator.
				const supportedMethods = resolvePkceSupportedMethods(pkceConfig, logger);

				// D-6 (RFC 9700 §2.1.1): PKCE/S256 is mandatory for public clients
				// regardless of operator `pkce.required` config. Public clients have
				// no transport-level credential at /token, so the only authenticity
				// gate on the code redemption is the verifier — accepting `plain`
				// or omitting PKCE entirely would let anyone with the issued code
				// exchange it for tokens.
				if (client.tokenEndpointAuthMethod === "none") {
					if (typeof code_challenge !== "string" || !code_challenge) {
						return redirectError(
							redirect_uri,
							"invalid_request",
							"code_challenge is required for public clients",
							toStr(state),
						);
					}
					const requestedMethod = toStr(code_challenge_method);
					// Public clients must explicitly select S256 — no defaulting to
					// `plain` per the operator-configured `defaultMethod`. The check
					// uses the raw query parameter so absence (= would silently pick
					// up `defaultMethod`) is rejected as `plain` would be.
					const effectivePublicMethod = requestedMethod ?? "plain";
					if (effectivePublicMethod !== "S256") {
						return redirectError(
							redirect_uri,
							"invalid_request",
							'code_challenge_method must be "S256" for public clients',
							toStr(state),
						);
					}
				}

				// B-8: PKCE required check at authorize endpoint
				if (pkceRequired && (typeof code_challenge !== "string" || !code_challenge)) {
					return redirectError(
						redirect_uri,
						"invalid_request",
						"code_challenge is required",
						toStr(state),
					);
				}

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
				const nonceMaxLength = config.oauth.nonce?.maxLength ?? 256;
				if (req.query.nonce !== undefined) {
					// Reject non-string `nonce` (Copilot review on PR #126):
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
					if (typeof req.query.nonce !== "string") {
						return redirectError(
							redirect_uri,
							"invalid_request",
							"nonce must be a single string value",
							toStr(state),
						);
					}
					const nonceValue = req.query.nonce;
					if (nonceValue.length > nonceMaxLength) {
						return redirectError(
							redirect_uri,
							"invalid_request",
							`nonce exceeds maximum length of ${nonceMaxLength}`,
							toStr(state),
						);
					}
					// Printable ASCII only (0x20-0x7E). Non-printable input could
					// confuse downstream JWT libraries that don't escape control
					// chars in JSON payloads. OIDC Core §3.1.2.1 leaves the
					// alphabet unconstrained; this is a defensive narrowing.
					if (!/^[\x20-\x7E]*$/.test(nonceValue)) {
						return redirectError(
							redirect_uri,
							"invalid_request",
							"nonce contains non-printable characters",
							toStr(state),
						);
					}
				}

				const requestedScopes = toStr(scope)?.split(" ").filter(Boolean) ?? [];
				const allowedFilteredScopes =
					requestedScopes.length > 0
						? requestedScopes.filter((s) => allowedScopes.includes(s))
						: allowedScopes;
				const configuredIssuer = config.oauth.jwt.issuer;
				const isActingAsOidcProvider =
					typeof configuredIssuer === "string" && configuredIssuer.length > 0;
				const oidcMode =
					(config.oauth as { oidcMode?: "oidc-required" | "dual" }).oidcMode ?? "oidc-required";
				if (
					isActingAsOidcProvider &&
					oidcMode === "oidc-required" &&
					// Two failure modes both undermine "OIDC required":
					//   (a) the request itself omits openid;
					//   (b) the request includes openid but the client allowlist
					//       filters it out — without checking the filtered set
					//       the request would silently proceed as OAuth-only
					//       even though the server is configured oidc-required.
					(!requestedScopes.includes("openid") || !allowedFilteredScopes.includes("openid"))
				) {
					logger.warn(
						{
							clientId: client_id,
							requestedScopes,
							allowedFilteredScopes,
						},
						"authorize_rejected_missing_openid_scope",
					);
					return redirectError(
						redirect_uri,
						"invalid_scope",
						"openid scope is required when server is acting as an OIDC OP",
						toStr(state),
					);
				}
				if (allowedFilteredScopes.length === 0 && requestedScopes.length > 0) {
					return redirectError(
						redirect_uri,
						"invalid_scope",
						"no requested scopes are allowed for this client",
						toStr(state),
					);
				}

				// C-2: policy evaluation at /authorize (evaluate-once, persist on Code).
				// The code exchange MUST NOT re-evaluate — it reads the narrowed values off
				// Code.grantedScope / Code.grantedAudience. This prevents scope escalation
				// via a crafted /token request after /authorize decided the narrow.
				let grantedScopes: readonly string[] = allowedFilteredScopes;
				let grantedAudience: readonly string[] | undefined;
				// RFC 8707 §2 at the authorization endpoint (Stage 2, #173). Read
				// from the query string here — `/authorize` is a GET — using the
				// same extractor the token endpoint uses, so a repeated
				// `?resource=` (which Express surfaces as an array) is handled
				// identically on both endpoints.
				const resourceIndicatorEnabled = config.oauth.resourceIndicator?.enabled === true;
				const authorizeResource = resourceIndicatorEnabled
					? extractResourceParam(req.query as Record<string, unknown>)
					: null;
				const subjectForPolicy =
					typeof (req.session.user as Record<string, unknown> | undefined)?.id === "string"
						? ((req.session.user as Record<string, unknown>).id as string)
						: undefined;
				if (grantPolicy) {
					// CP-11: issuer must NOT be request-derived (Host header is
					// attacker-controlled in many deployments). `canonicalIssuer` is
					// config-only, so policy decisions match the issuer claim on
					// minted tokens.
					// CP-18 (authorize side): fail-closed on policy throw. Same
					// rationale as the refresh_token path — policy is a security
					// boundary and failing open would hand out the pre-policy
					// scope ceiling.
					let decision: Awaited<ReturnType<typeof grantPolicy.evaluate>>;
					try {
						decision = await grantPolicy.evaluate(
							{
								grantType: "authorization_code",
								clientId: client_id,
								subject: subjectForPolicy,
								requestedScope: requestedScopes.length > 0 ? requestedScopes : undefined,
								originalScope: allowedScopes,
								// RFC 8707 Stage 2 (#173): `resource` is accepted at the
								// AUTHORIZATION endpoint for this flow and forwarded here,
								// so the policy can narrow `grantedAudience` to the
								// requested target before it is persisted on the code.
								// This is what keeps the token endpoint free of policy:
								// the audience decision happens once, here (C-2 / D-1).
								...(resourceIndicatorEnabled && authorizeResource
									? { resource: authorizeResource }
									: {}),
							},
							{
								ip: req.ip,
								userAgent: req.get("user-agent"),
								issuer: canonicalIssuer,
							},
						);
					} catch {
						return redirectError(
							redirect_uri,
							"temporarily_unavailable",
							"policy evaluation unavailable",
							toStr(state),
						);
					}
					if (decision.outcome === "deny") {
						return redirectError(
							redirect_uri,
							decision.error,
							decision.errorDescription ?? "policy denied",
							toStr(state),
						);
					}
					if (decision.grantedScope) {
						// CP-13: policy MUST NOT expand the client's scope ceiling.
						// Enforce grantedScope ⊆ allowedFilteredScopes (the
						// pre-policy-narrowed set) — a policy returning a scope
						// outside this is a bug or a compromised policy, and we
						// fail closed with invalid_scope per RFC 6749.
						const invalidFromPolicy = decision.grantedScope.filter(
							(s) => !allowedFilteredScopes.includes(s),
						);
						if (invalidFromPolicy.length > 0) {
							return redirectError(
								redirect_uri,
								"invalid_scope",
								`policy returned scopes outside client allowance: ${invalidFromPolicy.join(" ")}`,
								toStr(state),
							);
						}
						grantedScopes = decision.grantedScope;
					}
					if (decision.grantedAudience) grantedAudience = decision.grantedAudience;
				}

				// B-7: resolve code_challenge_method — use provided value or defaultMethod
				let resolvedMethod: string | undefined;
				if (typeof code_challenge === "string" && code_challenge) {
					// Challenge provided: use explicit method or fall back to defaultMethod
					resolvedMethod = toStr(code_challenge_method) ?? defaultMethod;
					if (!supportedMethods.includes(resolvedMethod)) {
						return redirectError(
							redirect_uri,
							"invalid_request",
							`code_challenge_method "${resolvedMethod}" is not supported`,
							toStr(state),
						);
					}
				} else {
					// No challenge: method is irrelevant (no PKCE)
					resolvedMethod = undefined;
				}

				// CP-14: persist `undefined` when no scopes/audiences survived —
				// an empty array would later stringify to `scope: ""` in the
				// token response, which is indistinguishable from "scope claim
				// omitted" and surprises consumers.
				const scopeForPersist = grantedScopes.length > 0 ? grantedScopes : undefined;
				// RFC 8707 §2 audience derivation (Stage 2, #173). When a `resource`
				// was requested and no policy narrowed an audience, derive it here so
				// the value persisted on the code — which the token endpoint reads and
				// enforces against — already reflects the request. Deriving at
				// `/authorize` rather than `/token` is what keeps the audience decided
				// exactly once (C-2 / D-1). Bounded by the client's allowedAudiences
				// plus its own id, the same ceiling a policy-returned audience meets.
				let effectiveGrantedAudience = grantedAudience;
				if (resourceIndicatorEnabled && authorizeResource && !effectiveGrantedAudience) {
					const derived = deriveAudienceFromResources(
						authorizeResource,
						new Set([...(client.allowedAudiences ?? []), client_id]),
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
				if (resourceIndicatorEnabled && authorizeResource) {
					const effectiveAudience = audienceForPersist?.[0] ?? client_id;
					const unrepresented = unrepresentedResources(authorizeResource, effectiveAudience);
					if (unrepresented.length > 0) {
						return redirectError(
							redirect_uri,
							"invalid_target",
							`requested_resources_not_in_audience: ${unrepresented.join(" ")}`,
							toStr(state),
						);
					}
				}

				let issue: Awaited<ReturnType<typeof codeRepository.createCode>>;
				try {
					issue = await codeRepository.createCode({
						client_id, // D-1: identity binding embedded in the code record (replaces session.code_client_id)
						redirect_uri, // D-1: required field (closes IH-4 vacuous-pass)
						code_challenge: toStr(code_challenge),
						code_challenge_method: resolvedMethod,
						grantedScope: scopeForPersist,
						grantedAudience: audienceForPersist,
						// NEW (TODO-F-3): OIDC round-trip state on the code record.
						nonce: typeof req.query.nonce === "string" ? req.query.nonce : undefined,
						sid: typeof req.session?.sid === "string" ? req.session.sid : undefined,
					});
				} catch {
					return redirectError(
						redirect_uri,
						"server_error",
						"Failed to create authorization code",
						toStr(state),
					);
				}

				// D-1 / CR-2: identity binding lives in the code record only — no
				// session writes. Concurrent /authorize requests sharing a session
				// previously raced on `req.session.code` last-write-wins; the
				// losing request's code became unredeemable. consumeByCode (atomic
				// getDel on a single Redis node) is now the sole authenticity gate.

				const url = new URL(redirect_uri);
				url.searchParams.append("code", issue.code);
				if (typeof state === "string") {
					url.searchParams.append("state", state);
				}

				await emitAuditEvent(auditSink, {
					timestamp: new Date(),
					type: "login.success",
					subject: typeof req.session.user?.id === "string" ? req.session.user.id : undefined,
					clientId: client_id,
					ip: req.ip,
					userAgent: req.get("user-agent"),
					details: { response_type: "code" },
				});
				return res.redirect(url.toString());
			}

			// A-1: unknown response_type without a validated redirect_uri → 400 JSON
			return res.status(400).json({
				error: "unsupported_response_type",
				error_description: `response_type "${req.query.response_type}" is not supported`,
			});
		});

	// OIDC Core §5.3 — UserInfo endpoint
	router.use(
		userinfo.createRouter(express, {
			keyStore,
			userSessionStore,
			refreshTokenFamilyRevocation,
			accessTokenDenylist,
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
				auditSink,
				logger,
				issuer: canonicalIssuer,
				legacyTypAccept: legacyTypAcceptOpt,
			}),
		);
	}

	// RFC 7009 — Token Revocation endpoint.
	// Always mounted. `accessTokenDenylist` is optional: when absent, AT
	// revocation is a warn-logged no-op (RT revocation is unaffected).
	router.use(
		createRevokeRouter(express, {
			clientRepository,
			keyStore,
			refreshTokenFamilyRevocation,
			accessTokenDenylist,
			logger,
			issuer: canonicalIssuer,
		}),
	);

	return { router, registry };
};
