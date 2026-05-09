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
	type AppConfig,
	type AuditSinkBase,
	type ClientRepository,
	type CodeRepository,
	consoleLogger,
	emitAuditEvent,
	errorEnvelope,
	type FederationProviderHandle,
	type FederationTokenStoreBase,
	formatObject,
	type GrantPolicyHookBase,
	type GrantRegistry,
	JwtVerificationError,
	type KeyStore,
	type Logger,
	type PublicClient,
	type RateLimiterBase,
	type RefreshTokenFamilyRevocation,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type UserSessionStore,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import { resolvePkceSupportedMethods } from "./grants/pkce.mjs";
import { createClientAuthMiddleware } from "./middleware/clientAuth.mjs";
import * as federationTokenRoute from "./routes/federationToken.mjs";
import * as logoutRoute from "./routes/logout.mjs";
import * as userinfo from "./routes/userinfo.mjs";

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
		userSessionStore,
		sessionRPRegistry,
		sessionFamilyIndex,
		sessionFederationIndex,
		federationTokenStore,
		getFederationProviders = () => undefined,
		logger = consoleLogger,
	}: {
		registry: GrantRegistry;
		config: AppConfig;
		clientRepository: ClientRepository;
		codeRepository: CodeRepository;
		keyStore: KeyStore;
		rateLimiter?: RateLimiterBase;
		auditSink?: AuditSinkBase;
		grantPolicy?: GrantPolicyHookBase;
		refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
		userSessionStore?: UserSessionStore;
		sessionRPRegistry?: SessionRPRegistry;
		sessionFamilyIndex?: SessionFamilyIndex;
		sessionFederationIndex?: SessionFederationIndex;
		federationTokenStore?: FederationTokenStoreBase;
		/**
		 * Lazy getter for the federation providers Map. Evaluated at request time so
		 * module init order does not affect resolution — pass `() => context.federationProviders`
		 * from `module.mts`. Defaults to `() => undefined` when not provided.
		 */
		getFederationProviders?: () => ReadonlyMap<string, FederationProviderHandle> | undefined;
		logger?: Logger;
	},
): Promise<{ router: Router; registry: GrantRegistry }> => {
	const router = express.Router();

	// Construct once at router-creation time so the closure is not re-allocated per request.
	// `issuer` populates the `realm` parameter on `WWW-Authenticate: Basic`
	// challenges (RFC 7235 §2.2). When the operator has not configured a
	// canonical issuer (or this router is constructed in a partial-config test
	// fixture), the middleware falls back to the literal "oauth".
	const issuerForRealm = (config as { oauth?: { jwt?: { issuer?: string } } }).oauth?.jwt?.issuer;
	// SF-1: legacyTypAccept default is `true` for v0.5.x. Use the same
	// defensive cast as `issuerForRealm` so partial-config test fixtures
	// (no `oauth.jwt` block at all) don't throw at router construction.
	const legacyTypAcceptOpt = (config as { oauth?: { jwt?: { legacyTypAccept?: boolean } } }).oauth
		?.jwt?.legacyTypAccept;
	// `/oauth/token` MUST accept public clients (`tokenEndpointAuthMethod: "none"`)
	// because PKCE/S256 at `/oauth/authorize` is their authenticity gate.
	const tokenClientAuthMw = createClientAuthMiddleware(clientRepository, {
		issuer: issuerForRealm,
		logger,
		allowPublicClients: true,
	});
	// `/oauth/introspect` MUST reject public clients per RFC 7662 §2.1 — a
	// known client_id is a non-secret value and would otherwise let any party
	// query token metadata. The default (`allowPublicClients: false`) applies.
	const introspectClientAuthMw = createClientAuthMiddleware(clientRepository, {
		issuer: issuerForRealm,
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
				const issuer = config.oauth.jwt.issuer ?? req.get("host");

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
					issuer,
					metadata: { ip: req.ip },
					ip: req.ip,
					userAgent: req.get("user-agent"),
					authenticatedClient: req.oauthClient
						? {
								clientId: req.oauthClient.clientId,
								tokenEndpointAuthMethod: req.oauthClient.tokenEndpointAuthMethod,
							}
						: null,
				};
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
				const auth = req.headers.authorization;
				if (auth?.startsWith("Bearer ")) {
					const bearerToken = auth.slice(7);
					// Self-introspection pattern: RFC 7662 requires a valid credential to call introspect.
					// When the caller uses their own token as the Bearer credential, the token in the
					// request body must match that Bearer token. If they differ, return inactive (not 403)
					// per RFC 7662 §2.2 — the server must not reveal whether the token exists.
					if (req.body.token !== bearerToken) {
						return res.status(200).json({ active: false });
					}
					try {
						// SF-1: bearer self-intro — calling-client identity is not yet
						// established (introspectClientAuthMw is skipped on this fall-
						// through path), so audience pinning is deferred. alg / iss /
						// typ + signature are still pinned by the central verifier.
						await verifyJwt(bearerToken, keyStore, {
							type: "access_token",
							expectedIssuer: issuerForRealm ?? "",
							legacyTypAccept: legacyTypAcceptOpt ?? true,
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
					const verified = await verifyJwt(token, keyStore, {
						type: "access_token",
						expectedIssuer: issuerForRealm ?? "",
						...(req.oauthClient ? { expectedAudience: req.oauthClient.clientId } : {}),
						legacyTypAccept: legacyTypAcceptOpt ?? true,
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
					// SF-8 (RFC 7662 §2.2): `token_type` is the OAuth 2.0 token-type
					// identifier registry value (`Bearer` per RFC 6750 §6.1.1), NOT
					// the JOSE `typ` header value (`at+jwt`). Hardcode the literal —
					// the SF-1 verifier with `type: "access_token"` already enforces
					// `typ: "at+jwt"` upstream, so any token reaching this point
					// has been confirmed as a Bearer access token.
					return res.status(200).json(
						formatObject({
							active: true,
							exp,
							iat,
							iss,
							aud,
							sub,
							azp,
							client_id: clientId,
							scope,
							token_type: "Bearer",
							jti: typeof jti === "string" ? jti : undefined,
						}),
					);
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
				const subjectForPolicy =
					typeof (req.session.user as Record<string, unknown> | undefined)?.id === "string"
						? ((req.session.user as Record<string, unknown>).id as string)
						: undefined;
				if (grantPolicy) {
					// CP-11: issuer must NOT be request-derived (Host header is
					// attacker-controlled in many deployments). Prefer the
					// configured jwt.issuer so policy decisions match the issuer
					// claim on minted tokens.
					const trustedIssuer = config.oauth.jwt.issuer ?? "";
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
							},
							{
								ip: req.ip,
								userAgent: req.get("user-agent"),
								issuer: trustedIssuer,
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
				const audienceForPersist =
					grantedAudience && grantedAudience.length > 0 ? grantedAudience : undefined;

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
			issuer: issuerForRealm,
			legacyTypAccept: legacyTypAcceptOpt,
			logger,
		}),
	);

	// Federation endpoints — mount conditionally based on available stores and config.
	// federationTokenStore is required for both POST /oauth/federation/:name/logout and
	// POST /oauth/federation/:name/token.
	// issuer is required for logout_token signing in POST /oauth/logout only.
	const issuer = (config as { oauth?: { jwt?: { issuer?: unknown } } }).oauth?.jwt?.issuer;
	const hasIssuer = typeof issuer === "string" && issuer.length > 0;

	// Logout (back-channel logout_token signing requires issuer).
	const logoutSupported =
		!!userSessionStore &&
		!!sessionRPRegistry &&
		!!sessionFamilyIndex &&
		!!sessionFederationIndex &&
		!!federationTokenStore &&
		!!refreshTokenFamilyRevocation &&
		hasIssuer;

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
				issuer: issuer as string,
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
				auditSink,
				logger,
				issuer: issuerForRealm,
				legacyTypAccept: legacyTypAcceptOpt,
			}),
		);
	}

	return { router, registry };
};
