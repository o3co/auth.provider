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
	emitAuditEvent,
	type FederationProviderHandle,
	type FederationTokenStoreBase,
	formatObject,
	type GrantPolicyHookBase,
	type GrantRegistry,
	type KeyStore,
	type PublicClient,
	type RateLimiterBase,
	type RefreshTokenStoreBase,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import { decodeProtectedHeader, jwtVerify } from "jose";
import { createClientAuthMiddleware } from "./middleware/clientAuth.mjs";
import * as federationTokenRoute from "./routes/federationToken.mjs";
import * as logoutRoute from "./routes/logout.mjs";
import * as userinfo from "./routes/userinfo.mjs";

// Session data type augmentation
declare module "express-session" {
	interface SessionData {
		client?: Record<string, unknown>;
		user?: Record<string, unknown>;
		code?: string;
		code_client_id?: string;
		code_redirect_uri?: string;
		granted_scopes?: string[];
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
		refreshTokenStore,
		userSessionStore,
		sessionRPRegistry,
		sessionFamilyIndex,
		sessionFederationIndex,
		federationTokenStore,
		getFederationProviders = () => undefined,
	}: {
		registry: GrantRegistry;
		config: AppConfig;
		clientRepository: ClientRepository;
		codeRepository: CodeRepository;
		keyStore: KeyStore;
		rateLimiter?: RateLimiterBase;
		auditSink?: AuditSinkBase;
		grantPolicy?: GrantPolicyHookBase;
		refreshTokenStore?: RefreshTokenStoreBase;
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
	},
): Promise<{ router: Router; registry: GrantRegistry }> => {
	const router = express.Router();

	// Construct once at router-creation time so the closure is not re-allocated per request.
	const clientAuthMw = createClientAuthMiddleware(clientRepository);

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
			// Fail-open: if the limiter backend is unavailable we prefer to serve
			// the auth flow over 5xx-ing every request. Operators see the outage
			// via the audit event below and via their limiter's own telemetry.
			emitAuditEvent(auditSink, {
				timestamp: new Date(),
				type: "rate_limit.unavailable",
				ip,
				userAgent: req.get("user-agent"),
				details: {
					tag,
					error: cause instanceof Error ? cause.message : String(cause),
				},
			});
			return true;
		}
		if (!decision.allowed) {
			if (decision.resetAt) {
				const secs = Math.max(0, Math.ceil((decision.resetAt.getTime() - Date.now()) / 1000));
				res.setHeader("Retry-After", String(secs));
			}
			res.status(429).json({ error: "rate_limited", reason: decision.reason });
			return false;
		}
		return true;
	}

	router
		.use(express.json())
		.use(express.urlencoded({ extended: false }))
		.post("/token", async (req: Request, res: Response) => {
			if (!(await checkRateLimit(req, res, "token"))) return;
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

			const ctx = {
				body: req.body,
				session: req.session,
				issuer,
				metadata: { ip: req.ip },
				ip: req.ip,
				userAgent: req.get("user-agent"),
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
					clientId: typeof req.body.client_id === "string" ? req.body.client_id : undefined,
					ip: req.ip,
					userAgent: req.get("user-agent"),
					details: { grant_type },
				});
				return res.status(result.status).json(result.tokens);
			}
			const errorBody: Record<string, unknown> = { error: result.error };
			if (result.errorDescription) errorBody.error_description = result.errorDescription;
			if (result.status === 401) {
				res.set("WWW-Authenticate", "Bearer");
			}
			await emitAuditEvent(auditSink, {
				timestamp: new Date(),
				type: "token.issued.failure",
				clientId: typeof req.body.client_id === "string" ? req.body.client_id : undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { grant_type, error: result.error },
			});
			return res.status(result.status).json(errorBody);
		})
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
						const { kid } = decodeProtectedHeader(bearerToken);
						const key = await keyStore.getVerificationKey(kid ?? keyStore.getSigningKidFallback());
						await jwtVerify(bearerToken, key);
						return next();
					} catch {
						return res.status(200).json({ active: false });
					}
				}
				return clientAuthMw(req, res, next);
			},
			async (req: Request, res: Response) => {
				const { token } = req.body;
				if (!token) {
					return res.status(200).json({ active: false });
				}
				try {
					const header = decodeProtectedHeader(token);
					const key = await keyStore.getVerificationKey(
						header.kid ?? keyStore.getSigningKidFallback(),
					);
					const { payload } = await jwtVerify(token, key);

					// TODO-F-3: cascading revoke (RFC 7009 §2.1 SHOULD). When a refresh_token
					// family has been revoked, all access_tokens minted under the same
					// authorization grant must introspect as inactive. family_id claim is
					// optional — legacy tokens without it still succeed (no cascade available).
					const rawFamilyId = (payload as Record<string, unknown>).family_id;
					const familyId =
						typeof rawFamilyId === "string" && rawFamilyId.length > 0 ? rawFamilyId : null;
					if (familyId !== null && refreshTokenStore) {
						let revoked: boolean;
						try {
							revoked = await refreshTokenStore.isFamilyRevoked(familyId);
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

					const { exp, iat, iss, aud, sub } = payload;
					const claims = payload as Record<string, unknown>;
					const azp = typeof claims.azp === "string" ? claims.azp : undefined;
					const scope = typeof claims.scope === "string" ? claims.scope : undefined;
					return res.status(200).json(
						formatObject({
							active: true,
							exp,
							iat,
							iss,
							aud,
							sub,
							azp,
							scope,
							token_type: header.typ,
						}),
					);
				} catch {
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
				const supportedMethods: string[] = Array.isArray(pkceConfig?.supportedMethods)
					? (pkceConfig.supportedMethods as string[])
					: ["S256", "plain"];

				// B-8: PKCE required check at authorize endpoint
				if (pkceRequired && (typeof code_challenge !== "string" || !code_challenge)) {
					return redirectError(
						redirect_uri,
						"invalid_request",
						"code_challenge is required",
						toStr(state),
					);
				}

				const requestedScopes = toStr(scope)?.split(" ").filter(Boolean) ?? [];
				const allowedFilteredScopes =
					requestedScopes.length > 0
						? requestedScopes.filter((s) => allowedScopes.includes(s))
						: allowedScopes;

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
						code_challenge: toStr(code_challenge),
						code_challenge_method: resolvedMethod,
						redirect_uri,
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

				req.session.code = issue.code;
				req.session.code_client_id = client_id;
				req.session.code_redirect_uri = redirect_uri;
				req.session.granted_scopes = grantedScopes.length > 0 ? [...grantedScopes] : undefined;

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
			// Transitional: routes.mts still holds the legacy refreshTokenStore
			// local. Task A6 will rename the local + dep field. Passing the
			// legacy 3-method store into a 2-method-typed param is sound via
			// structural subtyping (legacy is a superset of FamilyRevocation).
			refreshTokenFamilyRevocation: refreshTokenStore,
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
		!!refreshTokenStore &&
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
		!!refreshTokenStore;

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
				refreshTokenStore: refreshTokenStore!,
				clientRepository,
				getFederationProviders,
				auditSink,
			}),
		);
	}

	if (federationTokenSupported) {
		router.use(
			federationTokenRoute.createRouter(express, {
				keyStore,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				refreshTokenStore: refreshTokenStore!,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				userSessionStore: userSessionStore!,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				sessionFederationIndex: sessionFederationIndex!,
				// biome-ignore lint/style/noNonNullAssertion: composition-root invariant per A4 §3.4 / §8.1 + truthy gate above
				federationTokenStore: federationTokenStore!,
				clientRepository,
				getFederationProviders,
				auditSink,
			}),
		);
	}

	return { router, registry };
};
