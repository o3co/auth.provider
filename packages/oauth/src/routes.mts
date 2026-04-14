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
	type ClientRepository,
	type CodeRepository,
	formatObject,
	type GrantRegistry,
	type KeyStore,
	type PublicClient,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import rateLimit from "express-rate-limit";
import { decodeProtectedHeader, jwtVerify } from "jose";
import type { PassportStatic } from "passport";

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
	}
}

export const createOAuthRouter = async (
	express: {
		Router: () => Router;
		json: () => RequestHandler;
		urlencoded: (opts: { extended: boolean }) => RequestHandler;
	},
	{
		passport,
		registry,
		config,
		clientRepository,
		codeRepository,
		keyStore,
	}: {
		passport: PassportStatic;
		registry: GrantRegistry;
		config: AppConfig;
		clientRepository: ClientRepository;
		codeRepository: CodeRepository;
		keyStore: KeyStore;
	},
): Promise<{ router: Router; registry: GrantRegistry }> => {
	const router = express.Router();

	const tokenRateLimit = rateLimit({
		windowMs: config.rateLimit.token.windowMs,
		limit: config.rateLimit.token.limit,
		standardHeaders: true,
		legacyHeaders: false,
	});

	const authorizeRateLimit = rateLimit({
		windowMs: config.rateLimit.authorize.windowMs,
		limit: config.rateLimit.authorize.limit,
		standardHeaders: true,
		legacyHeaders: false,
	});

	router
		.use(express.json())
		.use(express.urlencoded({ extended: false }))
		.post("/token", tokenRateLimit, async (req: Request, res: Response) => {
			const { grant_type } = req.body;
			const issuer = config.oauth.jwt.issuer ?? req.get("host");

			if (typeof grant_type !== "string" || grant_type === "") {
				return res.status(400).json({
					error: "unsupported_grant_type",
					error_description: "grant_type must be a non-empty string",
				});
			}

			const handler = registry.get(grant_type);
			if (!handler) {
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
				return res.status(result.status).json(result.tokens);
			}
			const errorBody: Record<string, unknown> = { error: result.error };
			if (result.errorDescription) errorBody.error_description = result.errorDescription;
			if (result.status === 401) {
				res.set("WWW-Authenticate", "Bearer");
			}
			return res.status(result.status).json(errorBody);
		})
		// RFC 7662: Token Introspection
		.post(
			"/introspect",
			tokenRateLimit,
			async (req: Request, res: Response, next) => {
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
						const key = keyStore.getVerificationKey(kid ?? keyStore.current.kid);
						await jwtVerify(bearerToken, key);
						return next();
					} catch {
						return res.status(200).json({ active: false });
					}
				}
				return passport.authenticate("oauth2-client-password", { session: false })(req, res, next);
			},
			async (req: Request, res: Response) => {
				const { token } = req.body;
				if (!token) {
					return res.status(200).json({ active: false });
				}
				try {
					const header = decodeProtectedHeader(token);
					const key = keyStore.getVerificationKey(header.kid ?? keyStore.current.kid);
					const { payload } = await jwtVerify(token, key);
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
		.get("/authorize", authorizeRateLimit, async (req: Request, res: Response) => {
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
				const authorizationConfig = grantsConfig?.authorization as
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
				const grantedScopes =
					requestedScopes.length > 0
						? requestedScopes.filter((s) => allowedScopes.includes(s))
						: allowedScopes;

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

				let issue: Awaited<ReturnType<typeof codeRepository.createCode>>;
				try {
					issue = await codeRepository.createCode({
						code_challenge: toStr(code_challenge),
						code_challenge_method: resolvedMethod,
						redirect_uri,
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
				req.session.granted_scopes = grantedScopes.length > 0 ? grantedScopes : undefined;

				const url = new URL(redirect_uri);
				url.searchParams.append("code", issue.code);
				if (typeof state === "string") {
					url.searchParams.append("state", state);
				}

				return res.redirect(url.toString());
			}

			// A-1: unknown response_type without a validated redirect_uri → 400 JSON
			return res.status(400).json({
				error: "unsupported_response_type",
				error_description: `response_type "${req.query.response_type}" is not supported`,
			});
		});

	return { router, registry };
};
