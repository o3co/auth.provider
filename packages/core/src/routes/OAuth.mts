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
import type { Request, RequestHandler, Response, Router } from "express";
import rateLimit from "express-rate-limit";
import { decodeProtectedHeader, jwtVerify } from "jose";

import type { PassportStatic } from "passport";
import type { AppConfig } from "#/config/application.schema.mjs";
import type { GrantRegistry } from "#/grants/registry.mjs";
import { formatObject } from "#/grants/token.mjs";
import type { KeyStore } from "#/keys/KeyStore.mjs";
import type { ClientRepository, PublicClient } from "#/repositories/ClientRepository.mjs";
import type { CodeRepository } from "#/repositories/CodeRepository.mjs";

// Session data type augmentation
declare module "express-session" {
	interface SessionData {
		client?: Record<string, unknown>;
		user?: Record<string, unknown>;
		code?: string;
		code_client_id?: string;
		granted_scopes?: string[];
		isAuthenticated?: boolean;
	}
}

export const createRouter = (
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
): { router: Router; registry: GrantRegistry } => {
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
			const issuer = req.get("host");

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
				return res.status(result.status).json(result.tokens);
			}
			const errorBody: Record<string, unknown> = { error: result.error };
			if (result.errorDescription) errorBody.error_description = result.errorDescription;
			return res.status(result.status).json(errorBody);
		})
		// RFC 7662: Token Introspection
		// Auth: Bearer <token> (self-introspect only) or client_id + client_secret (any token)
		.post(
			"/introspect",
			async (req: Request, res: Response, next) => {
				const auth = req.headers.authorization;
				if (auth?.startsWith("Bearer ")) {
					const bearerToken = auth.slice(7);
					if (req.body.token !== bearerToken) {
						return res.status(403).json({ active: false });
					}
					try {
						const { kid } = decodeProtectedHeader(bearerToken);
						const key = keyStore.getVerificationKey(kid ?? keyStore.current.kid);
						await jwtVerify(bearerToken, key);
						return next();
					} catch {
						return res.status(401).json({ active: false });
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
					const { exp, iss, aud, sub } = payload;
					const claims = payload as Record<string, unknown>;
					const azp = typeof claims.azp === "string" ? claims.azp : undefined;
					const scope = typeof claims.scope === "string" ? claims.scope : undefined;
					return res.status(200).json(
						formatObject({
							active: true,
							exp,
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

				if (typeof client_id !== "string" || !client_id) {
					return res.status(400).json({ message: "client_id is required" });
				}

				if (typeof redirect_uri !== "string" || !redirect_uri) {
					return res.status(400).json({ message: "invalid redirect_uri" });
				}

				let client: PublicClient | null;
				try {
					client = await clientRepository.findById(client_id);
				} catch {
					return res.status(500).json({ message: "Failed to fetch client" });
				}
				if (!client) {
					return res.status(400).json({ message: "client not found" });
				}
				const allowedUris = client.allowedRedirectUris;
				const allowedScopes = client.allowedScopes;

				if (!allowedUris.includes(redirect_uri)) {
					return res.status(400).json({ message: "redirect_uri not allowed" });
				}

				const requestedScopes = toStr(scope)?.split(" ").filter(Boolean) ?? [];
				const grantedScopes =
					requestedScopes.length > 0
						? requestedScopes.filter((s) => allowedScopes.includes(s))
						: allowedScopes;

				const resolvedMethod = code_challenge
					? (toStr(code_challenge_method) ?? "S256")
					: toStr(code_challenge_method);

				let issue: Awaited<ReturnType<typeof codeRepository.createCode>>;
				try {
					issue = await codeRepository.createCode({
						code_challenge: toStr(code_challenge),
						code_challenge_method: resolvedMethod,
					});
				} catch {
					return res.status(500).json({ message: "Failed to create authorization code" });
				}

				req.session.code = issue.code;
				req.session.code_client_id = client_id;
				req.session.granted_scopes = grantedScopes.length > 0 ? grantedScopes : undefined;

				const url = new URL(redirect_uri);
				url.searchParams.append("code", issue.code);
				if (typeof state === "string") {
					url.searchParams.append("state", state);
				}

				return res.redirect(url.toString());
			}

			return res
				.status(400)
				.json({ message: `Unknown response_type "${req.query.response_type}"` });
		});

	return { router, registry };
};
