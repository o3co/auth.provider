/*
 * Copyright 2026 1o1 Inc.
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
import jwt, { type JwtPayload } from "jsonwebtoken";

import type { PassportStatic } from "passport";

import { HttpError } from "#/clients/base/RESTClient.mjs";
import type { AppClient } from "#/clients/Client.mjs";
import type { ClientFactory } from "#/clients/ClientFactory.mjs";
import type { CodeClient } from "#/clients/Code.mjs";
import type { AppConfig } from "#/config/application.schema.mjs";
import { createGrantRegistry, type GrantRegistry } from "./grants/registry.mjs";
import { formatObject } from "./grants/token.mjs";

// Session data type augmentation
declare module "express-session" {
	interface SessionData {
		client?: Record<string, unknown>;
		user?: Record<string, unknown>;
		code?: string;
		code_client_id?: string;
		code_challenge?: string;
		code_challenge_method?: string;
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
		config,
		clients,
	}: { passport: PassportStatic; config: AppConfig; clients: ClientFactory },
): { router: Router; registry: GrantRegistry } => {
	const router = express.Router();
	const registry = createGrantRegistry({ config, clients, passport });

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

			return handler.handle({ req, res, issuer });
		})
		// RFC 7662: Token Introspection
		// Auth: Bearer <token> (self-introspect only) or client_id + client_secret (any token)
		.post(
			"/introspect",
			(req: Request, res: Response, next) => {
				const auth = req.headers.authorization;
				if (auth?.startsWith("Bearer ")) {
					const bearerToken = auth.slice(7);
					if (req.body.token !== bearerToken) {
						return res.status(403).json({ active: false });
					}
					try {
						jwt.verify(bearerToken, config.oauth.jwt.secret);
						return next();
					} catch {
						return res.status(401).json({ active: false });
					}
				}
				return passport.authenticate("oauth2-client-password", { session: false })(req, res, next);
			},
			(req: Request, res: Response) => {
				const { token } = req.body;
				if (!token) {
					return res.status(200).json({ active: false });
				}
				try {
					const payload = jwt.verify(token, config.oauth.jwt.secret) as JwtPayload;
					const { exp, iss, aud, sub, scopes, type, user, client, ip } = payload;
					return res.status(200).json(
						formatObject({
							active: true,
							exp,
							iss,
							aud,
							sub,
							scopes,
							type,
							user,
							client,
							ip,
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

				let allowedUris: string[];
				let allowedScopes: string[];
				try {
					[allowedUris, allowedScopes] = await Promise.all([
						(clients.get("Client") as AppClient).listAllowedRedirectUris(client_id),
						(clients.get("Client") as AppClient).listAllowedScopes(client_id),
					]);
				} catch (err) {
					if (err instanceof HttpError && err.status === 404) {
						return res.status(400).json({ message: "client not found" });
					}
					return res.status(500).json({ message: "Failed to fetch client" });
				}

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

				let issue: Awaited<ReturnType<CodeClient["createCode"]>>;
				try {
					issue = await (clients.get("code") as CodeClient).createCode({
						code_challenge: toStr(code_challenge),
						code_challenge_method: resolvedMethod,
					});
				} catch {
					return res.status(500).json({ message: "Failed to create authorization code" });
				}

				req.session.code = issue.code;
				req.session.code_client_id = client_id;
				req.session.code_challenge = issue.code_challenge;
				req.session.code_challenge_method = issue.code_challenge_method;
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
