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
import crypto from "node:crypto";
import type { Request, RequestHandler, Response, Router } from "express";
import type { PassportStatic } from "passport";

import type { AppConfig } from "#/config/application.schema.mjs";
import type { FederationRegistry } from "#/federations/types.mjs";

declare module "express-session" {
	interface SessionData {
		redirectTo?: string;
		oauth_csrf_state?: string;
		isAuthenticated?: boolean;
		user?: Record<string, unknown>;
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
		federationRegistry,
	}: { passport: PassportStatic; config: AppConfig; federationRegistry: FederationRegistry },
): Router => {
	const router = express.Router();

	router
		.use(express.json())
		.use(express.urlencoded({ extended: false }))
		.get("/oauth/:provider", (req: Request, res: Response, next) => {
			const provider = federationRegistry.get(String(req.params.provider));
			if (!provider || !provider.enabled) {
				return res.status(404).json({ message: "NotFound" });
			}

			const { redirect_to } = req.query;
			if (redirect_to != null) {
				if (typeof redirect_to !== "string") {
					return res.status(400).json({
						error: "invalid_redirect",
						error_description: "Invalid redirect_to",
					});
				}

				const validation = provider.validateRedirect(redirect_to);
				if (!validation.ok) {
					return res.status(validation.status).json({
						error: validation.error,
						error_description: validation.errorDescription,
					});
				}
			}

			const csrfState = crypto.randomBytes(16).toString("hex");
			req.session.oauth_csrf_state = csrfState;
			if (typeof redirect_to === "string") {
				req.session.redirectTo = redirect_to;
			}

			return req.session.save((err) => {
				if (err) return res.status(500).json({ message: "Error saving session" });
				return passport.authenticate(provider.strategyName, {
					scope: provider.scope,
					state: csrfState,
				})(req, res, next);
			});
		})
		.get(
			"/oauth/:provider/callback",
			(req: Request, res: Response, next) => {
				const provider = federationRegistry.get(String(req.params.provider));
				if (!provider || !provider.enabled) {
					return res.status(404).json({ message: "NotFound" });
				}

				if (!req.session.oauth_csrf_state || req.query.state !== req.session.oauth_csrf_state) {
					return res.status(400).json({ message: "invalid state" });
				}

				return passport.authenticate(provider.strategyName, {
					session: false,
					failureRedirect: config.endpoints.login.url,
				})(req, res, next);
			},
			(req: Request, res: Response) => {
				const provider = federationRegistry.get(String(req.params.provider));
				if (!provider || !provider.enabled) {
					return res.status(404).json({ message: "NotFound" });
				}

				const user = req.user;
				const { redirectTo } = req.session;

				req.session.regenerate((err) => {
					if (err) return res.status(500).json({ message: "Error regenerating session" });

					req.session.isAuthenticated = true;
					req.session.user = user as Record<string, unknown> | undefined;

					const redirectResult = provider.resolveCallbackRedirect({ redirectTo });
					if (!redirectResult.ok) {
						return res.status(redirectResult.status).json({
							error: redirectResult.error,
							error_description: redirectResult.errorDescription,
						});
					}

					return res.redirect(redirectResult.value);
				});
			},
		);

	return router;
};
