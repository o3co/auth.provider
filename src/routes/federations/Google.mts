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
import crypto from "node:crypto";
import type { Request, RequestHandler, Response, Router } from "express";
import type { PassportStatic } from "passport";

import type { AppConfig } from "../../../config/application.schema.mjs";

declare module "express-session" {
	interface SessionData {
		redirectTo?: string;
		oauth_csrf_state?: string;
	}
}

export const createRouter = (
	express: {
		Router: () => Router;
		json: () => RequestHandler;
		urlencoded: (opts: { extended: boolean }) => RequestHandler;
	},
	{ passport, config }: { passport: PassportStatic; config: AppConfig },
): Router => {
	const router = express.Router();

	const googleEnabled = config.federations.google.enabled;

	router
		.use(express.json())
		.use(express.urlencoded({ extended: false }))
		.get("/oauth/google", (req: Request, res: Response, next) => {
			if (!googleEnabled) {
				return res.status(404).json({ message: "NotFound" });
			}
			const { redirect_to } = req.query;
			if (redirect_to != null) {
				if (typeof redirect_to !== "string" || redirect_to.length > 2048) {
					return res.status(400).json({
						error: "invalid_redirect",
						error_description: "Invalid redirect_to",
					});
				}
				try {
					const parsed = new URL(redirect_to);
					if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
						return res.status(400).json({
							error: "invalid_redirect",
							error_description: "Invalid redirect URL scheme",
						});
					}
					const cookieDomain = config.session.domain;
					if (cookieDomain) {
						const normalizedDomain = cookieDomain.replace(/^\./, "");
						if (
							parsed.hostname !== normalizedDomain &&
							!parsed.hostname.endsWith(`.${normalizedDomain}`)
						) {
							return res.status(400).json({
								error: "invalid_redirect",
								error_description: "Redirect domain not allowed",
							});
						}
					}
				} catch {
					return res.status(400).json({
						error: "invalid_redirect",
						error_description: "Invalid redirect URL",
					});
				}
			}
			const csrfState = crypto.randomBytes(16).toString("hex");
			req.session.oauth_csrf_state = csrfState;
			if (typeof redirect_to === "string") req.session.redirectTo = redirect_to;
			return req.session.save((err) => {
				if (err) return res.status(500).json({ message: "Error saving session" });
				return passport.authenticate("google", { scope: ["profile", "email"], state: csrfState })(
					req,
					res,
					next,
				);
			});
		})
		.get(
			"/oauth/google/callback",
			(req: Request, res: Response, next) => {
				if (!googleEnabled) {
					return res.status(404).json({ message: "NotFound" });
				}
				// Validate CSRF state before delegating to Passport
				if (!req.session.oauth_csrf_state || req.query.state !== req.session.oauth_csrf_state) {
					return res.status(400).json({ message: "invalid state" });
				}
				return passport.authenticate("google", {
					session: false,
					failureRedirect: config.endpoints.login.url,
				})(req, res, next);
			},
			(req: Request, res: Response) => {
				const user = req.user;
				const { redirectTo } = req.session;
				req.session.regenerate((err) => {
					if (err) return res.status(500).json({ message: "Error regenerating session" });
					req.session.isAuthenticated = true;
					req.session.user = user as Record<string, unknown> | undefined;
					const authCallbackUrl = config.endpoints.authCallback.url;
					if (redirectTo && authCallbackUrl) {
						return res.redirect(`${authCallbackUrl}?redirect_to=${encodeURIComponent(redirectTo)}`);
					}
					return res.redirect(config.endpoints.client.url);
				});
			},
		);

	return router;
};
