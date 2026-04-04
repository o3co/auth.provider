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
import type { NextFunction, Request, RequestHandler, Response, Router } from "express";
import rateLimit from "express-rate-limit";
import type { PassportStatic } from "passport";

import type { AppConfig } from "#/config/application.schema.mjs";

declare module "express-session" {
	interface SessionData {
		isAuthenticated?: boolean;
		user?: Record<string, unknown>;
		redirectTo?: string;
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

	const allowedOrigins = config.cors.allowedOrigins;
	const verifyCsrfOrigin = (req: Request, res: Response, next: NextFunction): void => {
		const origin = req.get("origin");
		if (!origin) {
			next();
			return;
		}
		const serverOrigin = `${req.protocol}://${req.get("host")}`;
		if (origin !== serverOrigin && !allowedOrigins.includes(origin)) {
			res.status(403).json({ message: "forbidden" });
			return;
		}
		next();
	};

	const loginRateLimit = rateLimit({
		windowMs: config.rateLimit.login.windowMs,
		limit: config.rateLimit.login.limit,
		standardHeaders: true,
		legacyHeaders: false,
	});

	router
		.use(express.json())
		.use(express.urlencoded({ extended: false }))
		.post(
			"/login",
			verifyCsrfOrigin,
			loginRateLimit,
			(req: Request, res: Response, next: NextFunction): void => {
				const { redirect_to } = req.body;
				if (redirect_to != null) {
					if (typeof redirect_to !== "string" || redirect_to.length > 2048) {
						res.status(400).json({
							error: "invalid_redirect",
							error_description: "Invalid redirect_to",
						});
						return;
					}
					try {
						const parsed = new URL(redirect_to);
						if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
							res.status(400).json({
								error: "invalid_redirect",
								error_description: "Invalid redirect URL scheme",
							});
							return;
						}
						const cookieDomain = config.session.domain;
						if (cookieDomain) {
							const normalizedDomain = cookieDomain.replace(/^\./, "");
							if (
								parsed.hostname !== normalizedDomain &&
								!parsed.hostname.endsWith(`.${normalizedDomain}`)
							) {
								res.status(400).json({
									error: "invalid_redirect",
									error_description: "Redirect domain not allowed",
								});
								return;
							}
						}
					} catch {
						res.status(400).json({
							error: "invalid_redirect",
							error_description: "Invalid redirect URL",
						});
						return;
					}
				}
				next();
			},
			passport.authenticate("local", {
				session: true,
			}),
			(req: Request, res: Response) => {
				const user = req.user;
				const redirectTo = req.body.redirect_to as string | undefined;
				req.session.regenerate((err: Error | null) => {
					if (err) {
						return res.status(500).json({ message: "Error regenerating session" });
					}
					req.session.isAuthenticated = true;
					req.session.user = user as Record<string, unknown> | undefined;
					if (redirectTo) {
						req.session.redirectTo = redirectTo;
					}
					return res.status(200).json({ message: "Logged in successfully" });
				});
			},
		)
		.post("/logout", verifyCsrfOrigin, (req: Request, res: Response) => {
			req.session.destroy((err: Error | null) => {
				if (err) {
					return res.status(500).json({ message: "Error logging out" });
				}
				return res.status(200).json({ message: "Logged out successfully" });
			});
		});

	return router;
};
