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

import { randomUUID } from "node:crypto";
import {
	type AppConfig,
	consoleLogger,
	createMemoryRateLimiter,
	errorEnvelope,
	type Logger,
	type RateLimiter,
	type User,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { NextFunction, Request, RequestHandler, Response, Router } from "express";
import { extractUserClaims } from "../internal/extractUserClaims.mjs";

declare module "express-session" {
	interface SessionData {
		isAuthenticated?: boolean;
		user?: Record<string, unknown>;
		redirectTo?: string;
		/** UserSession ID — set by local login and preserved across session regeneration. */
		sid?: string;
	}
}

const DEFAULT_SESSION_TTL_MS = 86400_000;

export const createRouter = (
	express: {
		Router: () => Router;
		json: () => RequestHandler;
		urlencoded: (opts: { extended: boolean }) => RequestHandler;
	},
	{
		userRepository,
		config,
		userSessionStore,
		rateLimiter,
		sessionTtlMs = DEFAULT_SESSION_TTL_MS,
		logger = consoleLogger,
	}: {
		userRepository: UserRepository;
		config: AppConfig;
		userSessionStore?: UserSessionStore;
		/**
		 * Shared rate limiter for the login brute-force guard.
		 *
		 * `/session/login` used to run express-rate-limit's per-process
		 * MemoryStore. Behind a load balancer every replica kept its own
		 * buckets, so the configured limit was really limit × replicas and it
		 * reset on every deploy — while the OAuth endpoints already had a
		 * Redis-backed limiter this route could not reach (#270).
		 *
		 * When omitted the router builds a private in-memory limiter with the
		 * same spec and warns, so a deployment that wires no limiter keeps the
		 * protection it had rather than losing it — but is told the guard is
		 * per-process.
		 */
		rateLimiter?: RateLimiter;
		/** Session TTL in milliseconds. Default: 24h. */
		sessionTtlMs?: number;
		logger?: Logger;
	},
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
			res.status(403).json(errorEnvelope("access_denied", "CSRF origin check failed"));
			return;
		}
		next();
	};

	// The login guard now runs on the same `RateLimiter` component the OAuth
	// endpoints use, so a deployment that wires the Redis adapter gets one
	// shared bucket set across replicas instead of one per process (#270).
	//
	// `login` is the key prefix by which an adapter resolves this route's spec;
	// it is the example key in `RateLimiter.check`'s own contract. Both bundled
	// adapters seed `limits.login` from `config.rateLimit.login`, so the
	// documented window and limit apply without the operator restating them.
	const loginLimitSpec = {
		limit: config.rateLimit.login.limit,
		windowSeconds: Math.max(1, Math.ceil(config.rateLimit.login.windowMs / 1000)),
	};
	if (rateLimiter === undefined) {
		logger.warn(
			{
				limit: loginLimitSpec.limit,
				windowSeconds: loginLimitSpec.windowSeconds,
			},
			"login_rate_limiter_not_shared",
		);
	}
	// Falling back rather than leaving the route unguarded: this is the endpoint
	// that exists to resist password guessing, and a per-process bucket is weak
	// protection, not absent protection. The warning above says which one is in
	// force so the weakness is stated rather than implied.
	const loginLimiter: RateLimiter =
		rateLimiter ??
		createMemoryRateLimiter({
			limits: { login: loginLimitSpec },
			defaultLimit: loginLimitSpec,
		});

	const loginRateLimit = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
		const ip = req.ip ?? "unknown";
		let decision: Awaited<ReturnType<RateLimiter["check"]>>;
		try {
			decision = await loginLimiter.check(`login:ip:${ip}`, {
				ip,
				userAgent: req.get("user-agent"),
			});
		} catch (cause) {
			// Same `failMode` policy the OAuth endpoints apply, read from the same
			// config key: a Redis outage should not mean "login sheds load" here
			// and "login lets everything through" there.
			const failMode = config.rateLimit.failMode;
			const errorMessage = cause instanceof Error ? cause.message : String(cause);
			logger.error(
				{ error: errorMessage, mode: failMode, tag: "login", ip },
				failMode === "open" ? "rate_limiter_failed_open" : "rate_limiter_failed_closed",
			);
			if (failMode === "closed") {
				res
					.status(503)
					.json(errorEnvelope("service_unavailable", "Rate limiter temporarily unavailable"));
				return;
			}
			next();
			return;
		}

		// `RateLimit-*` are preserved because this route emitted them under
		// express-rate-limit (`standardHeaders: true`). The OAuth endpoints do
		// not, but keeping behaviour on the route being changed matters more
		// than matching routes that are not.
		//
		// The advertised limit is the one the adapter reports having *applied*,
		// not the one configured here. They differ whenever an operator declares
		// `limits.login` on the adapter — which deliberately overrides the value
		// seeded from `rateLimit.login` — and a header advertising a limit no
		// request is measured against is worse than no header. `decision.limit`
		// is optional, so a custom adapter that does not report one falls back
		// to the configured value.
		res.setHeader("RateLimit-Limit", String(decision.limit ?? loginLimitSpec.limit));
		if (decision.remaining !== undefined) {
			res.setHeader("RateLimit-Remaining", String(Math.max(0, decision.remaining)));
		}
		const resetSeconds =
			decision.resetAt === undefined
				? loginLimitSpec.windowSeconds
				: Math.max(0, Math.ceil((decision.resetAt.getTime() - Date.now()) / 1000));
		res.setHeader("RateLimit-Reset", String(resetSeconds));

		if (!decision.allowed) {
			if (decision.resetAt !== undefined) {
				res.setHeader("Retry-After", String(resetSeconds));
			}
			res.status(429).json(errorEnvelope("rate_limited", decision.reason || "Rate limit exceeded"));
			return;
		}
		next();
	};

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
			async (req: Request, res: Response) => {
				const username = typeof req.body?.username === "string" ? req.body.username : undefined;
				const password = typeof req.body?.password === "string" ? req.body.password : undefined;
				if (!username || !password) {
					return res.status(400).json({
						error: "invalid_request",
						error_description: "missing credentials",
					});
				}

				let user: User | null;
				try {
					user = await userRepository.authenticate(username, password);
				} catch (err) {
					logger.warn({ err }, "local login authenticate failed");
					return res.status(503).json({
						error: "temporarily_unavailable",
						error_description: "User directory temporarily unavailable",
					});
				}
				if (!user) {
					return res.status(401).json({
						error: "invalid_credentials",
						error_description: "Incorrect username or password.",
					});
				}

				const redirectTo = req.body.redirect_to as string | undefined;

				// Generate sid and create UserSession before regenerating the browser session,
				// so we can restore the sid on the new session afterwards.
				let sid: string | undefined;
				if (userSessionStore) {
					const claims = extractUserClaims(user);
					const now = new Date();
					sid = randomUUID();
					try {
						await userSessionStore.create({
							sid,
							sub: user.id,
							authTime: now,
							expiresAt: new Date(now.getTime() + sessionTtlMs),
							claims,
						});
					} catch {
						// Fail-closed: store unavailable — return controlled 503 JSON rather
						// than an unhandled rejection hitting Express's default HTML error
						// handler. Matches the /token grant fail-closed pattern (CP-16/CP-17).
						// RFC 6749 §5.2 error shape for consistency with other /login failures.
						return res.status(503).json({
							error: "temporarily_unavailable",
							error_description: "Session store temporarily unavailable",
						});
					}
				}

				req.session.regenerate((err: Error | null) => {
					if (err) {
						// Best-effort rollback: UserSession was created but session regeneration failed.
						// Delete the orphan record so it doesn't leak. Ignore cleanup errors — the
						// primary error is already being returned to the caller.
						if (sid && userSessionStore) {
							userSessionStore.delete(sid).catch(() => {
								/* best-effort cleanup */
							});
						}
						return res
							.status(500)
							.json(errorEnvelope("server_error", "Session regeneration failed"));
					}
					req.session.isAuthenticated = true;
					req.session.user = user as Record<string, unknown> | undefined;
					if (redirectTo) {
						req.session.redirectTo = redirectTo;
					}
					// Restore sid on the new session so downstream (token/introspect) can read it.
					if (sid) {
						req.session.sid = sid;
					}
					return res.status(200).json({ message: "Logged in successfully" });
				});
			},
		)
		.post("/logout", verifyCsrfOrigin, (req: Request, res: Response) => {
			req.session.destroy((err: Error | null) => {
				if (err) {
					return res.status(500).json(errorEnvelope("server_error", "Session destroy failed"));
				}
				return res.status(200).json({ message: "Logged out successfully" });
			});
		});

	return router;
};
