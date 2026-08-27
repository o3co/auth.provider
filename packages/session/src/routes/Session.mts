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
	type AuditSink,
	consoleLogger,
	createMemoryRateLimiter,
	createRateLimitGuard,
	errorEnvelope,
	type Logger,
	type RateLimiter,
	type SubjectSessionIndex,
	type User,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { NextFunction, Request, RequestHandler, Response, Router } from "express";
import {
	type CsrfProtection,
	createCsrfGuard,
	createCsrfIssueHandler,
	createCsrfProtectionFromConfig,
	type SessionCsrfConfigSlice,
} from "../csrf.mjs";
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
		subjectSessionIndex,
		rateLimiter,
		auditSink,
		sessionTtlMs = DEFAULT_SESSION_TTL_MS,
		logger = consoleLogger,
		csrf,
	}: {
		userRepository: UserRepository;
		config: AppConfig;
		userSessionStore?: UserSessionStore;
		/**
		 * Subject-keyed index of live sessions (#296).
		 *
		 * Written on every login so a credential change can enumerate what to
		 * revoke. Without it `revokeAllForSubject` has nothing to find and the
		 * whole mechanism is inert, which is why its absence is reported rather
		 * than assumed.
		 */
		subjectSessionIndex?: SubjectSessionIndex;
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
		/**
		 * Structured pipeline for the login guard's `rate_limit.unavailable`
		 * emission during a limiter outage (#325 — the OAuth endpoints emitted
		 * it, this route did not; the shared guard emits it on both). Optional:
		 * when absent no audit events are emitted, matching the OAuth routers'
		 * treatment of the slot.
		 */
		auditSink?: AuditSink;
		/** Session TTL in milliseconds. Default: 24h. */
		sessionTtlMs?: number;
		logger?: Logger;
		/**
		 * CSRF mechanism for the state-changing session routes (#272).
		 *
		 * Built from the `session` config slice when omitted. Inject one to
		 * share a single instance with routes this router does not own — the
		 * token is signed, not stored, so two instances built from the same
		 * secret already accept each other's tokens; the slot exists so a
		 * composition root can also *issue* tokens from its own pages.
		 */
		csrf?: CsrfProtection;
	},
): Router => {
	const router = express.Router();

	// #272: the previous guard read `Origin`, and called `next()` when it was
	// absent. `sameSite=lax` covers session-riding, but login CSRF — forcing a
	// victim's browser to authenticate into an attacker-controlled account —
	// needs none of the victim's cookies, so "no Origin header" was a complete
	// bypass of the only check on the route. The trust list was
	// `cors.allowedOrigins`, which answers a different question; CSRF trust is
	// now stated on `session.csrf.trustedOrigins`. See `../csrf.mjs` for the
	// acceptance rule.
	const sessionSlice = config.session as unknown as SessionCsrfConfigSlice;
	const csrfProtection = csrf ?? createCsrfProtectionFromConfig(sessionSlice);
	const verifyCsrf = createCsrfGuard({
		csrf: csrfProtection,
		trustedOrigins: sessionSlice.csrf?.trustedOrigins ?? [],
		logger,
	});

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

	// #325: the check + outage policy is core's `createRateLimitGuard`, shared
	// with the OAuth endpoints — same `failMode` read from the same config key:
	// a Redis outage should not mean "login sheds load" here and "login lets
	// everything through" there. The guard also emits the
	// `rate_limit.unavailable` audit event during an outage, which this route's
	// hand-rolled copy of the policy did not.
	//
	// `RateLimit-*` are emitted as they were under express-rate-limit
	// (`standardHeaders: true`); since #325 the OAuth endpoints emit them too.
	// `headerFallback` backs the headers with the documented login spec when
	// the adapter reports no applied limit / reset of its own.
	const loginRateLimit = createRateLimitGuard({
		limiter: loginLimiter,
		tag: "login",
		failMode: config.rateLimit.failMode,
		logger,
		auditSink,
		headerFallback: loginLimitSpec,
	});

	router
		.use(express.json())
		.use(express.urlencoded({ extended: false }))
		// Where a browser gets its first token. Safe method, so it is not itself
		// behind the guard — it mints material, it does not act on any.
		.get("/csrf", createCsrfIssueHandler(csrfProtection))
		.post(
			"/login",
			verifyCsrf,
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
						const expiresAt = new Date(now.getTime() + sessionTtlMs);
						await userSessionStore.create({
							sid,
							sub: user.id,
							authTime: now,
							expiresAt,
							claims,
						});
						// #296: record the session against its subject so a later
						// credential change can find it. Best-effort and AFTER the
						// session exists: a failure here must not deny a legitimate
						// login, and the cost is that this one session is missed by
						// `revokeAllForSubject` — logged so it is not silent.
						//
						// Written at the earliest point the session exists rather than
						// after the regeneration below, because the two failure modes
						// are not symmetric: a missing entry is a live session a
						// credential change will never find, while an orphan entry
						// costs one redundant cascade that `cascadeLogout` absorbs
						// idempotently. The regeneration rollback compensates.
						if (subjectSessionIndex) {
							try {
								await subjectSessionIndex.addSid(user.id, sid, expiresAt);
							} catch (err) {
								logger.error({ err, sub: user.id, sid }, "subject_session_index_write_failed");
							}
						}
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
							// #296: the session is gone, so its subject-index entry must
							// go too — otherwise `revokeAllForSubject` would enumerate a
							// sid that no longer exists.
							subjectSessionIndex?.removeSid(user.id, sid).catch(() => {
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
					// The caller is now on a regenerated session; hand it a fresh
					// token in the same response so the follow-up `/session/logout`
					// does not need another round trip to `/session/csrf`.
					csrfProtection.issue(res);
					return res.status(200).json({ message: "Logged in successfully" });
				});
			},
		)
		.post("/logout", verifyCsrf, (req: Request, res: Response) => {
			req.session.destroy((err: Error | null) => {
				if (err) {
					return res.status(500).json(errorEnvelope("server_error", "Session destroy failed"));
				}
				return res.status(200).json({ message: "Logged out successfully" });
			});
		});

	return router;
};
