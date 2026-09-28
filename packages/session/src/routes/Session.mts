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

/**
 * The `/session` routes for a browser's own login and logout — `GET /csrf`,
 * `POST /login`, `POST /logout` — with the CSRF guard and the login rate limit
 * in front of them. A password login verifies the credentials against
 * `UserRepository`, establishes the session through `establishSession`
 * (`../establish-session.mts`), the tail it shares with the federation
 * callback, and answers with a fresh CSRF token; a logout invalidates the
 * records the session owns before destroying the cookie session. The package
 * README says what each route answers and what a logout reaches.
 */

import {
	type AppConfig,
	type AuditSink,
	BootError,
	consoleLogger,
	createMemoryRateLimiter,
	createRateLimitGuard,
	type FederationTokenStore,
	type Logger,
	loggableError,
	passwordSessionAuthentication,
	type RateLimiter,
	type SessionFederationIndex,
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
import { establishSession } from "../establish-session.mjs";
import {
	SESSION_STORE_UNAVAILABLE,
	USER_DIRECTORY_UNAVAILABLE,
} from "../internal/cookieSession.mjs";
import { extractUserClaims } from "../internal/extractUserClaims.mjs";
import { refusalEnvelope } from "../internal/refusalEnvelope.mjs";
import { createRedirectAllowlistValidator } from "../redirect-allowlist.mjs";

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
		federationTokenStore,
		sessionFederationIndex,
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
		 * Upstream-IdP tokens held for the session, dropped on logout.
		 *
		 * The federation *routes* have always taken this store; the logout
		 * handler takes it too so ending a session also drops what the session
		 * accumulated at the IdP. Optional here for the same reason
		 * `userSessionStore` is: a composition that federates nothing wires
		 * none, and the handler simply has nothing to remove.
		 */
		federationTokenStore?: FederationTokenStore;
		/**
		 * Reverse index naming which federations a session touched. Removed
		 * alongside `federationTokenStore` so the index does not outlive the
		 * entries it points at.
		 */
		sessionFederationIndex?: SessionFederationIndex;
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
		// #474: the per-process fallback below is replica-unsafe state of the
		// same kind the boot guard refuses (#271), and it sat outside the guard
		// because it is built here rather than declared on a manifest. Read the
		// same three-state switch: "multi" refuses — the configured limit would
		// really be limit × replicas, reset on every deploy — "single" is silent,
		// unset warns. Thrown from a route factory, the planner wraps this as
		// `contribute-factory-failed` with this error as its `cause`.
		const deploymentMode = config.deployment?.mode;
		if (deploymentMode === "multi") {
			throw new BootError({
				stage: "applyContributions",
				reason: "replica-unsafe-adapter",
				message: `deployment.mode is "multi" but no shared rateLimiter is wired for POST /session/login: the route would fall back to a per-process limiter, so the configured ${loginLimitSpec.limit} / ${loginLimitSpec.windowSeconds}s is really ${loginLimitSpec.limit} × replicas and resets on every deploy. Wire a rateLimiter (rateLimiter.adapter = "redis"), or set deployment.mode = "single".`,
				details: { reason: "replica-unsafe-adapter", modules: ["session"] },
			});
		}
		if (deploymentMode !== "single") {
			logger.warn(
				{
					limit: loginLimitSpec.limit,
					windowSeconds: loginLimitSpec.windowSeconds,
				},
				"login_rate_limiter_not_shared",
			);
		}
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

	// #405: `redirect_to` is held to the same exact-match, fail-closed allowlist
	// #278 gave the federation entry point, and for the same reason. The rule
	// this replaced was the pre-#278 one verbatim — any absolute http(s) URL,
	// narrowed to the cookie domain only when one was configured — so with
	// `session.domain` at its `null` default the route stored any URL on the
	// internet under `req.session.redirectTo`. Nothing in this repository
	// redirects to that key today, but it is declared on `SessionData`, and an
	// MFA login transaction carries it back to the page (`MfaTransaction.redirectTo`),
	// so what an embedder reads back has to be a value the deployment named.
	//
	// Built here rather than per request so a dead allowlist entry (a typo, or
	// a target outside `session.domain`) fails boot instead of refusing logins
	// at runtime with nothing in the config looking wrong.
	const redirectPolicy = createRedirectAllowlistValidator({
		redirectAllowlist: config.session.redirectAllowlist,
		sessionDomain: config.session.domain,
		allowlistConfigKey: "session.redirectAllowlist",
		factoryName: "createRouter",
	});

	/**
	 * Invalidates the server-side records a logging-out session owns.
	 *
	 * Why this exists: `/session/logout` used to call `req.session.destroy` and
	 * nothing else, so the `UserSession` record its `sid` named stayed alive.
	 * #506 stamped `sid` on the `session` grant's access token and gave
	 * `/oauth/introspect` the liveness check `/oauth/userinfo` already ran —
	 * both resolve that record. With it alive, a token minted from a
	 * logged-out session kept introspecting `active: true` and kept answering
	 * at `/userinfo` for its full lifetime, in exactly the BFF / proxy
	 * topology whose logout IS this endpoint. `/oauth/logout` was unaffected;
	 * it runs the full cascade.
	 *
	 * SCOPE — deliberately narrower than `/oauth/logout`'s cascade, and the
	 * line is a layering fact, not an oversight. `cascadeLogout` lives in
	 * `@o3co/auth-provider-oauth`; this package depends only on core, and the
	 * two are siblings (`packages/oauth/src/routes/logout.mts` records the
	 * same edge as forbidden in the other direction). Reaching the cascade
	 * would mean either taking a dependency on oauth or writing a second
	 * implementation of a documented algorithm — the drift
	 * `docs/design-vocabulary.md` exists to prevent. So this endpoint
	 * invalidates what the session module's own dependency set already owns:
	 *
	 *   - `userSessionStore.delete` — PRIMARY. The record every liveness check
	 *     resolves; deleting it is what closes the reported gap.
	 *   - `subjectSessionIndex.removeSid` — symmetry with the login-rollback
	 *     path above, which already pairs these two. A surviving entry has
	 *     `revokeAllForSubject` (#296) enumerate a sid that no longer exists.
	 *   - `federationTokenStore` / `sessionFederationIndex` `removeBySid` —
	 *     hygiene rather than containment: once the `UserSession` record is
	 *     gone the federation-token endpoint cannot resolve the session, so
	 *     the entries are already unreachable. Removed because leaving them to
	 *     TTL keeps upstream-IdP refresh tokens at rest for no reason.
	 *
	 * NOT done here: refresh-token family revocation, and the RP-registry /
	 * family-index cleanup that goes with it. Those need
	 * `refreshTokenFamilyRevocation`, `sessionFamilyIndex` and
	 * `sessionRPRegistry`, which this module declares none of — `module.mts`
	 * records the latter two as oauth-package concerns. It is a real
	 * difference and an operator has to know it: a browser that logged in
	 * here and then ran an `/authorize` → `authorization_code` flow holds a
	 * refresh token whose family only `/oauth/logout` revokes. The `session`
	 * grant itself issues no refresh token, so the topology this fix is for
	 * has no family to revoke. Both READMEs and the operator runbook state
	 * which endpoint reaches what.
	 *
	 * ORDERING — primary invalidation FIRST, then best-effort hygiene, then
	 * the cookie. This inverts `cascadeLogout`'s §6.2 order (fanout first,
	 * `delete` last) on purpose: §6.2 defers the delete so a FAILED cascade
	 * stays retryable through the sid it did not erase, and this endpoint
	 * offers no retry of these steps — it never reports their failure to the
	 * caller, and once the cookie is destroyed the caller has lost the sid. With retry off the table the
	 * remaining criterion is which failure hurts most, and that is the one
	 * that leaves a token still honoured. So the delete runs first and is not
	 * conditional on the hygiene that follows.
	 *
	 * FAILURE — every step here is best-effort and logged, never propagated:
	 * an outage of these stores must not turn a logout into a 5xx that leaves
	 * the user holding a live cookie — the cookie is the half this endpoint can
	 * always deliver, and a 5xx would invite a retry of work that partly
	 * succeeded. The residue of a failed delete is covered from the other side
	 * — `/authorize` refuses a session whose `sid` does not resolve, and a
	 * store that cannot answer `delete` will not answer `get` either, which the
	 * introspection and userinfo liveness checks both fail closed on. The one
	 * exception is the cookie's own destroy, in the route: when the cookie
	 * store cannot destroy the browser session the user is not logged out, so
	 * that answers `503` and the client retries.
	 */
	const invalidateSessionRecords = async (sid: string, sub: string | undefined): Promise<void> => {
		if (userSessionStore) {
			try {
				await userSessionStore.delete(sid);
			} catch (err) {
				logger.error({ err: loggableError(err), sid }, "logout_user_session_delete_failed");
			}
		}
		if (subjectSessionIndex && sub) {
			try {
				await subjectSessionIndex.removeSid(sub, sid);
			} catch (err) {
				logger.error(
					{ err: loggableError(err), sub, sid },
					"logout_subject_session_index_remove_failed",
				);
			}
		}
		if (federationTokenStore) {
			try {
				await federationTokenStore.removeBySid(sid);
			} catch (err) {
				logger.error({ err: loggableError(err), sid }, "logout_federation_token_remove_failed");
			}
		}
		if (sessionFederationIndex) {
			try {
				await sessionFederationIndex.removeBySid(sid);
			} catch (err) {
				logger.error(
					{ err: loggableError(err), sid },
					"logout_session_federation_index_remove_failed",
				);
			}
		}
	};

	/**
	 * A store `/session/login` cannot do without could not answer — the user
	 * directory, the `UserSession` record, the cookie session's regeneration
	 * or save:
	 * the server's outage, never a verdict on the credentials. One line at
	 * error level, `login_store_unavailable`, `store` naming which and `step`
	 * the operation, with the error's projection — never the error, which can
	 * carry what the store was sent — and never the username. The caller
	 * answers `503 temporarily_unavailable`.
	 */
	const loginStoreUnavailable = (
		store: "user_repository" | "user_session" | "cookie_session",
		step: "authenticate" | "create" | "regenerate" | "save",
		cause: unknown,
		context: { readonly sid?: string; readonly sub?: string } = {},
	): void => {
		logger.error({ ...context, store, step, err: loggableError(cause) }, "login_store_unavailable");
	};

	/**
	 * A best-effort rollback step of a login that failed after its
	 * `UserSession` was created could not run: one warn, `login_cleanup_failed`,
	 * with `store`, `step`, the `sid` and the error's projection.
	 * `establishSession` runs the rest of the rollback, and the login's own
	 * answer stands.
	 */
	const loginCleanupFailed = (
		store: "user_session" | "subject_session_index",
		step: "delete" | "remove_sid",
		cause: unknown,
		context: { readonly sid?: string; readonly sub?: string },
	): void => {
		logger.warn({ ...context, store, step, err: loggableError(cause) }, "login_cleanup_failed");
	};

	router
		// This router's own paths, exactly: it is mounted at `/session`, a prefix
		// other modules mount routes under too, and a `.use` parser would read
		// their bodies as well.
		.all(["/csrf", "/login", "/logout"], express.json(), express.urlencoded({ extended: false }))
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
					const validation = redirectPolicy.validateRedirect(redirect_to);
					if (!validation.ok) {
						res.status(validation.status).json(refusalEnvelope(validation, logger));
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
					loginStoreUnavailable("user_repository", "authenticate", err);
					return res.status(503).json(USER_DIRECTORY_UNAVAILABLE);
				}
				if (!user) {
					return res.status(401).json({
						error: "invalid_credentials",
						error_description: "Incorrect username or password.",
					});
				}

				const redirectTo = req.body.redirect_to as string | undefined;

				// The tail of the login — the `UserSession` record, its subject-index
				// entry, the express session's regeneration, its authenticated state
				// and its save — is `establishSession`'s (`../establish-session.mts`),
				// shared with the federation callback. What this route adds is its own
				// log vocabulary: a store that could not answer is one error line,
				// `login_store_unavailable`, and a rollback step that failed one warn,
				// `login_cleanup_failed`. The login answers `503`, with everything
				// written rolled back and the request's cookie session dropped.
				const established = await establishSession(
					{
						user,
						claims: extractUserClaims(user),
						authTime: new Date(),
						// #481, the MFA ADR's D9: a password login — `amr` `["pwd"]`
						// (RFC 8176), primary `pwd`, no second factor verified.
						recorded: passwordSessionAuthentication(),
						...(redirectTo ? { redirectTo } : {}),
					},
					{
						req,
						...(userSessionStore === undefined ? {} : { userSessionStore }),
						...(subjectSessionIndex === undefined ? {} : { subjectSessionIndex }),
						sessionTtlMs,
						reporter: ({ sid, sub }) => {
							// Every line names the sid where there is one; the record's
							// create and the index removal name the subject beside it.
							const named = sid === undefined ? {} : { sid };
							return {
								storeUnavailable: (store, step, cause) =>
									loginStoreUnavailable(
										store,
										step,
										cause,
										step === "create" ? { ...named, sub } : named,
									),
								cleanupFailed: (store, step, cause) =>
									loginCleanupFailed(
										store,
										step,
										cause,
										step === "remove_sid" ? { ...named, sub } : named,
									),
								subjectIndexWriteFailed: (cause) =>
									logger.error(
										{ err: loggableError(cause), sub, ...named },
										"subject_session_index_write_failed",
									),
							};
						},
					},
				);
				if (established.outcome === "unavailable") {
					return res.status(503).json(SESSION_STORE_UNAVAILABLE);
				}
				// The caller is now on a regenerated session; hand it a fresh
				// token in the same response so the follow-up `/session/logout`
				// does not need another round trip to `/session/csrf`.
				csrfProtection.issue(res);
				return res.status(200).json({ message: "Logged in successfully" });
			},
		)
		.post("/logout", verifyCsrf, async (req: Request, res: Response) => {
			// Read the session's identifiers BEFORE destroying it: `destroy`
			// empties the bag, so a handler that reads `sid` afterwards has
			// nothing left to invalidate. This is the whole reason the endpoint
			// used to invalidate nothing but the cookie.
			const rawSid = req.session.sid;
			const sid = typeof rawSid === "string" && rawSid.length > 0 ? rawSid : undefined;
			const rawSub = req.session.user?.id;
			const sub = typeof rawSub === "string" && rawSub.length > 0 ? rawSub : undefined;

			if (sid) {
				await invalidateSessionRecords(sid, sub);
			}

			const destroyErr = await new Promise<unknown>((resolve) => {
				req.session.destroy((err: unknown) => resolve(err ?? null));
			});
			if (destroyErr) {
				// The cookie store could not destroy the browser session: its
				// outage, answered as one so the client retries. The records are
				// already gone by now, so the surviving cookie buys nothing:
				// `/authorize`'s R1b check treats an `isAuthenticated` session whose
				// `sid` no longer resolves as unauthenticated, and
				// `/oauth/introspect` and `/oauth/userinfo` refuse the tokens it
				// minted.
				logger.error(
					{
						...(sid === undefined ? {} : { sid }),
						store: "cookie_session",
						step: "destroy",
						err: loggableError(destroyErr),
					},
					"session_logout_store_unavailable",
				);
				return res.status(503).json(SESSION_STORE_UNAVAILABLE);
			}
			return res.status(200).json({ message: "Logged out successfully" });
		});

	return router;
};
