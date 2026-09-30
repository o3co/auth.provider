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
 * `POST /login`, `POST /logout` — behind the CSRF guard and the login rate
 * limit. A password login verifies credentials, then asks session admission
 * (`admitPrimary`) before anything is written: if every requirement
 * establishes, `establishSession` writes the session and a fresh CSRF token
 * is returned; if one interrupts, its ceremony is opened on a regenerated,
 * unauthenticated session and its `403` answered. A logout invalidates the
 * records the session owns before destroying the cookie session.
 */

import {
	type AdmissionDeps,
	type AuditSink,
	admitPrimary,
	BootError,
	type CsrfTokenSigner,
	checkDeploymentMode,
	checkResolver,
	consoleLogger,
	createMemoryRateLimiter,
	createRateLimitGuard,
	type DeploymentMode,
	type FederationTokenStore,
	type Logger,
	loggableError,
	passwordPrimary,
	type RateLimiter,
	type SessionCookiePolicy,
	type SessionFederationIndex,
	type SessionRequirementResolver,
	type SubjectSessionIndex,
	type User,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { NextFunction, Request, RequestHandler, Response, Router } from "express";
import { answerInterruption } from "../answer-interruption.mjs";
import {
	createCsrfGuard,
	createCsrfIssueHandler,
	createCsrfProtectionFromConfig,
	type SessionCsrfConfigSlice,
	sessionCsrfSlice,
} from "../csrf.mjs";
import { establishSession } from "../establish-session.mjs";
import {
	admissionUnavailable,
	SESSION_STORE_UNAVAILABLE,
	USER_DIRECTORY_UNAVAILABLE,
} from "../internal/cookieSession.mjs";
import { extractUserClaims } from "../internal/extractUserClaims.mjs";
import { loginRequestFacts } from "../internal/loginRequest.mjs";
import { refusalEnvelope } from "../internal/refusalEnvelope.mjs";
import { LOGIN_RATE_LIMIT_PREFIX, readLoginRateLimitBudget } from "../loginBudget.mjs";
import { createRedirectAllowlistValidator } from "../redirect-allowlist.mjs";

const DEFAULT_SESSION_TTL_MS = 86400_000;

/** A registered session requirement's name: the `store` an interruption's `open` failure is logged under. */
type RequirementName = string;

/** The login asks admission for no `acr_values`: the table it would select against is empty. */
const NO_ACR_TABLE = Object.freeze({});

export const createRouter = (
	express: {
		Router: () => Router;
		json: () => RequestHandler;
		urlencoded: (opts: { extended: boolean }) => RequestHandler;
	},
	{
		userRepository,
		section,
		sessionCookie,
		deploymentMode,
		userSessionStore,
		subjectSessionIndex,
		federationTokenStore,
		sessionFederationIndex,
		rateLimiter,
		auditSink,
		sessionTtlMs = DEFAULT_SESSION_TTL_MS,
		logger = consoleLogger,
		csrfTokenSigner,
		requirements,
	}: {
		userRepository: UserRepository;
		/**
		 * The session module's own section, as its schema parsed it: the
		 * redirect allowlist, the CSRF settings and the login's budget.
		 */
		section: {
			readonly redirectAllowlist?: readonly string[] | undefined;
			readonly csrf?: SessionCsrfConfigSlice["csrf"];
			readonly rateLimit?: { readonly login?: unknown } | undefined;
		};
		/**
		 * The session cookie's name and attributes, as the `sessionCookiePolicy`
		 * slot carries them: the CSRF cookie is named after it and given its
		 * attributes, and a `redirect_to` is held to its domain.
		 */
		sessionCookie: Pick<SessionCookiePolicy, "name" | "secure" | "sameSite" | "domain">;
		/**
		 * The replica count, as core's `deploymentMode` slot holds it: what the
		 * login throttle's per-process fallback is refused, warned about or
		 * silent by. Anything but the three values, absence included, is a
		 * TypeError at construction.
		 */
		deploymentMode: DeploymentMode;
		userSessionStore?: UserSessionStore;
		/**
		 * Subject-keyed index of live sessions, written on every login so a
		 * credential change can enumerate what to revoke.
		 */
		subjectSessionIndex?: SubjectSessionIndex;
		/**
		 * Upstream-IdP tokens held for the session, dropped on logout. Optional:
		 * a composition that federates nothing wires none.
		 */
		federationTokenStore?: FederationTokenStore;
		/**
		 * Reverse index naming which federations a session touched. Removed
		 * alongside `federationTokenStore` so the index does not outlive the
		 * entries it points at.
		 */
		sessionFederationIndex?: SessionFederationIndex;
		/**
		 * Shared rate limiter for the login brute-force guard, so the limit holds
		 * across replicas. Omitted, the router builds a per-process in-memory
		 * limiter with the same spec and warns (or refuses when `deploymentMode`
		 * is `"multi"`).
		 */
		rateLimiter?: RateLimiter;
		/**
		 * Receives the login guard's `rate_limit.unavailable` event during a
		 * limiter outage. Absent: no audit events.
		 */
		auditSink?: AuditSink;
		/** Session TTL in milliseconds. Default: 24h. */
		sessionTtlMs?: number;
		logger?: Logger;
		/**
		 * What the CSRF token of the state-changing routes is signed and checked
		 * with: the `csrfTokenSigner` slot's signer. Tokens are signed, not
		 * stored, so a guard over the same signer (the `csrfGuard` slot) accepts
		 * the tokens these routes issue, and these routes accept the tokens it
		 * issues.
		 */
		csrfTokenSigner: CsrfTokenSigner;
		/**
		 * The registered session requirements, asked through `admitPrimary`
		 * before a password login writes anything. Required: a missing resolver,
		 * or one the boot planner did not build, is refused at construction.
		 */
		requirements: SessionRequirementResolver;
	},
): Router => {
	checkResolver(requirements, "session routes");
	if (csrfTokenSigner === undefined) {
		throw new Error(
			"session routes: csrfTokenSigner is required: pass the csrfTokenSigner slot's signer, or createSessionCsrfTokenSigner(secret)",
		);
	}
	const replicas = checkDeploymentMode(deploymentMode, "session routes: deploymentMode");
	const router = express.Router();

	/**
	 * What the login hands `admitPrimary`. The revocation boundary concerns
	 * sessions that already exist, and the acr table is empty since nothing is
	 * selected.
	 */
	const admissionDeps: AdmissionDeps = {
		userSessionStore,
		subjectRevocation: undefined,
		requirements,
		acrTable: NO_ACR_TABLE,
		logger,
		auditSink,
	};

	// Login CSRF (forcing a victim to authenticate into an attacker's account)
	// needs none of the victim's cookies, so `sameSite=lax` does not cover it
	// and a missing `Origin` must not bypass the check. CSRF trust is
	// `session.csrf.trustedOrigins`, not `cors.allowedOrigins`; the acceptance
	// rule is in `../csrf.mjs`.
	const sessionSlice = sessionCsrfSlice(sessionCookie, section.csrf);
	const csrfProtection = createCsrfProtectionFromConfig(sessionSlice, { signer: csrfTokenSigner });
	const verifyCsrf = createCsrfGuard({
		csrf: csrfProtection,
		trustedOrigins: sessionSlice.csrf?.trustedOrigins ?? [],
		logger,
	});

	// The login guard runs on the same `RateLimiter` as the OAuth endpoints,
	// keyed under the prefix the session module contributes this budget for.
	const loginLimitSpec = readLoginRateLimitBudget(section);
	if (loginLimitSpec === null) {
		throw new Error(
			"createRouter: POST /session/login requires session.rateLimit.login { windowMs, limit }",
		);
	}
	if (rateLimiter === undefined) {
		// The per-process fallback is replica-unsafe state, so the deployment
		// mode decides: "multi" refuses at boot (the limit would really be
		// limit × replicas, reset on every deploy), "single" is silent, "unset"
		// warns. The planner wraps this throw as `contribute-factory-failed`.
		if (replicas === "multi") {
			throw new BootError({
				stage: "applyContributions",
				reason: "replica-unsafe-adapter",
				message: `core.deployment.mode is "multi" but no shared rateLimiter is wired for POST /session/login: the route would fall back to a per-process limiter, so the configured ${loginLimitSpec.limit} / ${loginLimitSpec.windowSeconds}s is really ${loginLimitSpec.limit} × replicas and resets on every deploy. Wire a rateLimiter (rateLimiter.adapter = "redis"), or set core.deployment.mode = "single".`,
				details: { reason: "replica-unsafe-adapter", modules: ["session"] },
			});
		}
		if (replicas !== "single") {
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
			limits: { [LOGIN_RATE_LIMIT_PREFIX]: loginLimitSpec },
			defaultLimit: loginLimitSpec,
		});

	// The check and outage policy are core's `createRateLimitGuard`, shared
	// with the OAuth endpoints (the limiter's own `failMode`, the same
	// `rate_limit.unavailable` audit event). `RateLimit-*` headers fall back to
	// the documented login spec when the adapter reports none.
	const loginRateLimit = createRateLimitGuard({
		limiter: loginLimiter,
		tag: LOGIN_RATE_LIMIT_PREFIX,
		logger,
		auditSink,
		headerFallback: loginLimitSpec,
	});

	// `redirect_to` is held to the same exact-match, fail-closed allowlist as
	// the federation entry point: it is stored on the session and carried back
	// to pages (e.g. `MfaTransaction.redirectTo`), so it must be a value the
	// deployment named. Built once so a dead allowlist entry fails boot.
	const redirectPolicy = createRedirectAllowlistValidator({
		redirectAllowlist: section.redirectAllowlist,
		sessionDomain: sessionCookie.domain,
		allowlistConfigKey: "session.redirectAllowlist",
		factoryName: "createRouter",
	});

	/**
	 * Invalidates the server-side records a logging-out session owns, so tokens
	 * bound to its `sid` stop introspecting `active` and answering at
	 * `/userinfo`.
	 *
	 * Narrower than `/oauth/logout`'s cascade by layering: `cascadeLogout`
	 * lives in the oauth package, which this package must not depend on. This
	 * deletes what the session module owns: the `UserSession` record (primary:
	 * every liveness check resolves it), its subject-index entry, and the
	 * session's federation tokens and index (hygiene: unreachable once the
	 * record is gone, but holding upstream refresh tokens at rest).
	 * Refresh-token families are NOT revoked: a refresh token from an
	 * `/authorize` flow is revoked only by `/oauth/logout`.
	 *
	 * The delete runs first, unlike the cascade's delete-last order: that order
	 * keeps a failed cascade retryable, but this endpoint offers no retry, so
	 * the failure to avoid is a token still honoured. Every step is best effort
	 * and logged, never propagated: a store outage must not turn logout into a
	 * 5xx while the cookie, the half this endpoint can always deliver,
	 * survives. A failed delete is covered by the liveness checks failing
	 * closed.
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
	 * A store `/session/login` cannot do without could not answer (user
	 * directory, `UserSession`, cookie session regenerate/save, or an
	 * interrupting requirement's `open`): the server's outage, never a verdict
	 * on the credentials. Logged once as `login_store_unavailable` with the
	 * error's projection — never the error or the username. Answered `503`.
	 */
	const loginStoreUnavailable = (
		store: "user_repository" | "user_session" | "cookie_session" | RequirementName,
		step: "authenticate" | "create" | "regenerate" | "save" | "open",
		cause: unknown,
		context: { readonly sid?: string; readonly sub?: string } = {},
	): void => {
		logger.error({ ...context, store, step, err: loggableError(cause) }, "login_store_unavailable");
	};

	/**
	 * A best-effort rollback step failed after the `UserSession` was created:
	 * one warn, `login_cleanup_failed`. The login's own answer stands.
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

				// The user is verified and nothing is written yet: ask every
				// registered requirement over the primary core builds from this
				// login's facts. An outage is logged once, by admission.
				const admission = await admitPrimary(
					admissionDeps,
					passwordPrimary({
						subject: user.id,
						user,
						claims: extractUserClaims(user),
						authTime: new Date(),
						redirectTo: redirectTo || undefined,
						request: loginRequestFacts(req),
					}),
				);
				if (admission.outcome === "unavailable") {
					// Only a requirement reports an outage here: the requirement's words.
					return res.status(503).json(admissionUnavailable(admission.store));
				}
				if (admission.outcome === "interrupt") {
					// A requirement interrupted: regenerate, open its ceremony on the
					// regenerated session, save, and answer its `403` with a fresh
					// CSRF token — or `503` with the cookie session dropped. No
					// `UserSession` is written.
					await answerInterruption(admission, {
						req,
						res,
						csrf: csrfProtection,
						reporter: {
							storeUnavailable: (store, step, cause) => loginStoreUnavailable(store, step, cause),
						},
					});
					return;
				}

				// Every requirement answered `establish`: `establishSession` writes
				// the establishment's primary (`amr` `["pwd"]`, RFC 8176, composed by
				// core). This route supplies its log vocabulary
				// (`login_store_unavailable`, `login_cleanup_failed`); a failure is
				// `503` with everything rolled back.
				const established = await establishSession(admission.establishment, {
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
				});
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
			// Read the session's identifiers before destroying it: `destroy`
			// empties the bag.
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
				// The cookie store could not destroy the browser session: `503` so
				// the client retries. The records are already gone, so the surviving
				// cookie is refused at `/authorize` and its tokens at
				// `/oauth/introspect` and `/oauth/userinfo`.
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
