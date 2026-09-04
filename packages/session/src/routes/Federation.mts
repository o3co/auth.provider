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
import { randomBytes, randomUUID } from "node:crypto";
import {
	type AppConfig,
	consoleLogger,
	errorEnvelope,
	type FederationTokenStore,
	type Logger,
	type SessionFederationIndex,
	type SubjectSessionIndex,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import { mergeFederatedClaims } from "../federations/claim-precedence.mjs";
import { generateCodeVerifier } from "../federations/pkce.mjs";
import type { FederationRedirectPolicy } from "../federations/redirect-policy.mjs";
import { resolveFederationResponseMode } from "../federations/response-mode.mjs";
import {
	createFederationTransactionStore,
	DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
	deriveFederationTransactionCookieName,
	type FederationTransactionEnvelope,
	type FederationTransactionSessionStore,
	type FederationTransactionStore,
	mintFederationTransactionId,
} from "../federations/transaction.mjs";
import { type FederationProvider, supportsClaimMapping } from "../federations/types.mjs";
import { readCookie } from "../internal/cookies.mjs";
import { extractUserClaims } from "../internal/extractUserClaims.mjs";

declare module "express-session" {
	interface SessionData {
		/** Ephemeral federation state stored during the OAuth 2 redirect leg of a
		 *  `"query"` federation. Deleted by the callback handler immediately after
		 *  the CSRF check (reuse prevention).
		 *
		 *  A `"form_post"` federation does NOT use this field: its callback is a
		 *  cross-site POST that the session cookie does not accompany, so its
		 *  envelope lives in a federation transaction record instead (#494). */
		federation?: {
			name: string;
			state: string;
			codeVerifier: string;
			/** PB-4 nonce: bound to the upstream id_token via openid-client `expectedNonce`.
			 *  Optional so OAuth-only providers (GitHub OAuth Apps) can omit it without
			 *  breaking the shared session shape. */
			nonce?: string;
			redirectTo?: string;
		};
		/** UserSession ID — set after successful federation callback. */
		sid?: string;
		isAuthenticated?: boolean;
		user?: Record<string, unknown>;
	}
}

const DEFAULT_SESSION_TTL_MS = 86_400_000; // 24 h

/**
 * The session cookie name assumed when the caller passes neither
 * `federationTransactionCookieName` nor a config carrying `session.name`.
 *
 * It matches `reference.conf`'s default, minus the `__Host-` prefix that
 * {@link deriveFederationTransactionCookieName} would strip anyway. A
 * deployment reaches this only through a hand-built `AppConfig`; the module
 * wiring always passes the real name.
 */
const FALLBACK_SESSION_COOKIE_NAME = "auth.session";

/** Read `config.session.name` without assuming the caller supplied a full AppConfig. */
const readSessionCookieName = (config: unknown): string => {
	if (config == null || typeof config !== "object") return FALLBACK_SESSION_COOKIE_NAME;
	const session = (config as { session?: unknown }).session;
	if (session == null || typeof session !== "object") return FALLBACK_SESSION_COOKIE_NAME;
	const name = (session as { name?: unknown }).name;
	return typeof name === "string" && name.length > 0 ? name : FALLBACK_SESSION_COOKIE_NAME;
};

/**
 * Narrow a callback's parameter bag (`req.query` or `req.body`) to its string
 * entries.
 *
 * Both sources are attacker-shapeable: a repeated query parameter arrives as
 * an array, and a form body can carry nested objects. Dropping every
 * non-string here means the handler downstream compares `state` against a
 * string or against `undefined` — never against an array that might satisfy a
 * loose comparison — and that an adapter reading `callbackParams` is handed
 * flat strings rather than arbitrary parsed JSON.
 */
const readCallbackParams = (source: unknown): Readonly<Record<string, string>> => {
	if (source == null || typeof source !== "object") return {};
	return Object.fromEntries(
		Object.entries(source as Record<string, unknown>).filter(
			(entry): entry is [string, string] => typeof entry[1] === "string",
		),
	);
};

export const createRouter = (
	express: {
		Router: () => Router;
		json: () => RequestHandler;
		urlencoded: (opts: { extended: boolean }) => RequestHandler;
	},
	{
		config,
		federationProviders,
		federationRedirectPolicyResolver,
		providerCallbackUrls,
		userRepository,
		userSessionStore,
		subjectSessionIndex,
		sessionFederationIndex,
		federationTokenStore,
		sessionTtlMs = DEFAULT_SESSION_TTL_MS,
		federationTransactionTtlMs = DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
		federationTransactionCookieName,
		logger = consoleLogger,
	}: {
		config: AppConfig;
		federationProviders: ReadonlyMap<string, FederationProvider>;
		federationRedirectPolicyResolver: ReadonlyMap<string, FederationRedirectPolicy>;
		providerCallbackUrls: ReadonlyMap<string, string>;
		userRepository: UserRepository;
		userSessionStore: UserSessionStore;
		/**
		 * Subject-keyed index of live sessions (#296). Optional: a deployment
		 * that has not wired it simply has no subject-level revocation, which
		 * `revokeAllForSubject` reports rather than hiding.
		 */
		subjectSessionIndex?: SubjectSessionIndex;
		sessionFederationIndex: SessionFederationIndex;
		federationTokenStore: FederationTokenStore;
		sessionTtlMs?: number;
		/**
		 * How long a `form_post` federation's transaction may sit unconsumed
		 * (#494). Bounds the transaction cookie's `Max-Age` and the stored
		 * record's expiry together.
		 */
		federationTransactionTtlMs?: number;
		/**
		 * Name of the `form_post` transaction cookie. Defaults to the
		 * deployment's session cookie name run through
		 * {@link deriveFederationTransactionCookieName}, so it inherits the
		 * operator's naming without inheriting a `__Host-` prefix this
		 * path-scoped cookie could not satisfy.
		 */
		federationTransactionCookieName?: string;
		logger?: Logger;
	},
): Router => {
	if (!userSessionStore) throw new Error("federation routes require userSessionStore");
	if (!sessionFederationIndex) throw new Error("federation routes require sessionFederationIndex");
	if (!federationTokenStore) throw new Error("federation routes require federationTokenStore");
	if (!userRepository) throw new Error("federation routes require userRepository");
	if (!providerCallbackUrls) throw new Error("federation routes require providerCallbackUrls");

	const router = express.Router();

	const transactionCookieName =
		federationTransactionCookieName ??
		deriveFederationTransactionCookieName(readSessionCookieName(config));

	/**
	 * The federation transaction store, over the express-session store the
	 * deployment already runs (#494).
	 *
	 * Taken off the request rather than injected because that is where the
	 * store the session middleware mounted actually is, and a second wiring of
	 * the same store is a second thing that can point somewhere else. A request
	 * that reaches here without one has no session middleware in front of it,
	 * which is a composition error rather than a per-request condition — the
	 * `form_post` start leg refuses rather than silently proceeding.
	 */
	const transactionStore = (req: Request): FederationTransactionStore | undefined => {
		const store = (req as unknown as { sessionStore?: unknown }).sessionStore;
		if (store == null || typeof store !== "object") return undefined;
		const candidate = store as Partial<FederationTransactionSessionStore>;
		if (
			typeof candidate.get !== "function" ||
			typeof candidate.set !== "function" ||
			typeof candidate.destroy !== "function"
		) {
			return undefined;
		}
		return createFederationTransactionStore(candidate as FederationTransactionSessionStore);
	};

	/**
	 * The path the transaction cookie is scoped to: the provider's callback
	 * route and nothing else.
	 *
	 * Derived from `providerCallbackUrls`, the authoritative map, so the cookie
	 * is offered to exactly the URL the IdP was told to POST to. A cookie that
	 * is `SameSite=None` is offered on every cross-site request to a matching
	 * path, so the narrower that path, the less of the deployment is reachable
	 * carrying it.
	 */
	const transactionCookiePath = (provider: FederationProvider): string | undefined => {
		const callbackUrl = providerCallbackUrls.get(provider.name);
		if (!callbackUrl) return undefined;
		try {
			return new URL(callbackUrl).pathname;
		} catch {
			return undefined;
		}
	};

	/** Attributes shared by the `Set-Cookie` that issues the cookie and the one that clears it. */
	const transactionCookieAttributes = (path: string) =>
		({
			httpOnly: true,
			// `SameSite=None` is what makes the cookie reach a cross-site POST,
			// and every current browser drops such a cookie unless it is also
			// `Secure`. Apple refuses a non-`https` redirect URI anyway, so a
			// form_post federation is HTTPS-only regardless.
			secure: true,
			sameSite: "none",
			path,
		}) as const;

	/**
	 * Drop the transaction cookie. Called on every callback exit — success,
	 * refusal and error alike — so a consumed or unusable transaction never
	 * leaves a cookie behind for the next attempt to trip over.
	 */
	const clearTransactionCookie = (provider: FederationProvider, res: Response): void => {
		const path = transactionCookiePath(provider);
		if (path === undefined) return;
		res.clearCookie(transactionCookieName, transactionCookieAttributes(path));
	};

	/**
	 * The callback leg, shared verbatim by the GET and the POST route (#479).
	 *
	 * `params` is the callback's parameter set — the query string for a
	 * `"query"` federation, the `application/x-www-form-urlencoded` body for a
	 * `"form_post"` one. That substitution is the entire difference: the same
	 * `session.federation` lookup, the same `state` comparison, the same
	 * delete-then-save reuse prevention before any async work, the same PKCE
	 * verifier and nonce read from the session rather than from the request,
	 * and the same rollback ladder run either way.
	 *
	 * Factored out rather than copied precisely because it is the security
	 * boundary: two handlers would be two places for the CSRF check to drift.
	 */
	const runCallback = async (
		provider: FederationProvider,
		params: Readonly<Record<string, string>>,
		req: Request,
		res: Response,
	): Promise<unknown> => {
		// Per-handler logger child carrying the provider binding. After
		// `randomUUID()` produces `sid` below, we rebind to include `sid`
		// so subsequent calls do not need to repeat either field.
		let log = logger.child({ provider: provider.name });

		const responseMode = resolveFederationResponseMode(provider);

		// Where this federation's ephemeral state lives.
		//
		// A `"query"` federation keeps it in the session, exactly as it always
		// has: that callback is a same-site top-level GET, the session cookie is
		// sent with it, and nothing about Google or GitHub changes here.
		//
		// A `"form_post"` federation keeps it in a transaction record addressed
		// by its own cookie (#494), because that callback is a cross-site POST
		// which a `SameSite=Lax` session cookie does not accompany. The
		// transaction cookie is what binds the callback to the browser that
		// started the flow — the property the session cookie used to provide —
		// so a caller who cannot present it is refused before `state` is read at
		// all. A stolen `state` alone is therefore still worth nothing.
		let fed: FederationTransactionEnvelope | undefined;
		let transactions: FederationTransactionStore | undefined;
		let transactionId: string | undefined;

		/**
		 * Consume the transaction: drop the cookie and the stored record.
		 *
		 * Returns the store's error rather than throwing, so a caller on a
		 * refusal path can clean up best-effort while a caller about to do
		 * irreversible work can fail closed on it. A no-op for a `"query"`
		 * federation, which has no transaction to consume.
		 */
		const consumeTransaction = async (): Promise<unknown> => {
			if (!transactions || transactionId === undefined) return null;
			clearTransactionCookie(provider, res);
			const id = transactionId;
			transactionId = undefined;
			try {
				await transactions.delete(id);
				return null;
			} catch (err) {
				return err;
			}
		};

		if (responseMode === "form_post") {
			transactions = transactionStore(req);
			transactionId = readCookie(req, transactionCookieName);
			if (!transactions || transactionId === undefined || transactionId.length === 0) {
				// No transaction cookie, no transaction. This is the refusal an
				// attacker replaying a `state` from another browser meets.
				clearTransactionCookie(provider, res);
				return res.status(400).json({
					error: "invalid_session",
					error_description: "No active federation session for this provider",
				});
			}
			try {
				fed = (await transactions.get(transactionId)) ?? undefined;
			} catch (err) {
				log.warn({ err }, "federation transaction lookup failed");
				await consumeTransaction();
				return res.status(500).json({
					error: "server_error",
					error_description: "Session store unavailable",
				});
			}
		} else {
			fed = req.session.federation;
		}

		// Check the envelope is present and names this provider
		if (!fed || fed.name !== String(req.params.name)) {
			await consumeTransaction();
			return res.status(400).json({
				error: "invalid_session",
				error_description: "No active federation session for this provider",
			});
		}

		// CSRF state check — unchanged, and deliberately so: the transaction
		// cookie is an addition to this comparison, never a replacement for it.
		if (params.state !== fed.state) {
			await consumeTransaction();
			return res.status(400).json({
				error: "invalid_state",
				error_description: "CSRF state mismatch",
			});
		}

		// Copy ephemeral state to locals, then delete and persist BEFORE any async work
		// to guarantee reuse prevention even if exchangeCode throws.
		const { codeVerifier, redirectTo, nonce } = fed;
		// Fail-closed either way: if the ephemeral state cannot be retired, it
		// could still be replayed on a subsequent read. Return 500 rather than
		// continuing — an attacker who can force the failure and then replay the
		// code would bypass CSRF protection entirely.
		if (responseMode === "form_post") {
			const consumeErr = await consumeTransaction();
			if (consumeErr) {
				log.warn({ err: consumeErr }, "federation transaction delete failed");
				return res.status(500).json({
					error: "server_error",
					error_description: "Session store unavailable",
				});
			}
		} else {
			delete req.session.federation;
			const reusePrevSaveErr = await new Promise<unknown>((resolve) => {
				req.session.save((err) => resolve(err ?? null));
			});
			if (reusePrevSaveErr) {
				log.warn({ err: reusePrevSaveErr }, "reuse-prevention session save failed");
				return res.status(500).json({
					error: "server_error",
					error_description: "Session store unavailable",
				});
			}
		}

		// Fix 4: validate code query parameter early — missing/empty code must be a 400
		// rather than propagating an empty string downstream to the IdP (→ 502).
		const codeParam = params.code;
		if (typeof codeParam !== "string" || codeParam.length === 0) {
			return res.status(400).json({
				error: "invalid_request",
				error_description: "Missing authorization code",
			});
		}

		// Exchange the authorization code for a FederationProfile
		// providerCallbackUrls is the authoritative map; same entry verified above in the start handler.
		const callbackUrl = providerCallbackUrls.get(provider.name);
		if (!callbackUrl) {
			return res.status(500).json({
				error: "misconfiguration",
				error_description: `No callback URL registered for provider "${provider.name}"`,
			});
		}

		// #479: what the adapter sees of the callback, minus `code` and `state`.
		// Both are removed rather than passed through twice: `code` reaches the
		// adapter in its own field, `state` is the value this route has already
		// compared against the session and the adapter has no business
		// re-deriving, and a generic bag that still carried them would offer a
		// second, unchecked place to read a credential from.
		const { code: _code, state: _state, ...adapterCallbackParams } = params;

		let profile: Awaited<ReturnType<FederationProvider["exchangeCode"]>>;
		try {
			profile = await provider.exchangeCode({
				code: codeParam,
				codeVerifier,
				redirectUri: callbackUrl,
				// PB-4: thread the session-stored nonce so OIDC adapters bind the returned
				// id_token via openid-client `expectedNonce`. Adapters that ignore nonce
				// (OAuth-only) accept undefined gracefully.
				nonce,
				// #479: the remaining callback parameters, so an adapter can read
				// identity an IdP delivers beside the token response — Apple's
				// first-authorization `user` body. Unsigned and relayed through the
				// user agent: `mapClaims` decides what to make of it and claim
				// precedence decides where the result may land.
				callbackParams: adapterCallbackParams,
			});
		} catch (err) {
			log.warn({ err }, "federation token exchange failed");
			return res.status(502).json({
				error: "exchange_failed",
				error_description: "Token exchange with upstream IdP failed",
			});
		}

		if (!profile.sub) {
			return res.status(400).json({
				error: "invalid_profile",
				error_description: "Federation profile is missing sub claim",
			});
		}

		let user: Awaited<ReturnType<typeof userRepository.authenticateByToken>>;
		try {
			user = await userRepository.authenticateByToken(`${provider.name}:${profile.sub}`);
		} catch (err) {
			log.warn({ err }, "user repository lookup failed");
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "User directory temporarily unavailable",
			});
		}
		if (!user) {
			return res.status(401).json({
				error: "unknown_user",
				error_description: "No local account linked to this federated identity",
			});
		}

		// Build claims. The local record is authoritative; the provider's mapped
		// claims may fill a promotable field it left absent, and are otherwise
		// recorded under `claims.federated[<provider>]` rather than merged into
		// the envelope this deployment authorizes on (#279).
		const claims = mergeFederatedClaims({
			localClaims: extractUserClaims(user),
			providerName: provider.name,
			mappedClaims: supportsClaimMapping(provider) ? provider.mapClaims(profile) : undefined,
		});

		const sid = randomUUID();
		// Rebind: from this point onward, every log call carries `provider` AND `sid`.
		log = log.child({ sid });
		const authTime = new Date();
		const expiresAt = new Date(Date.now() + sessionTtlMs);

		try {
			await userSessionStore.create({
				sid,
				sub: user.id,
				authTime,
				expiresAt,
				claims,
			});
		} catch (err) {
			log.warn({ err }, "userSession create failed");
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "Session store unavailable",
			});
		}

		// #296: record the session against its subject so a later credential
		// change can find it. Best-effort and after the session exists — a
		// failure here must not deny a legitimate federated login, and the
		// cost is that this one session is missed by `revokeAllForSubject`.
		//
		// Written HERE, at the earliest point the session exists, rather than
		// after the last rollback point, because the two failure modes are not
		// symmetric: a missing entry is a live session a credential change will
		// never find, while an orphan entry costs one redundant cascade that
		// `cascadeLogout` absorbs idempotently. So the write goes early and
		// every rollback path below compensates with `rollbackSubjectIndex`.
		if (subjectSessionIndex) {
			try {
				await subjectSessionIndex.addSid(user.id, sid, expiresAt);
			} catch (err) {
				log.error({ err, sub: user.id }, "subject_session_index_write_failed");
			}
		}

		/**
		 * Undo the subject-index entry written above. Best-effort like every
		 * other rollback step here — the caller's original error is the one
		 * that must reach them.
		 */
		const rollbackSubjectIndex = async (): Promise<void> => {
			if (!subjectSessionIndex) return;
			try {
				await subjectSessionIndex.removeSid(user.id, sid);
			} catch {
				// best-effort — bounded by the index's own TTL
			}
		};

		// A4 §5.2: federation linkage recorded as a sibling-store operation.
		// Per A4 §6.1, this call is NOT atomic with userSessionStore.create above.
		// If addFederation fails, the orphan UserSession is rolled back below; the
		// caller can re-login to re-establish the link. Compound atomic call rejected
		// — would violate Theme B (re-coupling of responsibilities).
		try {
			await sessionFederationIndex.addFederation(sid, provider.name, expiresAt);
		} catch (err) {
			// Rollback the orphan UserSession (created above; addFederation failure
			// means the session has no federation linkage, which would silently
			// bypass federation logout / token-attach paths).
			try {
				await userSessionStore.delete(sid);
			} catch {
				// best-effort — ignore (the original error is the one returned)
			}
			// #296: the session is gone, so its subject-index entry must go too.
			await rollbackSubjectIndex();
			log.warn({ err }, "sessionFederationIndex.addFederation failed");
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "Session store unavailable",
			});
		}

		// Session fixation mitigation: regenerate the session ID before writing auth state.
		// This must happen AFTER userSessionStore.create + sessionFederationIndex.addFederation
		// (so we have a sid to restore) but BEFORE attaching federation tokens or writing
		// session fields.
		//
		// Rollback responsibility:
		//  - If regenerate fails: both stores need to be rolled back in REVERSE order
		//    (sessionFederationIndex first, then userSessionStore).
		//  - If post-regenerate work fails: rollback in REVERSE order
		//    (token → federationIndex → userSession).
		const regenerateErr = await new Promise<Error | null>((resolve) => {
			req.session.regenerate((err: Error | null) => resolve(err));
		});
		if (regenerateErr) {
			// Rollback in REVERSE order of creation:
			//   1. sessionFederationIndex.removeBySid (created last — added in step above)
			//   2. userSessionStore.delete (created first)
			// Per A4 §6.1: cross-store atomicity is not promised; reverse-order rollback
			// is best-effort but minimizes the window where one store has the linkage
			// and the other doesn't.
			try {
				await sessionFederationIndex.removeBySid(sid);
			} catch {
				// best-effort — ignore
			}
			try {
				await userSessionStore.delete(sid);
			} catch {
				// best-effort — ignore
			}
			// #296: the session is gone, so its subject-index entry must go too.
			await rollbackSubjectIndex();
			log.error(
				{ err: regenerateErr },
				"session regeneration failed after userSessionStore.create",
			);
			return res.status(500).json({
				error: "session_create_failed",
				error_description: "Internal error: session could not be regenerated",
			});
		}

		// Post-regenerate: attach federation tokens + restore sid on the new session.
		// Any failure here rolls back in REVERSE order (F-6 pattern).
		// Note: `session` is a stale reference after regenerate — use req.session exclusively.
		let attachedToFederation = false;
		try {
			if (profile.accessToken) {
				// `profile.expiresAt` is `Date | null` (required on FederationProfile).
				// `null` propagates to the store and signals "do not refresh; reuse" —
				// the route layer never invents a fallback expiry.
				await federationTokenStore.attach(sid, provider.name, {
					accessToken: profile.accessToken,
					refreshToken: profile.refreshToken,
					idToken: profile.idToken,
					expiresAt: profile.expiresAt,
				});
				attachedToFederation = true;
			}

			// Restore auth state on the new session (req.session is now the fresh one).
			req.session.sid = sid;
			req.session.isAuthenticated = true;
			req.session.user = user as Record<string, unknown>;

			// Persist the new session with auth state.
			await new Promise<void>((resolve, reject) => {
				req.session.save((err) => (err ? reject(err as Error) : resolve()));
			});

			// Resolve redirect URL via policy (Theme B: redirect concerns separated from IdP protocol)
			const callbackPolicy = federationRedirectPolicyResolver.get(provider.name);
			if (!callbackPolicy) {
				return res.status(500).json({
					error: "internal_error",
					error_description: "redirect policy not registered for provider",
				});
			}
			const redirectResult = callbackPolicy.resolveCallbackRedirect({ redirectTo });
			if (!redirectResult.ok) {
				return res.status(redirectResult.status).json({
					error: redirectResult.error,
					error_description: redirectResult.errorDescription,
				});
			}

			return res.redirect(redirectResult.value);
		} catch (err) {
			// Rollback in REVERSE order of creation:
			//   1. federationTokenStore (attached last, undone first — already here)
			//   2. sessionFederationIndex.removeBySid (NEW — undone before session)
			//   3. userSessionStore.delete (created first, undone last)
			if (attachedToFederation) {
				try {
					await federationTokenStore.delete(sid, provider.name);
				} catch {
					// best-effort — ignore
				}
			}
			try {
				await sessionFederationIndex.removeBySid(sid);
			} catch {
				// best-effort — ignore
			}
			try {
				await userSessionStore.delete(sid);
			} catch {
				// best-effort — ignore
			}
			// #296: the session is gone, so its subject-index entry must go too.
			await rollbackSubjectIndex();
			// Best-effort: destroy the fresh (empty) session so the store doesn't
			// accumulate authenticated-nothing sessions on post-regenerate failures.
			await new Promise<void>((resolve) => {
				req.session.destroy(() => resolve());
			});
			log.error({ err }, "session post-create failed");
			return res.status(500).json({
				error: "session_create_failed",
				error_description: "Internal error: session could not be persisted",
			});
		}
	};

	/**
	 * Bind {@link runCallback} to a parameter source.
	 *
	 * The POST binding is gated on the provider having declared
	 * `responseMode: "form_post"`. An IdP that answers in the query string has
	 * no reason to POST here, so every federation that predates #479 keeps
	 * exactly the GET surface it had and a stray POST is refused rather than
	 * parsed as a callback.
	 */
	const callbackHandler =
		(source: "query" | "body") =>
		async (req: Request, res: Response): Promise<unknown> => {
			const provider = federationProviders.get(String(req.params.name));
			if (!provider) {
				return res
					.status(404)
					.json(
						errorEnvelope(
							"not_found",
							`Federation provider not registered: ${String(req.params.name)}`,
						),
					);
			}

			if (source === "body" && resolveFederationResponseMode(provider) !== "form_post") {
				return res
					.status(405)
					.set("Allow", "GET")
					.json({
						error: "method_not_allowed",
						error_description: `Federation "${provider.name}" returns its authorization response in the query string; the POST callback is accepted only for a form_post federation`,
					});
			}

			return runCallback(
				provider,
				readCallbackParams(source === "body" ? req.body : req.query),
				req,
				res,
			);
		};

	router
		.use(express.json())
		.use(express.urlencoded({ extended: false }))

		// ------------------------------------------------------------------
		// GET /oauth/federation/:name  — start the OAuth 2 redirect leg
		// ------------------------------------------------------------------
		.get("/oauth/federation/:name", async (req: Request, res: Response) => {
			const provider = federationProviders.get(String(req.params.name));
			if (!provider) {
				return res
					.status(404)
					.json(
						errorEnvelope(
							"not_found",
							`Federation provider not registered: ${String(req.params.name)}`,
						),
					);
			}

			const { redirect_to } = req.query;

			let redirectTo: string | undefined;
			if (redirect_to != null) {
				if (typeof redirect_to !== "string") {
					return res.status(400).json({
						error: "invalid_redirect",
						error_description: "redirect_to must be a string",
					});
				}
				const policy = federationRedirectPolicyResolver.get(provider.name);
				if (!policy) {
					// Pairing invariant fires at boot; this branch is defence-in-depth
					// against a hypothetical bug bypassing the invariant at runtime.
					return res.status(500).json({
						error: "internal_error",
						error_description: "redirect policy not registered for provider",
					});
				}
				const validation = policy.validateRedirect(redirect_to);
				if (!validation.ok) {
					return res.status(validation.status).json({
						error: validation.error,
						error_description: validation.errorDescription,
					});
				}
				redirectTo = redirect_to;
			}

			// #479: how this IdP will deliver the authorization response. Absent
			// (every federation written before Sign in with Apple) means "query",
			// so nothing below changes for them.
			const responseMode = resolveFederationResponseMode(provider);

			// Generate CSRF state, PKCE code verifier, and OIDC nonce.
			// PB-4: nonce is generated for every provider; OIDC adapters forward it to the IdP
			// (then verify via openid-client `expectedNonce`). OAuth-only adapters ignore it.
			const state = randomBytes(16).toString("base64url");
			const codeVerifier = generateCodeVerifier();
			const nonce = randomBytes(16).toString("base64url");

			// providerCallbackUrls is the authoritative map of per-provider callback URLs,
			// populated by module wiring from config.federations.<name>.callbackURL.
			//
			// Read before the ephemeral state is persisted: a form_post start
			// scopes its transaction cookie to this URL's path, and there is
			// nothing to be gained by persisting state for a provider whose
			// callback URL is missing.
			const callbackUrl = providerCallbackUrls.get(provider.name);
			if (!callbackUrl) {
				return res.status(500).json({
					error: "misconfiguration",
					error_description: `No callback URL registered for provider "${provider.name}"`,
				});
			}

			const envelope = {
				name: provider.name,
				state,
				codeVerifier,
				nonce,
				redirectTo,
			};

			// #494: a form_post callback arrives as a cross-site POST from the
			// IdP's origin, and a SameSite=Lax cookie is not sent on one. The
			// ephemeral state therefore travels as a transaction of its own — an
			// opaque id in a short-lived, path-scoped, SameSite=None cookie, and
			// the envelope in a store record keyed by it.
			//
			// The application session cookie is not touched, by this branch or
			// any other. This route is unauthenticated and a SameSite=Lax cookie
			// IS sent on a top-level GET, so anything the start leg changed about
			// that cookie would be changeable by any third party who could make a
			// browser follow a link here — permanently, since express-session
			// serialises `req.session.cookie` into the store and rebuilds it from
			// there on every later request.
			if (responseMode === "form_post") {
				const transactions = transactionStore(req);
				const cookiePath = transactionCookiePath(provider);
				if (!transactions || cookiePath === undefined) {
					logger.error(
						{ provider: provider.name, callbackUrl },
						"federation declares response_mode=form_post but no express-session store is reachable on the request, or its callback URL has no parsable path; the cross-site callback would arrive with nothing to check state against",
					);
					return res.status(500).json({
						error: "misconfiguration",
						error_description: `Federation "${provider.name}" cannot start: no session store is mounted to hold its transaction`,
					});
				}

				const transactionId = mintFederationTransactionId();
				// Persist the transaction BEFORE redirecting to the IdP, for the
				// same reason the query branch saves the session here: an async
				// store that loses the record before the user reaches the callback
				// breaks CSRF + PKCE + nonce binding, and failing closed on a store
				// outage is cheaper than a stranded callback.
				try {
					await transactions.set(transactionId, envelope, federationTransactionTtlMs);
				} catch (err) {
					logger.warn({ err, provider: provider.name }, "federation transaction save failed");
					return res.status(500).json({
						error: "server_error",
						error_description: "Session store unavailable",
					});
				}

				res.cookie(transactionCookieName, transactionId, {
					...transactionCookieAttributes(cookiePath),
					// Expires with the record it addresses, so an abandoned flow
					// leaves neither behind.
					maxAge: federationTransactionTtlMs,
				});
			} else {
				// Persist ephemeral federation state in the session
				req.session.federation = envelope;

				// Persist the federation envelope BEFORE redirecting to the IdP. Without an explicit
				// save, async session stores (Redis, etc.) can lose the state/codeVerifier/nonce
				// before the user reaches the callback, breaking CSRF + PKCE + nonce binding —
				// fail-closed on store outages here is cheaper than a stranded callback.
				const startSaveErr = await new Promise<unknown>((resolve) => {
					req.session.save((err) => resolve(err ?? null));
				});
				if (startSaveErr) {
					logger.warn(
						{ err: startSaveErr, provider: provider.name },
						"federation start session save failed",
					);
					return res.status(500).json({
						error: "server_error",
						error_description: "Session store unavailable",
					});
				}
			}

			const authUrl = provider.buildAuthorizationUrl({
				redirectUri: callbackUrl,
				state,
				codeVerifier,
				nonce,
			});

			// #479: the route writes `response_mode`, not the adapter — one place
			// for the parameter, and it stays paired with the POST callback and the
			// cookie relaxation above, which are the route's to decide. Nothing is
			// appended for the default mode, so a query-mode federation's
			// authorization URL is byte-for-byte what its adapter returned.
			if (responseMode !== "query") {
				authUrl.searchParams.set("response_mode", responseMode);
			}

			return res.redirect(authUrl.toString());
		})

		// ------------------------------------------------------------------
		// GET  /oauth/federation/:name/callback  — query-mode callback
		// POST /oauth/federation/:name/callback  — form_post-mode callback (#479)
		//
		// One handler, two parameter sources. The POST route is mounted
		// unconditionally and refuses (405) any federation that did not declare
		// `responseMode: "form_post"`, so the decision stays per federation and
		// visible in one place rather than spread across route registration.
		// ------------------------------------------------------------------
		.get("/oauth/federation/:name/callback", callbackHandler("query"))
		.post("/oauth/federation/:name/callback", callbackHandler("body"));

	return router;
};
