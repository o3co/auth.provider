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
 * The start leg, `GET /oauth/federation/:name`: the `redirect_to`, a
 * freshness hint (`prompt`, `max_age`) and a link start checked — a login
 * started from a signed-in browser asks the upstream for a new login — then the
 * state, PKCE verifier and nonce minted and kept —
 * in the session, or a `form_post` federation's transaction and its cookie —
 * before the browser is sent to the IdP. The browser is sent to the IdP only
 * after they are kept.
 */

import { randomBytes } from "node:crypto";
import {
	errorEnvelope,
	type FederationAsk,
	readSpaceDelimitedParameter,
	resolveFederationResponseMode,
	sanitizeErrorText,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { generateCodeVerifier } from "../federations/pkce.mjs";
import { type LinkIntent, mintFederationTransactionId } from "../federations/transaction.mjs";
import { abandonCookieSession, SESSION_STORE_UNAVAILABLE } from "../internal/cookieSession.mjs";
import { refusalEnvelope } from "../internal/refusalEnvelope.mjs";
import type { FederationRouterContext } from "./FederationContext.mjs";
import { checkLinkStart } from "./FederationLinkStart.mjs";
import { logMisconfigured, logStoreUnavailable } from "./FederationLog.mjs";
import { answerNoRedirectPolicy } from "./FederationRedirectAnswer.mjs";

/**
 * The freshness the login asks the upstream for, from the start's query: a
 * `prompt` space list in which only `login` counts, and a `max_age` of
 * non-negative whole seconds. Empty reads as omitted (RFC 6749 §3.1).
 * `undefined` when it asks nothing, `null` when malformed. A hint only: it can
 * make the upstream stricter, and whether a session meets an ask is judged
 * from what the upstream reports, never from this.
 */
function readFreshnessHint(query: Request["query"]): FederationAsk | undefined | null {
	const { prompt, max_age: maxAge } = query;
	if (prompt !== undefined && typeof prompt !== "string") return null;
	if (maxAge !== undefined && typeof maxAge !== "string") return null;
	const prompts = prompt ? readSpaceDelimitedParameter(prompt) : [];
	if (prompts === null) return null;
	let maxAgeSeconds: number | undefined;
	if (maxAge) {
		if (!/^[0-9]+$/.test(maxAge)) return null;
		maxAgeSeconds = Number(maxAge);
		if (!Number.isSafeInteger(maxAgeSeconds)) return null;
	}
	const login = prompts.includes("login");
	if (!login && maxAgeSeconds === undefined) return undefined;
	return {
		...(login ? { login: true } : {}),
		...(maxAgeSeconds === undefined ? {} : { maxAgeSeconds }),
	};
}

/** The start route's handler, over the router's context. */
export const createStartHandler =
	(ctx: FederationRouterContext) =>
	async (req: Request, res: Response): Promise<unknown> => {
		const {
			federationProviders,
			federationRedirectPolicyResolver,
			providerCallbackUrls,
			federationTransactionTtlMs,
			logger,
			transactionCookieName,
			transactionStore,
			transactionCookiePath,
			transactionCookieAttributes,
		} = ctx;
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
				// Boot registers a provider and its policy together, from the
				// entry's type; this branch is defence-in-depth against a
				// hypothetical bug that registers one without the other.
				return answerNoRedirectPolicy(res, logger, { provider: provider.name });
			}
			const validation = policy.validateRedirect(redirect_to);
			if (!validation.ok) {
				return res
					.status(validation.status)
					.json(refusalEnvelope(validation, logger, { provider: provider.name }));
			}
			redirectTo = redirect_to;
		}

		const hint = readFreshnessHint(req.query);
		if (hint === null) {
			return res
				.status(400)
				.json(
					errorEnvelope(
						"invalid_request",
						"prompt must be a space-delimited list, and max_age a non-negative integer",
					),
				);
		}

		// `link=1` asks to link this federation's identity to the signed-in
		// account. Explicit because a session cookie plus a stray identity is
		// the login-CSRF shape: signing in with another provider never links
		// by itself. Refused here, before any redirect, when it cannot succeed.
		const wantsLink = req.query.link === "1" || req.query.link === "true";
		let link: LinkIntent | undefined;
		if (wantsLink) {
			const intent = await checkLinkStart(ctx, provider, req, res);
			if (intent === null) return;
			link = intent;
		}

		// A login started while this browser already holds an application
		// session is a re-authentication — nothing else sends a signed-in user
		// to sign in again — so the upstream is asked for a new login rather
		// than answering from its own single sign-on. A link is not a login.
		const reauthenticating =
			link === undefined &&
			(req.session as { isAuthenticated?: unknown } | undefined)?.isAuthenticated === true;
		const ask: FederationAsk | undefined = reauthenticating ? { ...hint, login: true } : hint;

		const responseMode = resolveFederationResponseMode(provider);

		// CSRF state, PKCE verifier and OIDC nonce. The nonce is generated for
		// every provider; OAuth-only adapters ignore it.
		const state = randomBytes(16).toString("base64url");
		const codeVerifier = generateCodeVerifier();
		const nonce = randomBytes(16).toString("base64url");

		// The authoritative callback URL map, from core's federationSettings.
		// Read before any state is persisted: a form_post start scopes its
		// cookie to this path.
		const callbackUrl = providerCallbackUrls.get(provider.name);
		if (!callbackUrl) {
			logMisconfigured(logger, "no_callback_url", { provider: provider.name });
			return res.status(500).json({
				error: "misconfiguration",
				error_description: sanitizeErrorText(
					`No callback URL registered for provider '${provider.name}'`,
				),
			});
		}

		const envelope = {
			name: provider.name,
			state,
			codeVerifier,
			nonce,
			redirectTo,
			...(link === undefined ? {} : { link }),
		};

		// A form_post callback is a cross-site POST, which does not carry a
		// SameSite=Lax cookie, so its state travels as a transaction: an opaque
		// id in a short-lived, path-scoped SameSite=None cookie, with the
		// envelope in a store record. The application session cookie is never
		// touched here: this route is unauthenticated and reachable through any
		// third-party link, and express-session persists `req.session.cookie`.
		if (responseMode === "form_post") {
			const transactions = transactionStore(req);
			const cookiePath = transactionCookiePath(provider);
			if (!transactions || cookiePath === undefined) {
				// The composition's fault, not an outage: a form_post federation
				// whose request carries no express-session store, or whose
				// callback URL has no path to scope the cookie to, cannot check
				// state on the cross-site callback it would be sent.
				logMisconfigured(logger, transactions ? "no_callback_path" : "no_session_store", {
					provider: provider.name,
					callbackUrl,
				});
				return res.status(500).json({
					error: "misconfiguration",
					error_description: sanitizeErrorText(
						`Federation '${provider.name}' cannot start: no session store is mounted to hold its transaction`,
					),
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
				logStoreUnavailable(
					logger,
					"federation_start_store_unavailable",
					"federation_transaction",
					"set",
					err,
					{ provider: provider.name },
				);
				abandonCookieSession(req);
				return res.status(503).json(SESSION_STORE_UNAVAILABLE);
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
				logStoreUnavailable(
					logger,
					"federation_start_store_unavailable",
					"cookie_session",
					"save",
					startSaveErr,
					{ provider: provider.name },
				);
				abandonCookieSession(req);
				return res.status(503).json(SESSION_STORE_UNAVAILABLE);
			}
		}

		const authUrl = provider.buildAuthorizationUrl({
			redirectUri: callbackUrl,
			state,
			codeVerifier,
			nonce,
			...(ask === undefined ? {} : { ask }),
		});

		// The route, not the adapter, writes `response_mode`, keeping it paired
		// with the POST callback and the cookie decisions. Nothing is appended
		// for query mode, so that URL is exactly what the adapter returned.
		if (responseMode !== "query") {
			authUrl.searchParams.set("response_mode", responseMode);
		}

		return res.redirect(authUrl.toString());
	};
