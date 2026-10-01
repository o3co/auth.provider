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
 * The end-user: the login check before any lookup, what session admission's
 * verdict is answered with, and the verified-email requirement. An outage is
 * `temporarily_unavailable` on the redirect URI, never the login page.
 */

import {
	type Admission,
	cookieClaim,
	describeAdmissionOutage,
	isEmailVerified,
	loggableError,
	parseScopeTokens,
	type SessionClaim,
	type UserSession,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { auditFailure, loginRedirect, redirectError } from "./authorizeAnswers.mjs";
import {
	evaluateReauthentication,
	loginReturnWithAsk,
	type PromptDirective,
	presentedAsk,
	refuseUnmet,
	sendToLogin,
	stepUpTrip,
} from "./authorizeAsk.mjs";
import {
	type AuthorizeContext,
	type AuthorizeHandlerOptions,
	authorizeParams,
	authorizeRequestUrl,
} from "./authorizeContext.mjs";
import type { ReauthAskStore } from "./reauthAsk.mjs";

/**
 * The login check, before any lookup: an unauthenticated browser is sent to
 * the login page unless the request names `prompt=none`, with the login ask
 * recorded when it names `prompt=login`. Returns the cookie's claim, or
 * `null` once the browser has been sent.
 */
export const checkLogin = async (
	req: Request,
	res: Response,
	opts: Pick<AuthorizeHandlerOptions, "login" | "logger">,
	issuerOrigin: string,
	askStore: ReauthAskStore | undefined,
): Promise<SessionClaim | null> => {
	// `prompt=none` must not get a login page (a hidden iframe cannot act on
	// it); it falls through so `login_required` can be delivered at the
	// validated `redirect_uri`. Any list naming `none` opens this gate —
	// forbidden combinations included, read tolerantly (`parseScopeTokens`)
	// — since such a request still comes from a silent context and its
	// `invalid_request` belongs at the RP's `redirect_uri`. Every other
	// unauthenticated request is answered before any lookup.
	const promptRaw = authorizeParams(req).prompt;
	const prompts = typeof promptRaw === "string" ? parseScopeTokens(promptRaw) : [];
	const wantsSilentAuth = prompts.includes("none");

	// The cookie's flag is checked first, with no store read, so an
	// anonymous request costs no lookup. Whether the session behind it is
	// live is admission's to decide, once, after the client and parameters
	// are validated.
	const claim = cookieClaim(req);
	if (!claim.authenticated && !wantsSilentAuth) {
		// `prompt=login`: the login about to be made is the one asked for.
		// Recorded before the client is looked up, as every unauthenticated
		// request is answered before any lookup; the `/authorize` rate limit
		// and the ask's window bound what an anonymous caller can write.
		const target = prompts.includes("login")
			? await loginReturnWithAsk(req, issuerOrigin, askStore, opts.logger)
			: authorizeRequestUrl(issuerOrigin, req).toString();
		loginRedirect(res, opts.login, target);
		return null;
	}
	return claim;
};

/** Refuses `prompt=none` from a browser with no logged-in session. */
export const checkPromptNoneHasSession = (
	ctx: AuthorizeContext,
	prompt: PromptDirective,
	claim: SessionClaim,
): boolean => {
	if (prompt.silent && !claim.authenticated) {
		// OIDC Core §3.1.2.6. Now that `redirect_uri` is validated this
		// reaches the RP's own listener rather than a login page it cannot
		// use.
		redirectError(
			ctx,
			"login_required",
			"prompt=none was requested but no end-user session is present",
		);
		return false;
	}
	return true;
};

/**
 * Regenerates the cookie session so nothing of the refused session survives.
 * A failure is that store's outage; a session that cannot regenerate at all
 * fails the same way.
 */
const regenerateCookieSession = (
	req: Request,
): Promise<{ readonly failed: false } | { readonly failed: true; readonly cause: unknown }> =>
	new Promise((resolve) => {
		const session = (req as { session?: { regenerate?: unknown } }).session;
		if (typeof session?.regenerate !== "function") {
			resolve({
				failed: true,
				cause: new TypeError("the request's session cannot be regenerated"),
			});
			return;
		}
		(session.regenerate as (callback: (err?: unknown) => void) => void)((err) =>
			resolve(err == null ? { failed: false } : { failed: true, cause: err }),
		);
	});

/**
 * A new login, for `not_live`, `revoked`, `reauthenticate` and
 * `unauthenticated`. Under `prompt=none` the answer is `login_required` (OIDC
 * Core §3.1.2.6). Otherwise the cookie session is regenerated first, so a
 * login page that forwards signed-in users cannot loop on the refused
 * session's flag; if regeneration fails, answer `temporarily_unavailable` and
 * abandon the session so express-session does not write to that store again.
 */
const newLogin = async (ctx: AuthorizeContext, prompt: PromptDirective): Promise<void> => {
	if (prompt.silent) {
		redirectError(
			ctx,
			"login_required",
			"prompt=none was requested but no end-user session is present",
		);
		return;
	}
	const regenerated = await regenerateCookieSession(ctx.req);
	if (regenerated.failed) {
		ctx.opts.logger.error(
			{ store: "cookie_session", step: "regenerate", err: loggableError(regenerated.cause) },
			"authorize_cookie_session_unavailable",
		);
		(ctx.req as { session?: unknown }).session = undefined;
		redirectError(ctx, "temporarily_unavailable", "session store unavailable");
		return;
	}
	loginRedirect(ctx.res, ctx.opts.login, authorizeRequestUrl(ctx.issuerOrigin, ctx.req).toString());
};

/**
 * Acts on the admission, or returns `null` once answered. An outage is
 * `temporarily_unavailable` on the validated redirect URI — never the login
 * page, whose forwarding of signed-in users would loop. A dead or
 * unauthenticated session gets a new login. For the outcomes that carry a
 * session, freshness (`max_age`, `prompt=login`) is decided first, so
 * `prompt=none` with a stale `max_age` is `login_required` whatever the
 * verdict; then `unmet` is refused, `step_up` is a trip, and `admitted`
 * proceeds with the `acr` the session met.
 */
export const decideOnAdmission = async (
	ctx: AuthorizeContext,
	admission: Admission,
	prompt: PromptDirective,
	maxAge: number | undefined,
	requested: readonly string[],
	askStore: ReauthAskStore | undefined,
): Promise<{
	readonly session: UserSession | null;
	readonly acr: string | undefined;
	/** The session is fresh because of the login the presented ask asked for. */
	readonly freshByAsk: boolean;
} | null> => {
	switch (admission.outcome) {
		case "unavailable":
			redirectError(ctx, "temporarily_unavailable", describeAdmissionOutage(admission.store));
			return null;
		case "not_live":
		case "revoked":
		case "reauthenticate":
		// Never reached: a cookie whose flag is not exactly `true` was sent to
		// log in, or answered `login_required`, before admission. Listed so the
		// switch stays exhaustive over core's `Admission`.
		case "unauthenticated":
			await newLogin(ctx, prompt);
			return null;
		case "admitted":
		case "step_up":
		case "unmet": {
			// The ask is read only when a decision below needs it.
			const needsAsk = prompt.login || maxAge !== undefined || admission.outcome === "step_up";
			const ask = needsAsk ? await presentedAsk(ctx, askStore) : null;
			if (ask === undefined) return null;
			const reauth = evaluateReauthentication(
				ctx,
				prompt,
				maxAge,
				admission.session,
				askStore,
				ask,
			);
			if (reauth === "answered") return null;
			if (reauth === "login") {
				// `evaluateReauthentication` refused already when there is no store.
				await sendToLogin(ctx, askStore as ReauthAskStore, ask);
				return null;
			}
			if (admission.outcome === "unmet") {
				refuseUnmet(ctx, admission.requirement, requested);
				return null;
			}
			if (admission.outcome === "step_up") {
				await stepUpTrip(ctx, admission, prompt, askStore, ask);
				return null;
			}
			return {
				session: admission.session,
				acr: admission.acr,
				freshByAsk: reauth === "fresh_by_ask",
			};
		}
	}
};

// Refuse before a code is minted when a verified email is required and the
// Store has published none. Artifacts derived from a code (refresh, token
// exchange) are not re-checked: that would end a live session on a Store
// hiccup. `access_denied` does not suggest the client sent something malformed.
export const checkEmailVerified = async (ctx: AuthorizeContext): Promise<boolean> => {
	if (!(ctx.opts.oauth.requireEmailVerified && !isEmailVerified(ctx.req.session.user))) return true;
	await auditFailure(ctx, { reason: "email_not_verified" });
	redirectError(ctx, "access_denied", "email address is not verified");
	return false;
};
