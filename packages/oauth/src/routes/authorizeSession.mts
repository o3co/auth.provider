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
	authTimeAt,
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
	loginSince,
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
import type { ReauthAskRecord, ReauthAskStore } from "./reauthAsk.mjs";

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
 * Regenerates the cookie session before a login trip, so a login page that
 * forwards signed-in users cannot loop on the refused session's flag. A
 * failure answers `temporarily_unavailable` and abandons the session, so
 * express-session does not write to that store again; `false` then.
 */
const signedOut = async (ctx: AuthorizeContext): Promise<boolean> => {
	const regenerated = await regenerateCookieSession(ctx.req);
	if (!regenerated.failed) return true;
	ctx.opts.logger.error(
		{ store: "cookie_session", step: "regenerate", err: loggableError(regenerated.cause) },
		"authorize_cookie_session_unavailable",
	);
	(ctx.req as { session?: unknown }).session = undefined;
	redirectError(ctx, "temporarily_unavailable", "session store unavailable");
	return false;
};

/**
 * A new login, for `not_live`, `revoked` and `unauthenticated`: a session
 * that is gone or ended, so regenerating the cookie session signs out no
 * one still signed in. Under
 * `prompt=none` the answer is `login_required` (OIDC Core §3.1.2.6).
 * Otherwise the cookie session is regenerated first (`signedOut`), and under
 * `prompt=login` the login ask is recorded, as the login check records it,
 * so the login made now meets the prompt.
 */
const newLogin = async (
	ctx: AuthorizeContext,
	prompt: PromptDirective,
	askStore: ReauthAskStore | undefined,
): Promise<void> => {
	if (prompt.silent) {
		redirectError(
			ctx,
			"login_required",
			"prompt=none was requested but no end-user session is present",
		);
		return;
	}
	if (!(await signedOut(ctx))) return;
	const target = prompt.login
		? await loginReturnWithAsk(ctx.req, ctx.issuerOrigin, askStore, ctx.opts.logger)
		: authorizeRequestUrl(ctx.issuerOrigin, ctx.req).toString();
	loginRedirect(ctx.res, ctx.opts.login, target);
};

/**
 * One login trip, with the ask recorded (and a step-up trip already asked
 * carried). The live session is kept, as the `prompt=login` trip keeps it: a
 * request anyone can send must not sign the user out. A session that comes
 * back from the login trip already asked is refused by `refuse`, never sent
 * round again. `prompt=none` is `login_required`; no session store to record
 * the ask in is a composition error.
 */
const oneLoginTrip = async (
	ctx: AuthorizeContext,
	prompt: PromptDirective,
	askStore: ReauthAskStore | undefined,
	refuse: (loginAskedAt: number) => void,
): Promise<void> => {
	if (prompt.silent) {
		redirectError(
			ctx,
			"login_required",
			"prompt=none was requested but the session must log in again",
		);
		return;
	}
	if (askStore === undefined) {
		// As a step-up is refused without a store to record the ask in: the
		// login trip could not be bounded.
		redirectError(
			ctx,
			"invalid_request",
			"a re-authentication needs a session store, which this deployment does not wire",
		);
		return;
	}
	const ask = await presentedAsk(ctx, askStore);
	if (ask === undefined) return;
	const loginAskedAt = ask?.loginAskedAt;
	if (loginAskedAt !== undefined) {
		refuse(loginAskedAt);
		return;
	}
	// An ask spent by another pass since it was read: no successor carries
	// its instants, and with no ask this is the first trip.
	if ((await sendToLogin(ctx, askStore, ask)) === "spent") {
		await sendToLogin(ctx, askStore, null);
	}
};

/**
 * A `reauthenticate` admission: one login trip (`oneLoginTrip`). A session
 * that comes back from it still `reauthenticate` is refused, whether it
 * logged in since the ask or not: `unmet_authentication_requirements` for
 * `acr` (a new login could not carry what the request asked for),
 * `login_required` for a requirement.
 */
const reauthenticate = (
	ctx: AuthorizeContext,
	admission: Extract<Admission, { outcome: "reauthenticate" }>,
	prompt: PromptDirective,
	requested: readonly string[],
	askStore: ReauthAskStore | undefined,
): Promise<void> =>
	oneLoginTrip(ctx, prompt, askStore, (loginAskedAt) => {
		// The trip already asked is the one this request gets. Whether a login
		// was made since only words the refusal.
		const loggedIn =
			admission.session !== null &&
			loginSince(admission.session, loginAskedAt, Date.now()) === true;
		if (admission.requirement === "acr") {
			refuseUnmet(ctx, "acr", requested);
			return;
		}
		redirectError(
			ctx,
			"login_required",
			loggedIn
				? `the session still does not meet the ${admission.requirement} requirement after the login it was sent to`
				: "re-authentication was requested but the session was not re-established",
		);
	});

/**
 * Whether `session`'s `authTime` can be read against this clock (core's
 * `authTimeAt`), as every exchange of a code minted from it reads it. One
 * that cannot is logged as the exchange logs it and sent on one login trip
 * (`oneLoginTrip`), and refused with `login_required` when it comes back
 * still unreadable; `false` then, once answered.
 */
const authTimeReadable = async (
	ctx: AuthorizeContext,
	session: UserSession,
	prompt: PromptDirective,
	askStore: ReauthAskStore | undefined,
): Promise<boolean> => {
	const now = Date.now();
	if (authTimeAt(session.authTime, now) !== undefined) return true;
	ctx.opts.logger.warn(
		{ sid: session.sid, clientId: ctx.clientId, aheadMs: session.authTime.getTime() - now },
		"auth_time_ahead_of_clock",
	);
	await oneLoginTrip(ctx, prompt, askStore, () =>
		redirectError(
			ctx,
			"login_required",
			"the session's authentication time cannot be read; a new login is required",
		),
	);
	return false;
};

/**
 * Acts on the admission, or returns `null` once answered. An outage is
 * `temporarily_unavailable` on the validated redirect URI — never the login
 * page, whose forwarding of signed-in users would loop. A dead or
 * unauthenticated session gets a new login; `reauthenticate` gets one login
 * trip (`reauthenticate`). For the outcomes that carry a
 * session, freshness (`max_age`, `prompt=login`) is decided first, so
 * `prompt=none` with a stale `max_age` is `login_required` whatever the
 * verdict; then `unmet` is refused, `step_up` is a trip, and `admitted`
 * proceeds with the `acr` the session met, once its `authTime` can be read
 * against the clock (`authTimeReadable`).
 */
export const decideOnAdmission = async (
	ctx: AuthorizeContext,
	admission: Admission,
	prompt: PromptDirective,
	maxAge: number | undefined,
	requested: readonly string[],
	askStore: ReauthAskStore | undefined,
): Promise<Decided | null> => {
	switch (admission.outcome) {
		case "unavailable":
			redirectError(ctx, "temporarily_unavailable", describeAdmissionOutage(admission.store));
			return null;
		case "not_live":
		case "revoked":
		// Never reached: a cookie whose flag is not exactly `true` was sent to
		// log in, or answered `login_required`, before admission. Listed so the
		// switch stays exhaustive over core's `Admission`.
		case "unauthenticated":
			await newLogin(ctx, prompt, askStore);
			return null;
		case "reauthenticate":
			await reauthenticate(ctx, admission, prompt, requested, askStore);
			return null;
		case "admitted":
		case "step_up":
		case "unmet": {
			// The ask is read only when a decision below needs it.
			const needsAsk = prompt.login || maxAge !== undefined || admission.outcome === "step_up";
			const ask = needsAsk ? await presentedAsk(ctx, askStore) : null;
			if (ask === undefined) return null;
			const decided = await decideWithAsk(ctx, admission, prompt, maxAge, requested, askStore, ask);
			if (decided !== "spent") return decided;
			// An ask spent by another pass since it was read: judged again with
			// none, so no successor carries its instants. With no ask, no trip
			// finds one spent.
			const again = await decideWithAsk(ctx, admission, prompt, maxAge, requested, askStore, null);
			return again === "spent" ? null : again;
		}
	}
};

/** What `decideOnAdmission` hands on for a session it lets through. */
interface Decided {
	readonly session: UserSession | null;
	readonly acr: string | undefined;
	/** What the code records of how the session had authenticated: the admission's. */
	readonly codeFields: Extract<Admission, { readonly outcome: "admitted" }>["codeFields"];
	/** The session is fresh because of the login the presented ask asked for. */
	readonly freshByAsk: boolean;
}

/**
 * Freshness, then the verdict, for an admission that carries a session,
 * judged with `ask`: what to proceed with, `null` once answered, or `spent`
 * when a trip found `ask` spent by another pass (nothing answered).
 */
const decideWithAsk = async (
	ctx: AuthorizeContext,
	admission: Extract<Admission, { outcome: "admitted" | "step_up" | "unmet" }>,
	prompt: PromptDirective,
	maxAge: number | undefined,
	requested: readonly string[],
	askStore: ReauthAskStore | undefined,
	ask: ReauthAskRecord | null,
): Promise<Decided | null | "spent"> => {
	const reauth = evaluateReauthentication(ctx, prompt, maxAge, admission.session, askStore, ask);
	if (reauth === "answered") return null;
	if (reauth === "login") {
		// `evaluateReauthentication` refused already when there is no store.
		return (await sendToLogin(ctx, askStore as ReauthAskStore, ask)) === "spent" ? "spent" : null;
	}
	if (admission.outcome === "unmet") {
		refuseUnmet(ctx, admission.requirement, requested);
		return null;
	}
	if (admission.outcome === "step_up") {
		return (await stepUpTrip(ctx, admission, prompt, askStore, ask)) === "spent" ? "spent" : null;
	}
	if (
		admission.session !== null &&
		!(await authTimeReadable(ctx, admission.session, prompt, askStore))
	) {
		return null;
	}
	return {
		session: admission.session,
		acr: admission.acr,
		codeFields: admission.codeFields,
		freshByAsk: reauth === "fresh_by_ask",
	};
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
