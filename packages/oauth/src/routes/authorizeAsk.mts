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
 * What the request asks of the session — `prompt`, `max_age`, `acr_values` —
 * and the trips that answer it: the login trip and the step-up trip, each
 * recorded as a re-authentication ask bound to this request (`./reauthAsk.mts`).
 */

import {
	type Admission,
	LOGIN_RETURN_PARAMETER,
	loggableError,
	readSpaceDelimitedParameter,
	type UserSession,
} from "@o3co/auth-provider-core";
import { loginRedirect, redirectError } from "./authorizeAnswers.mjs";
import { type AuthorizeContext, authorizeRequestUrl } from "./authorizeContext.mjs";
import { REAUTH_ASK_PARAM, type ReauthAskRecord, type ReauthAskStore } from "./reauthAsk.mjs";

/** The `prompt` values this server honours. */
export type PromptDirective = {
	readonly silent: boolean;
	readonly login: boolean;
	readonly consent: boolean;
};

const NO_PROMPT: PromptDirective = { silent: false, login: false, consent: false };

/**
 * OIDC Core §3.1.2.1 `prompt`. `none` answers `login_required` instead of a
 * login page, which a hidden iframe doing silent renewal cannot act on.
 * `consent` forces the consent page for a client that is not first-party (a
 * no-op for first-party). `login` goes through the re-authentication ask
 * (`./reauthAsk.mts`), which keeps it from looping. Anything else
 * (`select_account`) is refused with `invalid_request`, not ignored: ignoring
 * it would return a token the RP believes honoured it.
 *
 * Returns the directive, or `null` when it has already answered.
 */
export const resolvePrompt = (ctx: AuthorizeContext): PromptDirective | null => {
	const raw = ctx.params.prompt;
	if (raw === undefined) return NO_PROMPT;
	if (typeof raw !== "string") {
		redirectError(ctx, "invalid_request", "prompt must be a single string value");
		return null;
	}
	// §3.1.2.1: a space-delimited list read strictly (a tab is not a
	// delimiter); `none` may not be combined with any other value.
	const values = readSpaceDelimitedParameter(raw);
	if (values === null) {
		redirectError(ctx, "invalid_request", "prompt is not a space-delimited list of values");
		return null;
	}
	if (values.length === 0) return NO_PROMPT;
	if (values.includes("none") && values.length > 1) {
		redirectError(ctx, "invalid_request", "prompt=none cannot be combined with other values");
		return null;
	}
	// `login`: see `evaluateReauthentication`; `consent`: see `checkConsent`.
	const unsupported = values.filter((v) => v !== "none" && v !== "login" && v !== "consent");
	if (unsupported.length > 0) {
		redirectError(
			ctx,
			"invalid_request",
			`prompt values not supported: ${unsupported.join(" ")}; this authorization server ` +
				"has no account picker",
		);
		return null;
	}
	return {
		silent: values.includes("none"),
		login: values.includes("login"),
		consent: values.includes("consent"),
	};
};

/**
 * `max_age` (OIDC Core §3.1.2.1): a non-negative integer, or a refusal.
 * Absent or empty means no constraint (RFC 6749 §3.1).
 */
export const parseMaxAge = (
	ctx: AuthorizeContext,
): { readonly value: number | undefined } | null => {
	const raw = ctx.params.max_age;
	if (raw === undefined || raw === "") return { value: undefined };
	if (typeof raw !== "string" || !/^[0-9]+$/.test(raw)) {
		redirectError(ctx, "invalid_request", "max_age must be a non-negative integer");
		return null;
	}
	return { value: Number(raw) };
};

/**
 * `acr_values` (OIDC Core §3.1.2.1), read strictly: a malformed list is the
 * request's fault, not an acr this deployment lacks. Whether the values are
 * met is admission's decision (`asks.acrValues`).
 */
export const parseAcrValues = (ctx: AuthorizeContext): readonly string[] | null => {
	const raw = ctx.params.acr_values;
	if (raw === undefined) return [];
	const requested = typeof raw === "string" ? readSpaceDelimitedParameter(raw) : [];
	if (requested === null) {
		redirectError(ctx, "invalid_request", "acr_values is not a space-delimited list of values");
		return null;
	}
	return requested;
};

/**
 * The parameter this endpoint adds to a page it sends the browser to, naming
 * the request to come back to: core's `LOGIN_RETURN_PARAMETER`, which the
 * login page and a requirement's step-up page both read. The login page's own
 * URL may not carry it (core's `LoginEntry` contract).
 */
export const REDIRECT_TO_PARAM = LOGIN_RETURN_PARAMETER;

/**
 * The authorize request an ask is minted for and returned to: this request
 * as a GET URL (`authorizeRequestUrl` — a POST's form body written as the
 * query) without the ask parameter, so both sides agree by construction —
 * the POST that sends the browser away and the GET it comes back as.
 */
const askRequestOf = (ctx: AuthorizeContext): string => {
	const url = authorizeRequestUrl(ctx.issuerOrigin, ctx.req);
	url.searchParams.delete(REAUTH_ASK_PARAM);
	return url.toString();
};

/**
 * The presented ask, consumed so a replayed URL asks again rather than
 * minting twice: `null` when absent, unknown, bound to another request or
 * expired; `undefined` after an outage has been answered. Read only when a
 * decision needs it.
 */
export const presentedAsk = async (
	ctx: AuthorizeContext,
	askStore: ReauthAskStore | undefined,
): Promise<ReauthAskRecord | null | undefined> => {
	const presented = ctx.params[REAUTH_ASK_PARAM];
	if (typeof presented !== "string" || presented.length === 0 || askStore === undefined) {
		return null;
	}
	try {
		return await askStore.consume(presented, askRequestOf(ctx));
	} catch (err) {
		// The same rule the session read applies: an outage is not a decision
		// either way.
		ctx.opts.logger.error({ err: loggableError(err) }, "authorize_reauth_ask_store_unavailable");
		redirectError(ctx, "temporarily_unavailable", "session store unavailable");
		return undefined;
	}
};

/** Writes an ask, or answers the outage and returns `null`. */
const recordAsk = async (
	ctx: AuthorizeContext,
	askStore: ReauthAskStore,
	record: ReauthAskRecord,
): Promise<string | null> => {
	try {
		return await askStore.ask(record);
	} catch (err) {
		ctx.opts.logger.error({ err: loggableError(err) }, "authorize_reauth_ask_store_unavailable");
		redirectError(ctx, "temporarily_unavailable", "session store unavailable");
		return null;
	}
};

/** The request to come back to, carrying the ask `askId` names. */
const returnWithAsk = (askRequest: string, askId: string): string => {
	const back = new URL(askRequest);
	back.searchParams.set(REAUTH_ASK_PARAM, askId);
	return back.toString();
};

type ReauthOutcome = "proceed" | "login" | "answered";

/**
 * Whether the session's authentication is fresh enough. `prompt=login`, or a
 * `max_age` older than the session's `auth_time`, sends the browser to log in
 * with the ask recorded (`login_required` under `prompt=none`). When the
 * presented ask records a login trip, a session authenticated after the ask
 * satisfies both; one that was not is refused with `login_required` rather
 * than looped. Decided before admission's verdict is acted on.
 */
export const evaluateReauthentication = (
	ctx: AuthorizeContext,
	prompt: PromptDirective,
	maxAge: number | undefined,
	session: UserSession | null,
	askStore: ReauthAskStore | undefined,
	ask: ReauthAskRecord | null,
): ReauthOutcome => {
	if (!prompt.login && maxAge === undefined) return "proceed";
	if (session === null) {
		// No UserSessionStore in this composition: there is no `auth_time` to
		// measure against, and pretending would be the silent acceptance the
		// parameters exist to prevent.
		redirectError(
			ctx,
			"invalid_request",
			"max_age and prompt=login need a user session store, which this deployment does not wire",
		);
		return "answered";
	}
	if (askStore === undefined) {
		// The ask is a record in the session store, and there is none to write
		// it to. A composition error, not a per-request condition — and the
		// alternative is asking for a re-authentication this endpoint could
		// never recognise on the way back.
		redirectError(
			ctx,
			"invalid_request",
			"max_age and prompt=login need a session store, which this deployment does not wire",
		);
		return "answered";
	}
	if (ask !== null && ask.loginAskedAt !== undefined) {
		// Strictly after the ask, to the millisecond: an authentication made
		// before it — even earlier in the same second — is not the one it asked for.
		if (session.authTime.getTime() > ask.loginAskedAt) return "proceed";
		redirectError(
			ctx,
			"login_required",
			"re-authentication was requested but the session was not re-established",
		);
		return "answered";
	}
	// An id that names no ask, names one for another request, or has expired,
	// is simply not an ask — and one that records a step-up trip alone asked
	// for no login: evaluate the request on its merits, which asks again
	// rather than proceeding.
	const nowSeconds = Math.floor(Date.now() / 1000);
	const authTimeSeconds = Math.floor(session.authTime.getTime() / 1000);
	const stale = maxAge !== undefined && nowSeconds - authTimeSeconds > maxAge;
	if (!prompt.login && !stale) return "proceed";
	if (prompt.silent) {
		redirectError(
			ctx,
			"login_required",
			"the session is older than max_age and prompt=none forbids re-authenticating",
		);
		return "answered";
	}
	return "login";
};

/**
 * The login trip. The ask is a store record named by an opaque id on the URL:
 * a caller cannot invent an id that exists, the record survives the session
 * regeneration login performs, and it is bound to this request so it cannot
 * satisfy another's freshness requirement. A step-up trip already asked is
 * carried over, so the session is not sent on it twice.
 */
export const sendToLogin = async (
	ctx: AuthorizeContext,
	askStore: ReauthAskStore,
	ask: ReauthAskRecord | null,
): Promise<void> => {
	const now = Date.now();
	const askRequest = askRequestOf(ctx);
	const askId = await recordAsk(ctx, askStore, {
		request: askRequest,
		// Kept across the trips of one request, which caps a chain of them.
		createdAt: ask?.createdAt ?? now,
		loginAskedAt: now,
		stepUpAskedAt: { ...ask?.stepUpAskedAt },
	});
	if (askId === null) return;
	loginRedirect(ctx.res, ctx.opts.login, returnWithAsk(askRequest, askId));
};

/**
 * An `unmet` admission: `unmet_authentication_requirements` when the
 * requested `acr` is what nothing meets (naming values not configured here
 * rather than accepting them silently), else `login_required`, since only a
 * new login can change what the requirement decides on.
 */
export const refuseUnmet = (
	ctx: AuthorizeContext,
	requirement: string,
	requested: readonly string[],
): void => {
	if (requirement === "acr") {
		// `Object.hasOwn` rather than a bare read: the table may be a plain
		// object a composition handed in, and the value being looked up is one
		// an unauthenticated caller writes.
		const table = ctx.opts.oauth.acrValues;
		const unknown = requested.filter((acr) => !Object.hasOwn(table, acr));
		redirectError(
			ctx,
			"unmet_authentication_requirements",
			unknown.length > 0
				? `acr_values not configured on this authorization server: ${unknown.join(" ")}`
				: `the session's authentication does not satisfy any requested acr: ${requested.join(" ")}`,
		);
		return;
	}
	redirectError(
		ctx,
		"login_required",
		`the session does not meet the ${requirement} requirement; a new login is required`,
	);
};

/**
 * A `step_up` admission: send the browser to the requirement's registered
 * page with `acr_values` (when the request asked for an acr) and
 * `redirect_to` naming this request with the ask recorded. A session that
 * comes back no later than the recorded trip is refused rather than sent
 * again (`unmet_authentication_requirements` or `login_required`); one
 * established after it may make one more. `prompt=none` is
 * `interaction_required`.
 */
export const stepUpTrip = async (
	ctx: AuthorizeContext,
	admission: Extract<Admission, { outcome: "step_up" }>,
	prompt: PromptDirective,
	askStore: ReauthAskStore | undefined,
	ask: ReauthAskRecord | null,
): Promise<void> => {
	const { requirement, page } = admission;
	const trips = ask?.stepUpAskedAt;
	const askedAt =
		trips !== undefined && Object.hasOwn(trips, requirement) ? trips[requirement] : undefined;
	if (askedAt !== undefined && admission.session.authTime.getTime() <= askedAt) {
		if (admission.whenStillUnmet === "unmet") {
			redirectError(
				ctx,
				"unmet_authentication_requirements",
				`the session came back from ${requirement} still not meeting the request`,
			);
		} else {
			redirectError(
				ctx,
				"login_required",
				`the session came back from ${requirement} still not meeting it; a new login is required`,
			);
		}
		return;
	}
	if (prompt.silent) {
		redirectError(
			ctx,
			"interaction_required",
			`prompt=none was requested but the session must step up through ${requirement}`,
		);
		return;
	}
	if (askStore === undefined) {
		// As a login trip is refused without a store to record the ask in: a
		// composition error, not a per-request condition.
		redirectError(
			ctx,
			"invalid_request",
			"a step-up needs a session store, which this deployment does not wire",
		);
		return;
	}
	// The page as registered; this trip's own parameters are set on it below.
	const target = new URL(page.href);
	// Registration holds a page to the issuer's origin (core's
	// `checkStepUpPage`); a resolver built without an issuer does not. The
	// URL this endpoint is about to send a browser to is checked anyway, and
	// one off the origin is a composition fault, never followed.
	if (target.origin !== ctx.issuerOrigin) {
		ctx.opts.logger.error({ requirement }, "authorize_step_up_page_off_origin");
		redirectError(ctx, "server_error", "the step-up page is not on this server's origin");
		return;
	}
	if (admission.acrValues.length > 0) {
		target.searchParams.set("acr_values", admission.acrValues.join(" "));
	}
	const now = Date.now();
	const askRequest = askRequestOf(ctx);
	const askId = await recordAsk(ctx, askStore, {
		request: askRequest,
		// Kept across the trips of one request, as the login trip keeps it.
		createdAt: ask?.createdAt ?? now,
		loginAskedAt: ask?.loginAskedAt,
		stepUpAskedAt: { ...trips, [requirement]: now },
	});
	if (askId === null) return;
	target.searchParams.set(REDIRECT_TO_PARAM, returnWithAsk(askRequest, askId));
	ctx.res.redirect(target.toString());
};
