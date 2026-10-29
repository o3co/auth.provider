import { type FormTokens, formTokens } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, jsonAnswer, type Loads, noStore } from "@mod/http";
import { endpointOrigin, issuer } from "@mod/issuer";
import { type BuildContext, isUnavailable, type Log } from "@mod/kernel";
import { type Keys, keys } from "@mod/keys";
import { sessions } from "@mod/session";
import { type Closing, closingFrom, closingTakes } from "../closing/closing.ts";
import type { LogoutReturn, UpstreamEnd } from "../contract.ts";
import { frontChannelPage, loggedOutPage, returnUrl } from "../page/page.ts";
import type { Settings } from "../section.ts";

/** Where a person confirms a logout that `ending` could not close without asking. */
export const confirmPath = "/oauth/logout/confirm";
/** The parameter a carried request goes in, to the logout's `GET` and to this page. */
export const carriedParam = "request";

/** The kind of the token that binds a confirmation to the session it was shown for. */
const confirmationType = "logout-confirm+jwt";
/** How long a confirmation page may be answered. */
const confirmationSeconds = 300;
/** The kind of the token a carried request is. */
const carriedType = "logout-request+jwt";
/** How long the browser has to follow a carried request. */
const carriedSeconds = 300;

/**
 * A logout `ending` checked and carries on in the browser's URL: the session the hint names, its
 * client, and the return the client registered with its `state`. It closes nothing by itself.
 */
export interface CarriedRequest {
	readonly sid: string;
	readonly client?: string;
	readonly back: LogoutReturn;
}

export interface ConfirmParts {
	readonly sessions: { handleOf(request: HttpRequest): Promise<string | undefined> };
	/** The close the hinted logout shares. */
	readonly closing: Closing;
	readonly keys: Pick<Keys, "sign" | "verify">;
	readonly forms: FormTokens;
	/** The issuer's URL, which the confirmation names as its issuer. */
	readonly issuer: string;
	/** The confirmation endpoint's URL, which the confirmation names as its audience. */
	readonly confirmUrl: string;
	/** The logout endpoint's URL, which a carried request names as its audience. */
	readonly logoutUrl: string;
	readonly now: () => number;
	readonly log: Log;
}

/** A checked return, as a token's claims carry it: the return and its `state`, each where there is one. */
const backClaims = (back: LogoutReturn) => ({
	...(back.postLogoutRedirectUri === undefined ? {} : { back: back.postLogoutRedirectUri }),
	...(back.state === undefined ? {} : { state: back.state }),
});

const escaped = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const repeated = jsonAnswer(400, {
	error: "invalid_request",
	error_description: "repeated parameter",
});
const unavailable = jsonAnswer(503, { error: "temporarily_unavailable" });
const htmlHeaders = { ...noStore, "content-type": "text/html; charset=utf-8" };

/** A page, its cookies and what it loads. */
const page = (
	html: string,
	extra: { readonly cookies?: readonly string[]; readonly loads?: Loads } = {},
): HttpResponse => ({
	status: 200,
	headers: htmlHeaders,
	body: html,
	cookies: extra.cookies ?? [],
	loads: extra.loads ?? {},
});

/** The page for a browser with no session: nothing to close, moving on to the return where there is one. */
const notSignedIn = (back: LogoutReturn) => {
	const said = loggedOutPage({ next: returnUrl(back), notSignedIn: true });
	return page(said.html, { loads: said.loads });
};

/**
 * The confirmation of a logout `ending` could not close without asking (OpenID Connect RP-Initiated
 * Logout 1.0 §2): `carry` and `carried` sign and check a request `ending` carries on in the browser's
 * URL; `show` asks the person whether to log out of the provider, bound to the session the browser's
 * cookie opens; `take` closes that session, never the one a carried request names, once they agree,
 * moving on to the request's return, and asks again where the browser's session is no longer the one
 * the page was shown for.
 */
export function confirmWith(p: ConfirmParts) {
	const { closing } = p;
	const host = new URL(p.issuer).host;

	const seconds = () => Math.floor(p.now() / 1000);
	/** Claims this module signed, of `type`, for `audience` and not yet expired; none otherwise. */
	const claimsOf = async (token: string | undefined, type: string, audience: string) => {
		if (!token) return undefined;
		const verified = await p.keys.verify(token, type);
		if (verified.kind !== "valid") return undefined;
		// keys checks the signature, the type and the key alone; the claims are this module's to check.
		const { iss, aud, exp } = verified.claims;
		if (iss !== p.issuer || aud !== audience) return undefined;
		if (typeof exp !== "number" || !Number.isFinite(exp) || exp <= seconds()) return undefined;
		return verified.claims;
	};
	/** The return a token carries, read back only as strings; none where it carries none. */
	const backOf = (claims: Readonly<Record<string, unknown>> | undefined): LogoutReturn => {
		const back = typeof claims?.back === "string" ? claims.back : undefined;
		const state = typeof claims?.state === "string" ? claims.state : undefined;
		if (back === undefined) return {};
		return { postLogoutRedirectUri: back, ...(state === undefined ? {} : { state }) };
	};

	/** A request `ending` checked, signed to be carried in the browser's URL. */
	const carry = (request: CarriedRequest): Promise<string> => {
		const at = { iss: p.issuer, aud: p.logoutUrl, exp: seconds() + carriedSeconds };
		const client = request.client === undefined ? {} : { client: request.client };
		return p.keys.sign(
			{ ...at, sid: request.sid, ...client, ...backClaims(request.back) },
			carriedType,
		);
	};
	/** The request a token carries, where this module signed it for the logout and its time holds. */
	const carried = async (token: string | undefined): Promise<CarriedRequest | undefined> => {
		const claims = await claimsOf(token, carriedType, p.logoutUrl);
		const sid = claims?.sid;
		if (typeof sid !== "string" || sid === "") return undefined;
		const client = typeof claims?.client === "string" ? { client: claims.client } : {};
		return { sid, ...client, back: backOf(claims) };
	};

	/** The confirmation page for `handle`: the person's choice, the form's CSRF token and the binding. */
	const asking = async (
		request: HttpRequest,
		handle: string,
		back: LogoutReturn,
	): Promise<HttpResponse> => {
		const exp = seconds() + confirmationSeconds;
		const confirmation = await p.keys.sign(
			{ iss: p.issuer, aud: p.confirmUrl, sid: handle, exp, ...backClaims(back) },
			confirmationType,
		);
		const csrf = p.forms.issue(request);
		const html = `<!doctype html><html><head><meta charset="utf-8"><title>Log out?</title></head><body><h1>Log out?</h1><p>Do you want to log out of ${escaped(host)}? You will be logged out of this provider, and of the applications that use it.</p><form method="post" action="${confirmPath}"><input type="hidden" name="${escaped(csrf.field)}" value="${escaped(csrf.token)}"><input type="hidden" name="confirmation" value="${escaped(confirmation)}"><button type="submit">Log out</button></form></body></html>`;
		return page(html, { cookies: csrf.cookies, loads: { forms: "self" } });
	};

	/** The session the confirmation was shown for and the return it carries, where it is valid. */
	const boundTo = async (confirmation: string | undefined) => {
		const claims = await claimsOf(confirmation, confirmationType, p.confirmUrl);
		const sid = claims?.sid;
		if (typeof sid !== "string" || sid === "") return undefined;
		return { sid, back: backOf(claims) };
	};

	const show = async (request: HttpRequest): Promise<HttpResponse> => {
		// A request not carried by a token of this module's, or one past its time, is none: no return.
		const back = (await carried(request.query.single(carriedParam)))?.back ?? {};
		const handle = await p.sessions.handleOf(request);
		if (handle === undefined) return notSignedIn(back);
		return asking(request, handle, back);
	};

	const take = async (request: HttpRequest): Promise<HttpResponse> => {
		if (request.fields.repeated().length > 0) return repeated;
		const bound = await boundTo(request.fields.single("confirmation"));
		const handle = await p.sessions.handleOf(request);
		if (handle === undefined) return notSignedIn(bound?.back ?? {});
		// Another session than the one the page was shown for, or no valid binding: asked again, nothing closed.
		if (bound?.sid !== handle) return asking(request, handle, bound?.back ?? {});
		const { back } = bound;
		const closed = await closing(request, { sid: handle, back });
		if (closed.kind === "unavailable") return unavailable;
		if (closed.kind === "pending")
			return jsonAnswer(503, { error: "temporarily_unavailable" }, { cookies: closed.cookies });
		if (closed.kind === "not-this-logout")
			return page(loggedOutPage({}).html, { cookies: closed.cookies });
		// Always a page: the form's policy would hold a redirect after the post to this origin.
		const frames = await closed.frames();
		const next = closed.upstream ?? returnUrl(back);
		const framed = frontChannelPage(frames, { issuer: p.issuer, session: handle, next });
		if (framed && framed.skipped > 0)
			p.log.warn("rp-logout.frames_skipped", { count: framed.skipped });
		const done = framed ?? loggedOutPage({ next });
		return page(done.html, { cookies: closed.cookies, loads: done.loads });
	};

	/** Answered here where something cannot tell, so http never sees it: logged by what failed. */
	const guarded =
		(handler: (request: HttpRequest) => Promise<HttpResponse>) =>
		async (request: HttpRequest): Promise<HttpResponse> => {
			try {
				return await handler(request);
			} catch (error) {
				if (!isUnavailable(error)) throw error;
				p.log.warn("rp-logout.unavailable", { what: error.what });
				return unavailable;
			}
		};
	return { carry, carried, show: guarded(show), take: guarded(take) };
}

/** What `confirmFrom` takes from the composition. */
export const confirmTakes = [sessions, keys, formTokens, issuer, ...closingTakes] as const;

/** The routes' handlers, from the composition's contracts; `logoutPath` is the logout's, a carried request's audience. */
export async function confirmFrom(
	c: BuildContext<Settings>,
	upstream: UpstreamEnd | undefined,
	logoutPath: string,
) {
	const named = await c.get(issuer);
	const issuerUrl = named.url;
	// The endpoint's origin, as the metadata names the logout's.
	const origin = endpointOrigin(named);
	return confirmWith({
		sessions: await c.get(sessions),
		closing: await closingFrom(c, upstream),
		keys: await c.get(keys),
		forms: await c.get(formTokens),
		issuer: issuerUrl,
		confirmUrl: `${origin}${confirmPath}`,
		logoutUrl: `${origin}${logoutPath}`,
		now: c.clock.now,
		log: c.log,
	});
}
