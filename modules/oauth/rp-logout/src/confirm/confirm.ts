import { type Client, clients } from "@mod/clients";
import { type FormTokens, formTokens } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, jsonAnswer, type Loads, noStore } from "@mod/http";
import { endpointOrigin, issuer } from "@mod/issuer";
import type { BuildContext, Log } from "@mod/kernel";
import { type Keys, keys } from "@mod/keys";
import { sessions } from "@mod/session";
import { type Closing, closingFrom, closingTakes } from "../closing/closing.ts";
import type { LogoutReturn, UpstreamEnd } from "../contract.ts";
import { frontChannelPage, loggedOutPage, returnUrl } from "../page/page.ts";
import type { Settings } from "../section.ts";
import { type Carried, carriedClaims, carriedParam, carriedWith } from "./carried/carried.ts";

export { type CarriedRequest, carriedParam } from "./carried/carried.ts";

/** Where a person confirms a logout that `ending` could not close without asking. */
export const confirmPath = "/oauth/logout/confirm";

/** The kind of the token that binds a confirmation to the session it was shown for. */
const confirmationType = "logout-confirm+jwt";

export interface ConfirmParts {
	readonly sessions: { handleOf(request: HttpRequest): Promise<string | undefined> };
	/** The client records a carried return is held to, as they are when it is used. */
	readonly clients: { find(id: string): Promise<Client | undefined> };
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
	/** How long, in seconds, a confirmation and a carried request may be answered (the package's `confirm-within`). */
	readonly withinSeconds: number;
	readonly now: () => number;
	readonly log: Log;
}

const escaped = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const repeated = jsonAnswer(400, {
	error: "invalid_request",
	error_description: "repeated parameter",
});
/** A check that cannot tell: the package's routes declare it, and a close that cannot be made answers it. */
export const unavailable = jsonAnswer(503, { error: "temporarily_unavailable" });
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
	const carrying = carriedWith(p);
	const { read, current } = carrying;

	/** The confirmation page for `handle`: the person's choice, the form's CSRF token and the binding. */
	const asking = async (
		request: HttpRequest,
		handle: string,
		carried: Carried,
	): Promise<HttpResponse> => {
		// A confirmation carrying a return lasts no longer than the request it came from.
		const fresh = seconds() + p.withinSeconds;
		const exp = carried.back.postLogoutRedirectUri === undefined ? fresh : (carried.exp ?? fresh);
		const confirmation = await p.keys.sign(
			{ iss: p.issuer, aud: p.confirmUrl, sid: handle, exp, ...carriedClaims(carried) },
			confirmationType,
		);
		const csrf = p.forms.issue(request);
		const html = `<!doctype html><html><head><meta charset="utf-8"><title>Log out?</title></head><body><h1>Log out?</h1><p>Do you want to log out of ${escaped(host)}? You will be logged out of this provider, and of the applications that use it.</p><form method="post" action="${confirmPath}"><input type="hidden" name="${escaped(csrf.field)}" value="${escaped(csrf.token)}"><input type="hidden" name="confirmation" value="${escaped(confirmation)}"><button type="submit">Log out</button></form></body></html>`;
		return page(html, { cookies: csrf.cookies, loads: { forms: "self" } });
	};

	/** The session the confirmation was shown for and what it carries, where it is valid. */
	const confirmed = (confirmation: string | undefined) =>
		carrying.boundTo(confirmation, confirmationType, p.confirmUrl);

	const show = async (request: HttpRequest): Promise<HttpResponse> => {
		// A request not carried by a token of this module's, or one past its time, is none: no return.
		const found: Carried = (await read(request.query.single(carriedParam))) ?? { back: {} };
		const handle = await p.sessions.handleOf(request);
		if (handle === undefined) return notSignedIn(await current(found));
		return asking(request, handle, found);
	};

	const take = async (request: HttpRequest): Promise<HttpResponse> => {
		if (request.fields.repeated().length > 0) return repeated;
		const bound = await confirmed(request.fields.single("confirmation"));
		const handle = await p.sessions.handleOf(request);
		if (handle === undefined) return notSignedIn(bound ? await current(bound) : {});
		// Another session than the one the page was shown for, or no valid binding: asked again, nothing closed.
		if (bound?.sid !== handle) return asking(request, handle, bound ?? { back: {} });
		// Held to the registration now, before the close hands it on to the upstream's end of session too.
		const back = await current(bound);
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

	const { carry, carried } = carrying;
	// A check that cannot tell throws Unavailable on, which the routes' declared answer answers.
	return { carry, carried, current, show, take };
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
		clients: await c.get(clients),
		closing: await closingFrom(c, upstream),
		keys: await c.get(keys),
		forms: await c.get(formTokens),
		issuer: issuerUrl,
		confirmUrl: `${origin}${confirmPath}`,
		logoutUrl: `${origin}${logoutPath}`,
		withinSeconds: c.section["confirm-within"],
		now: c.clock.now,
		log: c.log,
	});
}
