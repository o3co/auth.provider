import { type FormTokens, formTokens } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, jsonAnswer, type Loads, noStore } from "@mod/http";
import { endpointOrigin, issuer } from "@mod/issuer";
import { type BuildContext, isUnavailable, type Log } from "@mod/kernel";
import { type Keys, keys } from "@mod/keys";
import { sessions } from "@mod/session";
import { type Closing, closingFrom, closingTakes } from "../closing/closing.ts";
import type { UpstreamEnd } from "../contract.ts";
import { frontChannelPage, loggedOutPage } from "../page/page.ts";
import type { Settings } from "../section.ts";

/** Where a person confirms a logout a client started without a hint. */
export const confirmPath = "/oauth/logout/confirm";

/** The kind of the token that binds a confirmation to the session it was shown for. */
const confirmationType = "logout-confirm+jwt";
/** How long a confirmation page may be answered. */
const confirmationSeconds = 300;

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
	readonly now: () => number;
	readonly log: Log;
}

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

const notSignedIn = page(
	`<!doctype html><html><head><meta charset="utf-8"><title>Logged out</title></head><body><h1>Logged out</h1><p>You are not signed in.</p></body></html>`,
);

/**
 * The confirmation of a logout a client started without a hint (OpenID Connect RP-Initiated Logout
 * 1.0 §2): `show` asks the person whether to log out of the provider, bound to the session the
 * browser's cookie opens; `take` closes that session once they agree, and asks again where the
 * browser's session is no longer the one the page was shown for.
 */
export function confirmWith(p: ConfirmParts) {
	const { closing } = p;
	const host = new URL(p.issuer).host;

	/** The confirmation page for `handle`: the person's choice, the form's CSRF token and the binding. */
	const asking = async (request: HttpRequest, handle: string): Promise<HttpResponse> => {
		const exp = Math.floor(p.now() / 1000) + confirmationSeconds;
		const confirmation = await p.keys.sign(
			{ iss: p.issuer, aud: p.confirmUrl, sid: handle, exp },
			confirmationType,
		);
		const csrf = p.forms.issue(request);
		const html = `<!doctype html><html><head><meta charset="utf-8"><title>Log out?</title></head><body><h1>Log out?</h1><p>Do you want to log out of ${escaped(host)}? You will be logged out of this provider, and of the applications that use it.</p><form method="post" action="${confirmPath}"><input type="hidden" name="${escaped(csrf.field)}" value="${escaped(csrf.token)}"><input type="hidden" name="confirmation" value="${escaped(confirmation)}"><button type="submit">Log out</button></form></body></html>`;
		return page(html, { cookies: csrf.cookies, loads: { forms: "self" } });
	};

	/** The session the confirmation was shown for, where it is one this deployment made and still current. */
	const boundTo = async (confirmation: string | undefined) => {
		if (!confirmation) return undefined;
		const verified = await p.keys.verify(confirmation, confirmationType);
		if (verified.kind !== "valid") return undefined;
		// keys checks the signature, the type and the key alone; the claims are this module's to check.
		const { iss, aud, sid, exp } = verified.claims;
		if (iss !== p.issuer || aud !== p.confirmUrl) return undefined;
		if (typeof sid !== "string" || sid === "") return undefined;
		if (typeof exp !== "number" || !Number.isFinite(exp)) return undefined;
		return exp > Math.floor(p.now() / 1000) ? sid : undefined;
	};

	const show = async (request: HttpRequest): Promise<HttpResponse> => {
		const handle = await p.sessions.handleOf(request);
		return handle === undefined ? notSignedIn : asking(request, handle);
	};

	const take = async (request: HttpRequest): Promise<HttpResponse> => {
		if (request.fields.repeated().length > 0) return repeated;
		const handle = await p.sessions.handleOf(request);
		if (handle === undefined) return notSignedIn;
		// Another session than the one the page was shown for, or no valid binding: asked again, nothing closed.
		if ((await boundTo(request.fields.single("confirmation"))) !== handle)
			return asking(request, handle);
		const closed = await closing(request, { sid: handle, back: {} });
		if (closed.kind === "unavailable") return unavailable;
		if (closed.kind === "pending")
			return jsonAnswer(503, { error: "temporarily_unavailable" }, { cookies: closed.cookies });
		if (closed.kind === "not-this-logout")
			return page(loggedOutPage({}).html, { cookies: closed.cookies });
		// Always a page: the form's policy would hold a redirect after the post to this origin.
		const frames = await closed.frames();
		const framed = frontChannelPage(frames, {
			issuer: p.issuer,
			session: handle,
			next: closed.upstream,
		});
		if (framed && framed.skipped > 0)
			p.log.warn("rp-logout.frames_skipped", { count: framed.skipped });
		const done = framed ?? loggedOutPage({ next: closed.upstream });
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
	return { show: guarded(show), take: guarded(take) };
}

/** What `confirmFrom` takes from the composition. */
export const confirmTakes = [sessions, keys, formTokens, issuer, ...closingTakes] as const;

/** The routes' handlers, from the composition's contracts. */
export async function confirmFrom(c: BuildContext<Settings>, upstream: UpstreamEnd | undefined) {
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
		now: c.clock.now,
		log: c.log,
	});
}
