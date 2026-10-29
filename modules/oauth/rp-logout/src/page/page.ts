import type { Loads } from "@mod/http";
import type { LogoutReturn } from "../contract.ts";

/** A client to tell in a frame, and whether it asked for the session. */
export interface Frame {
	readonly uri: string;
	readonly withSession: boolean;
}

/** The client's return with its `state`, where there is one: where the browser goes once logged out. */
export const returnUrl = (back: LogoutReturn): string | undefined => {
	if (back.postLogoutRedirectUri === undefined) return undefined;
	if (back.state === undefined) return back.postLogoutRedirectUri;
	const url = new URL(back.postLogoutRedirectUri);
	url.searchParams.set("state", back.state);
	return url.href;
};

/** The frames get this long to load before the browser moves on. */
const delayMs = 2000;
const script =
	"const b=document.body;setTimeout(()=>{location.href=b.dataset.target},Number(b.dataset.delay))";
/** A Content-Security-Policy host source holds no IPv6 literal or `_`; a frame there could not load. */
const framable = /^https?:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?$/;
const escaped = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** The front-channel page, or none when no frame can load; `next` is where the browser goes after. */
export function frontChannelPage(
	frames: readonly Frame[],
	at: { readonly issuer: string; readonly session: string; readonly next?: string | undefined },
): { readonly html: string; readonly loads: Loads; readonly skipped: number } | undefined {
	const loadable = frames
		.map((frame) => ({ url: new URL(frame.uri), withSession: frame.withSession }))
		.filter(({ url }) => framable.test(url.origin));
	if (loadable.length === 0) return undefined;
	const iframes = loadable
		.map(({ url, withSession }) => {
			url.searchParams.set("iss", at.issuer);
			if (withSession) url.searchParams.set("sid", at.session);
			return `<iframe src="${escaped(url.href)}" hidden aria-hidden="true" referrerpolicy="no-referrer" sandbox="allow-scripts allow-same-origin"></iframe>`;
		})
		.join("");
	const origins = [...new Set(loadable.map(({ url }) => url.origin))];
	const page = pageOf(iframes, origins, at.next, delayMs);
	return { ...page, skipped: frames.length - loadable.length };
}

/**
 * The page a logout ends on where no client is framed: it says the user is logged out, and moves the
 * browser on to `next` at once by the front-channel page's one script, or stays, with no script.
 */
export function loggedOutPage(at: {
	readonly next?: string | undefined;
	/** Says the person was not signed in, where no session was there to close. */
	readonly notSignedIn?: true;
}): {
	readonly html: string;
	readonly loads: Loads;
} {
	const words = at.notSignedIn ? "You are not signed in." : "You are logged out.";
	return pageOf("", [], at.next, 0, words);
}

/** The page: the words that say the user is logged out, the frames, and the move on where there is one. */
function pageOf(
	iframes: string,
	origins: readonly string[],
	next: string | undefined,
	delay: number,
	words = "You are logged out.",
): { readonly html: string; readonly loads: Loads } {
	const moving =
		next === undefined
			? { attributes: "", script: "", scripts: [] }
			: {
					attributes: ` data-target="${escaped(next)}" data-delay="${delay}"`,
					script: `<script>${script}</script>`,
					scripts: [script],
				};
	const html = `<!doctype html><html><head><meta charset="utf-8"><title>Logged out</title></head><body${moving.attributes}><h1>Logged out</h1><p>${words}</p>${iframes}${moving.script}</body></html>`;
	return { html, loads: { frames: [...origins], scripts: moving.scripts } };
}
