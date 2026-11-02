import { isLoopbackName } from "@mod/url-setting";

/** Names a redirect URI's own query may not use, since the answer adds them. */
const answerNames = ["code", "state", "iss", "error", "error_description", "error_uri"];

const loopbackLiteral = /^http:\/\/(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\])(:\d{1,5})?(\/|\?|$)/;
const withoutPort = (uri: string) =>
	uri.replace(/^(http:\/\/(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\])):\d{1,5}/, "$1");
/** A private-use scheme in reverse-domain form (RFC 8252 §7.1), never a script scheme. */
const reverseDomain = /^[a-z][a-z0-9+-]*(\.[a-z0-9+-]+)+:$/;

export function registrable(uri: string): boolean {
	const control = [...uri].some((ch) => {
		const code = ch.codePointAt(0) ?? 0;
		return code < 0x20 || code === 0x7f || /\s/.test(ch);
	});
	if (control) return false;
	let parsed: URL;
	try {
		parsed = new URL(uri);
	} catch {
		return false;
	}
	if (parsed.hash || uri.includes("#") || parsed.username || parsed.password) return false;
	const scheme = parsed.protocol.toLowerCase();
	const local =
		scheme === "http:" &&
		(loopbackLiteral.test(uri) || /^http:\/\/localhost(:\d{1,5})?(\/|\?|$)/.test(uri));
	const native = reverseDomain.test(scheme) && !scheme.startsWith("javascript.");
	if (scheme !== "https:" && !local && !native) return false;
	// An answer goes out as written, so a URI says its host the one way every reader of it takes.
	if (scheme === "https:" && !/^https:\/\//i.test(uri)) return false;
	return !answerNames.some((name) => parsed.searchParams.has(name));
}

/** Where a redirect URI sends the user, as it is shown to them. */
export interface RedirectShown {
	/** The host as the URL parser writes it, with a port other than the scheme's default where matching reads it; a private-use scheme, alone. */
	readonly host: string;
	readonly kind: "web" | "loopback" | "app";
}

/** A URI as it is shown: read from what the URL parser takes of it, never from how it is written. */
export function shownOf(uri: string): RedirectShown | undefined {
	const parsed = URL.parse(uri);
	if (!parsed) return undefined;
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
		return { host: parsed.protocol.slice(0, -1), kind: "app" };
	}
	// `matches` drops this port, so showing one would say of the client what no match holds it to.
	const host = loopbackLiteral.test(uri) ? parsed.hostname : parsed.host;
	return { host, kind: isLoopbackName(parsed.hostname) ? "loopback" : "web" };
}

export function matches(registered: string, given: string): boolean {
	if (registered === given) return true;
	return (
		loopbackLiteral.test(registered) &&
		loopbackLiteral.test(given) &&
		withoutPort(registered) === withoutPort(given)
	);
}

export function answerTo(
	uri: string,
	params: Readonly<Record<string, string | undefined>>,
): string {
	const extra = new URLSearchParams();
	for (const [name, value] of Object.entries(params))
		if (value !== undefined) extra.set(name, value);
	return `${uri}${uri.includes("?") ? "&" : "?"}${extra}`;
}
