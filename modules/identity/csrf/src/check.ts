import type { Cookies } from "@mod/cookies";
import type { HttpRequest } from "@mod/http";
import { type Random, sameSecret } from "@mod/kernel";

/** Where the double-submit token travels; the route tells clients the header and field names. */
export const carried = { cookie: "csrf", header: "x-csrf-token", field: "csrf_token" } as const;

/** A token as it is handed out: 43 base64url characters. */
const tokenShape = /^[A-Za-z0-9_-]{43}$/;

/** The token the request's cookie holds, if it has the shape this module hands out. */
export function keptToken(jar: Cookies, request: HttpRequest): string | undefined {
	const kept = jar.read(request, carried.cookie);
	return kept && tokenShape.test(kept) ? kept : undefined;
}

/** A new token: 32 random bytes are 43 base64url characters. */
export const newToken = (random: Random) => Buffer.from(random.bytes(32)).toString("base64url");

/** Same-origin evidence or the double-submit token; any foreign evidence is refused regardless. */
export function checking(origin: string, secureCookies: boolean, jar: Cookies) {
	return (request: HttpRequest): "passed" | "refused" => {
		// A secure cookie means nothing to a plain-http request.
		if (secureCookies && request.source.scheme !== "https") return "refused";
		const evidence = namedOrigins(request);
		if (evidence.some((o) => o !== origin)) return "refused";
		if (evidence.length > 0) return "passed";
		const kept = keptToken(jar, request);
		const sent = request.headers.get(carried.header) ?? request.fields.single(carried.field);
		return kept && sent && sameSecret(kept, sent) ? "passed" : "refused";
	};
}

/** Positive evidence only: Origin is ours or Sec-Fetch-Site says same-origin, and nothing says otherwise. */
export function sameOriginOf(origin: string, secureCookies: boolean) {
	return (request: HttpRequest): boolean => {
		if (secureCookies && request.source.scheme !== "https") return false;
		const fetchSite = request.headers.get("sec-fetch-site");
		if (namedOrigins(request).some((o) => o !== origin)) return false;
		if (fetchSite !== undefined && fetchSite !== "same-origin") return false;
		return request.headers.get("origin") === origin || fetchSite === "same-origin";
	};
}

/** The origins Origin and Referer name; `null` and an unreadable Referer name none. */
function namedOrigins(request: HttpRequest): string[] {
	return [request.headers.get("origin"), refererOrigin(request.headers.get("referer"))].filter(
		(o): o is string => o !== undefined && o !== "null",
	);
}

/** The origin a Referer names; an unreadable one is no evidence. */
const refererOrigin = (referer: string | undefined) =>
	referer === undefined ? undefined : URL.parse(referer)?.origin;
