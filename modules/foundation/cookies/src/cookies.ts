import type { HttpRequest } from "@mod/http";
import type { Log } from "@mod/kernel";
import type { Source } from "@mod/request-source";
import type { CookieLookup, Cookies, WithheldReason } from "./contract.ts";

/** A cookie's name: an HTTP token (RFC 9110 §5.6.2). */
const tokenName = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
/** A cookie's value: cookie-octets only (RFC 6265 §4.1.1), so it cannot end the cookie or add an attribute. */
const cookieValue = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;

/** Whether a request came over HTTPS, by the scheme its source holds. */
const overHttps = (source: Source) => source.scheme === "https";

/**
 * Cookies for this deployment: `__Host-` and Secure where they can be secure, plain names otherwise.
 * With a log, a withheld cookie warns once a request and name, since anyone can send a name twice.
 */
export function cookiesFor(secure: boolean, log?: Pick<Log, "warn">): Cookies {
	const nameOf = (base: string) => (secure ? `__Host-${base}` : base);
	const warned = new WeakMap<HttpRequest, Set<string>>();
	const withheld = (request: HttpRequest, base: string, reason: WithheldReason): CookieLookup => {
		const told = warned.get(request) ?? new Set<string>();
		if (log && !told.has(base)) {
			told.add(base);
			warned.set(request, told);
			log.warn("cookies.withheld", { name: base, reason });
		}
		return { kind: "withheld", reason };
	};
	const lookup = (request: HttpRequest, base: string): CookieLookup => {
		const name = nameOf(base);
		const found = (request.headers.get("cookie") ?? "")
			.split(";")
			.map((part) => part.trim())
			.filter((part) => part.startsWith(`${name}=`));
		const [only, ...more] = found;
		if (only === undefined) return { kind: "absent" };
		if (secure && !overHttps(request.source)) return withheld(request, base, "plain-http");
		if (more.length > 0) return withheld(request, base, "duplicate");
		return { kind: "found", value: only.slice(name.length + 1) };
	};
	return Object.freeze({
		read: (request: HttpRequest, base: string) => {
			const looked = lookup(request, base);
			return looked.kind === "found" ? looked.value : undefined;
		},
		lookup,
		write: (
			base: string,
			value: string,
			maxAgeSeconds: number,
			options: { readonly crossSite?: true } = {},
		) => {
			if (options.crossSite && !secure) throw new Error("a cross-site cookie needs secure cookies");
			if (!tokenName.test(base)) throw new Error("a cookie name must be a token");
			if (!cookieValue.test(value)) throw new Error("a cookie value must be cookie-octets");
			const sameSite = options.crossSite ? "None" : "Lax";
			return [
				`${nameOf(base)}=${value}`,
				"Path=/",
				"HttpOnly",
				`SameSite=${sameSite}`,
				...(secure ? ["Secure"] : []),
				`Max-Age=${maxAgeSeconds}`,
			].join("; ");
		},
	});
}
