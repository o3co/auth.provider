import type { HttpRequest } from "@mod/http";
import type { Source } from "@mod/request-source";
import type { Cookies } from "./contract.ts";

/** A cookie's name: an HTTP token (RFC 9110 §5.6.2). */
const tokenName = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
/** A cookie's value: cookie-octets only (RFC 6265 §4.1.1), so it cannot end the cookie or add an attribute. */
const cookieValue = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;

/** Whether a request came over HTTPS, by the scheme its source holds. */
const overHttps = (source: Source) => source.scheme === "https";

/** Cookies for this deployment: `__Host-` and Secure where they can be secure, plain names otherwise. */
export function cookiesFor(secure: boolean): Cookies {
	const nameOf = (base: string) => (secure ? `__Host-${base}` : base);
	return Object.freeze({
		read: (request: HttpRequest, base: string) => {
			if (secure && !overHttps(request.source)) return undefined;
			const name = nameOf(base);
			const found = (request.headers.get("cookie") ?? "")
				.split(";")
				.map((part) => part.trim())
				.filter((part) => part.startsWith(`${name}=`));
			return found.length === 1 ? found[0]?.slice(name.length + 1) : undefined;
		},
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
