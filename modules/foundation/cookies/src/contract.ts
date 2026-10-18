import type { HttpRequest } from "@mod/http";
import { contract } from "@mod/kernel";

/** Why a cookie the request carries is not read: sent over plain http where cookies are secure, or under its name more than once. */
export type WithheldReason = "plain-http" | "duplicate";

/** What a request carries under a name: the cookie, none, or one withheld with the reason. */
export type CookieLookup =
	| { readonly kind: "found"; readonly value: string }
	| { readonly kind: "absent" }
	| { readonly kind: "withheld"; readonly reason: WithheldReason };

/** This deployment's cookies, named and set by one rule. */
export interface Cookies {
	/** The cookie the request carries under this name, none, or why it is withheld; a withheld one warns once a request and name. */
	lookup(request: HttpRequest, name: string): CookieLookup;
	/**
	 * A `Set-Cookie` value: path `/`, HttpOnly, SameSite=Lax; zero seconds removes it. A cross-site one
	 * is SameSite=None and only ever `__Host-` and Secure: it throws where cookies cannot be secure. A name that is not a token, or a value with anything but cookie-octets, throws.
	 */
	write(
		name: string,
		value: string,
		maxAgeSeconds: number,
		options?: { readonly crossSite?: true },
	): string;
}

export const cookies = contract<Cookies>("cookies");

export { cookiesFor } from "./cookies.ts";
