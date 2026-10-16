import type { HttpRequest } from "@mod/http";
import { contract } from "@mod/kernel";

/** This deployment's cookies, named and set by one rule. */
export interface Cookies {
	/** The cookie the request carries once under this name; none when sent twice, or over plain http where cookies are secure. */
	read(request: HttpRequest, name: string): string | undefined;
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
