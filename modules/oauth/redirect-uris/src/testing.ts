import { redirects } from "./contract.ts";

/** A client's sections registering these redirect URIs. */
export function redirectsFor(uris: readonly string[]) {
	return { [redirects.name]: { "redirect-uris": uris } };
}
