import type { Client, Section } from "@mod/clients";
import { z } from "zod";
import { registrable } from "./redirect-uris/redirect-uris.ts";

export interface Redirects {
	readonly "redirect-uris": readonly string[];
}

export const redirects: Section<Redirects> = {
	name: "authorize",
	schema: z.strictObject({
		"redirect-uris": z
			.array(
				z
					.string()
					.refine(
						registrable,
						"an absolute URI without a fragment, userinfo, control characters, or a query named like a response parameter",
					),
			)
			.prefault([])
			.describe(
				"The redirect URIs the client may ask for, each matched as written: https, http to a loopback host, or a private-use reverse-domain scheme, with no fragment, userinfo or query parameter named like a response parameter.",
			),
	}),
};
export * from "./store.ts";

/**
 * Whether `origin` is the scheme, host and port of one of the client's registered redirect URIs, as
 * OpenID Connect Front-Channel Logout 1.0 §2 asks of a front-channel URI. A private-use scheme's URI
 * has the opaque origin `null`, which no origin asked equals.
 */
export function redirectsAt(client: Client, origin: string): boolean {
	if (origin === "null") return false;
	// A client read where authorize's section is not composed holds no section at all, so no URI.
	const uris = (client.section(redirects) as Redirects | undefined)?.["redirect-uris"] ?? [];
	return uris.some((uri) => URL.parse(uri)?.origin === origin);
}

/** Whether a URI may be registered for a client to be sent back to, by the redirect URI rules. */
export { registrable };
