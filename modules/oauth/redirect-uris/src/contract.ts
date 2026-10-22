import type { DocumentCopy } from "@mod/client-documents";
import type { Client, Section } from "@mod/clients";
import { z } from "zod";
import { answerTo, matches, registrable } from "./uris.ts";

export interface Redirects {
	readonly "redirect-uris": readonly string[];
}

/** The client's redirect URIs; the section is named for the authorization request that reads them. */
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
	reads: ["redirect_uris"],
	fromDocument: (document) => copied(document),
};

// As given, under the section's own key: the schema checks each URI, so a document key never shows.
function copied(document: Readonly<Record<string, unknown>>) {
	return document.redirect_uris === undefined
		? undefined
		: { value: { "redirect-uris": document.redirect_uris } };
}

/** The section's copy from a client's metadata document, for `client-documents`' `documentCopies`. */
export const redirectsCopy: DocumentCopy = {
	section: redirects,
	reads: ["redirect_uris"],
	copy: (document) => copied(document),
};

/**
 * Whether `origin` is the scheme, host and port of one of the client's registered redirect URIs, as
 * OpenID Connect Front-Channel Logout 1.0 §2 asks of a front-channel URI. A private-use scheme's URI
 * has the opaque origin `null`, which no origin asked equals.
 */
export function redirectsAt(client: Client, origin: string): boolean {
	if (origin === "null") return false;
	// A client read where the section is not composed holds no section at all, so no URI.
	const uris = (client.section(redirects) as Redirects | undefined)?.["redirect-uris"] ?? [];
	return uris.some((uri) => URL.parse(uri)?.origin === origin);
}

/** Whether a URI may be registered for a client to be sent back to; whether a given one matches a registered one; the answer's URL. */
export { answerTo, matches, registrable };
