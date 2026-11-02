import type { DocumentCopy } from "@mod/client-documents";
import type { Client, Section } from "@mod/clients";
import { z } from "zod";
import { answerTo, matches, type RedirectShown, registrable, shownOf } from "./uris.ts";

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
						"an absolute URI, https written with its //, without a fragment, userinfo, control characters, or a query named like a response parameter",
					),
			)
			.prefault([])
			.describe(
				"The redirect URIs the client may ask for, each matched as written: https followed by //, http to a loopback host, or a private-use reverse-domain scheme, with no fragment, userinfo or query parameter named like a response parameter.",
			),
	}),
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
	copy: copied,
};

/** A client's redirect URIs; a client read where the section is not composed holds no section at all, so none. */
const urisOf = (client: Client) =>
	(client.section(redirects) as Redirects | undefined)?.["redirect-uris"] ?? [];

/**
 * Whether `origin` is the scheme, host and port of one of the client's registered redirect URIs, as
 * OpenID Connect Front-Channel Logout 1.0 §2 asks of a front-channel URI. A private-use scheme's URI
 * has the opaque origin `null`, which no origin asked equals.
 */
export function redirectsAt(client: Client, origin: string): boolean {
	if (origin === "null") return false;
	return urisOf(client).some((uri) => URL.parse(uri)?.origin === origin);
}

/**
 * Where a client's redirect URIs send the user, each once, as a page shows them: a host as the URL
 * parser writes it (lower case, an A-label), with a port other than the scheme's default but for a
 * loopback literal `matches` takes on any port, read as `loopback` by that host or as `web`; a
 * private-use scheme alone, as `app`, its authority being no host anyone reaches. Two URIs that
 * match show alike.
 */
export function redirectsShown(client: Client): readonly RedirectShown[] {
	const once = new Map<string, RedirectShown>();
	for (const uri of urisOf(client)) {
		const shown = shownOf(uri);
		if (shown) once.set(`${shown.kind} ${shown.host}`, shown);
	}
	return [...once.values()];
}

/** Whether a URI may be registered for a client to be sent back to; whether a given one matches a registered one; the answer's URL. */
export { answerTo, matches, type RedirectShown, registrable };
