import type { DocumentCopy, DocumentSource } from "@mod/client-documents";
import type { Client, Section } from "@mod/clients";
import { z } from "zod";
import { httpsUrl, spaceOrControl } from "./shapes.ts";

/** Client metadata: whether the operator runs the client, and what the consent page shows of it. */
export interface ClientShown {
	readonly "first-party": boolean;
	/** Trimmed and cut to 200 characters. */
	readonly name?: string | undefined;
	readonly uri?: string | undefined;
	/** The host the client's source verified; it counts only for a client the operator did not register. */
	readonly host?: string | undefined;
}

const name = z
	.string()
	.transform((text) => [...text.trim()].slice(0, 200).join(""))
	.pipe(z.string().min(1));

export const clientSection: Section<ClientShown> = {
	name: "consent",
	schema: z.strictObject({
		"first-party": z
			.boolean()
			.prefault(false)
			.describe(
				"Whether the operator runs the client, so its users are never asked for consent; it counts only for a client the operator registered.",
			),
		name: name
			.optional()
			.describe("The client's name the consent page shows, trimmed and cut to 200 characters."),
		uri: z
			.string()
			.refine((text) => httpsUrl(text) !== undefined)
			.optional()
			.describe("The client's home page the consent page shows, an https URL."),
		host: z
			.string()
			.min(1)
			.refine((text) => !spaceOrControl.test(text))
			.optional()
			.describe(
				"The host the client's source verified, shown only for a client the operator did not register.",
			),
	}),
	fromDocument: (document, from) => copied(document, from),
	reads: ["client_name", "client_uri"],
};

// A document never sets first-party: its client is no client the operator runs.
function copied(document: Readonly<Record<string, unknown>>, from: DocumentSource) {
	const name = document.client_name;
	if (typeof name !== "string" || name.trim() === "") return { refused: "client_name" };
	const uri = document.client_uri;
	return { value: { name, ...(uri === undefined ? {} : { uri }), host: from.host } };
}

/** The section's copy from a client's metadata document, for `client-documents`' `documentCopies`. */
export const clientCopy: DocumentCopy = {
	section: clientSection,
	reads: ["client_name", "client_uri"],
	copy: (document, from) => copied(document, from),
};

/** Whether the client needs no consent: only one the operator registered can be first-party. */
export function isFirstParty(client: Client): boolean {
	return client.registered && client.section(clientSection)["first-party"];
}

/** What the consent page shows of the client; a host only for a client from another source. */
export function shownOf(client: Client): Omit<ClientShown, "first-party"> {
	const { name, uri, host } = client.section(clientSection);
	return {
		...(name === undefined ? {} : { name }),
		...(uri === undefined ? {} : { uri }),
		...(host === undefined || client.registered ? {} : { host }),
	};
}
