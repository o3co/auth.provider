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
	/** The client's description as its source read it, for a grant to be agreed under; the same rule. */
	readonly under?: string | undefined;
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
		under: z
			.string()
			.min(1)
			.refine((text) => !spaceOrControl.test(text))
			.optional()
			.describe(
				"What the client's source says of the description it read, which a grant is agreed under; ignored on a client the operator registered.",
			),
	}),
};

// A document never sets first-party: its client is no client the operator runs.
function copied(document: Readonly<Record<string, unknown>>, from: DocumentSource) {
	const name = document.client_name;
	if (typeof name !== "string" || name.trim() === "") return { refused: "client_name" };
	const uri = document.client_uri;
	const under = from.digest;
	return {
		value: {
			name,
			...(uri === undefined ? {} : { uri }),
			host: from.host,
			...(under === undefined ? {} : { under }),
		},
	};
}

/** The section's copy from a client's metadata document, for `client-documents`' `documentCopies`. */
export const clientCopy: DocumentCopy = {
	section: clientSection,
	reads: ["client_name", "client_uri"],
	copy: copied,
};

/** Whether the client needs no consent: only one the operator registered can be first-party. */
export function isFirstParty(client: Client): boolean {
	return client.registered && client.section(clientSection)["first-party"];
}

/** What a grant for the client is agreed under: nothing for a client the operator registered. */
export function underOf(client: Client): string | undefined {
	return client.registered ? undefined : client.section(clientSection).under;
}

/** Whether a grant can ever count for the client: not for one from another source that says nothing it is agreed under. */
export function canBeAgreed(client: Client): boolean {
	return client.registered || underOf(client) !== undefined;
}

/** What the consent page shows of the client; a host only for a client from another source. */
export function shownOf(client: Client): Pick<ClientShown, "name" | "uri" | "host"> {
	const { name, uri, host } = client.section(clientSection);
	return {
		...(name === undefined ? {} : { name }),
		...(uri === undefined ? {} : { uri }),
		...(host === undefined || client.registered ? {} : { host }),
	};
}
