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
		"first-party": z.boolean().default(false),
		name: name.optional(),
		uri: z
			.string()
			.refine((text) => httpsUrl(text) !== undefined)
			.optional(),
		host: z
			.string()
			.min(1)
			.refine((text) => !spaceOrControl.test(text))
			.optional(),
	}),
};

/** What a source puts in consent's section of a client it found, for the consent page to show. */
export function displayed(shown: {
	readonly name: string;
	readonly uri?: string | undefined;
	readonly host: string;
}): unknown {
	return {
		name: shown.name,
		host: shown.host,
		...(shown.uri === undefined ? {} : { uri: shown.uri }),
	};
}

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
