import { z } from "zod";
import type { StoredReauth } from "./store.ts";

/** A re-authentication asked for one request, taken once. */
export interface Reauth {
	readonly format: 1;
	/** On `kernel`'s clock, epoch ms: a login in its second or after counts. */
	readonly at: number;
	readonly request: string;
	/** Written when the browser was sent to raise its authentication: it goes there once. */
	readonly stepUp?: true;
	readonly taken?: true;
}

const shape = z.strictObject({
	format: z.literal(1),
	at: z.number(),
	request: z.string(),
	stepUp: z.literal(true).optional(),
	taken: z.literal(true).optional(),
});

export const toStored = (reauth: Reauth) => reauth as unknown as StoredReauth;
/** What a kept record holds, checked on every read; nothing for a format or shape this does not know. */
export const fromStored = (stored: StoredReauth | undefined): Reauth | undefined => {
	const read = shape.safeParse(stored);
	return read.success ? (read.data as Reauth) : undefined;
};
