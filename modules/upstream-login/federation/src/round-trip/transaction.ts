import { z } from "zod";
import type { StoredTransaction } from "../store.ts";

/** One round trip to an upstream, a login's or a link's, from its start to its callback, taken once. */
export interface Transaction {
	readonly format: 1;
	readonly idp: string;
	readonly state: string;
	readonly nonce: string;
	readonly verifier: string;
	readonly redirectTo?: string;
	/** The browser asked the upstream to log in again. */
	readonly prompt?: "login";
	readonly maxAgeSeconds?: number;
	/** When the round trip started, on the kernel's clock. */
	readonly startedAt: number;
	/** A link's round trip: the session entered at its start, and its subject. None for a login. */
	readonly link?: { readonly session: string; readonly subject: string };
	readonly taken?: true;
}

const shape = z.strictObject({
	format: z.literal(1),
	idp: z.string(),
	state: z.string(),
	nonce: z.string(),
	verifier: z.string(),
	redirectTo: z.string().optional(),
	prompt: z.literal("login").optional(),
	maxAgeSeconds: z.number().optional(),
	startedAt: z.number(),
	link: z.strictObject({ session: z.string(), subject: z.string() }).optional(),
	taken: z.literal(true).optional(),
});

export const toStored = (transaction: Transaction) => transaction as unknown as StoredTransaction;
/** What a kept record holds, checked on every read; nothing for a format or shape this does not know. */
export const fromStored = (stored: StoredTransaction | undefined): Transaction | undefined => {
	const read = shape.safeParse(stored);
	// The shape checked is the interface's own; zod's output loses only its readonly marks.
	return read.success ? (read.data as Transaction) : undefined;
};
